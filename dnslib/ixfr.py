"""Apply DNS AXFR/IXFR transfer sequences to in-memory zones."""

from __future__ import print_function

from collections import OrderedDict
from copy import deepcopy

from dnslib.dns import DNSError,DNSRecord,QTYPE,RR,SOA
from dnslib.label import DNSBuffer,DNSLabel


SERIAL_BITS = 32
SERIAL_MODULUS = 1 << SERIAL_BITS
SERIAL_WRAP = 1 << (SERIAL_BITS - 1)


class ZoneTransferError(DNSError):
    """Invalid or incomplete AXFR/IXFR transfer sequence."""


def serial_lt(old,new):
    """Compare unsigned 32-bit serials according to RFC 1982."""
    difference = (int(new) - int(old)) % SERIAL_MODULUS
    return 0 < difference < SERIAL_WRAP


def _rr_key(rr):
    if not isinstance(rr,RR):
        raise ZoneTransferError("Transfer sequence contains non-RR value")
    rdata = deepcopy(rr.rdata)
    _lowercase_labels(rdata)
    buffer = DNSBuffer()
    rdata.pack(buffer)
    name = tuple(part.lower() for part in rr.rname.label)
    return (name,rr.rtype,rr.rclass,bytes(buffer.data))


def _lowercase_labels(value):
    if isinstance(value,DNSLabel):
        return DNSLabel(tuple(part.lower() for part in value.label))
    if isinstance(value,list):
        return [_lowercase_labels(item) for item in value]
    if isinstance(value,tuple):
        return tuple(_lowercase_labels(item) for item in value)
    if isinstance(value,dict):
        return dict((key,_lowercase_labels(item))
                    for key,item in value.items())
    if hasattr(value,"__dict__"):
        for attr,child in vars(value).items():
            if isinstance(child,(DNSLabel,list,tuple,dict)):
                setattr(value,attr,_lowercase_labels(child))
    return value


def _is_soa(rr):
    return isinstance(rr,RR) and rr.rtype == QTYPE.SOA and isinstance(rr.rdata,SOA)


def _soa_key(rr):
    if not _is_soa(rr):
        raise ZoneTransferError("Expected SOA record in transfer sequence")
    return _rr_key(rr)


def _same_soa_place(left,right):
    return left.rname == right.rname and left.rclass == right.rclass


class DNSZone(object):
    """Immutable, in-memory DNS zone stored as a set of RR identities."""

    @classmethod
    def from_zone(cls,zone):
        return cls(RR.fromZone(zone))

    def __init__(self,records=()):
        self._records = OrderedDict()
        for record in records:
            if not isinstance(record,RR):
                raise ZoneTransferError("Zone contains non-RR value")
            record = deepcopy(record)
            self._records[_rr_key(record)] = record

        soas = [record for record in self._records.values() if _is_soa(record)]
        if len(soas) != 1:
            raise ZoneTransferError("Zone must contain exactly one SOA record")

    @property
    def origin(self):
        return self.soa.rname

    @property
    def serial(self):
        return self.soa.rdata.times[0]

    @property
    def soa(self):
        return deepcopy(self._records[_soa_record_key(self)])

    @property
    def records(self):
        return tuple(deepcopy(record) for record in self._records.values())

    def to_zone(self):
        return "\n".join(record.toZone() for record in self._records.values())

    def apply_ixfr(self,records):
        return apply_ixfr(self,records)

    def __iter__(self):
        for record in self._records.values():
            yield deepcopy(record)

    def __len__(self):
        return len(self._records)


def _soa_record_key(zone):
    for key,record in zone._records.items():
        if _is_soa(record):
            return key
    raise ZoneTransferError("Zone must contain exactly one SOA record")


class _PushbackIterator(object):
    def __init__(self,iterator):
        self.iterator = iter(iterator)
        self.pushed = []

    def __iter__(self):
        return self

    def next(self):
        if self.pushed:
            return self.pushed.pop()
        return next(self.iterator)

    __next__ = next

    def push(self,value):
        self.pushed.append(value)


def _transfer_records(records):
    if isinstance(records,RR):
        records = (records,)
    elif isinstance(records,DNSRecord):
        records = records.rr

    for item in records:
        if isinstance(item,DNSRecord):
            for record in item.rr:
                yield record
        else:
            yield item


def _next_record(iterator):
    try:
        return next(iterator)
    except StopIteration:
        raise ZoneTransferError("Truncated zone transfer")


def _new_zone(candidate):
    return DNSZone(candidate.values())


def apply_ixfr(zone,records):
    """Apply an IXFR response, or an AXFR fallback response, to a zone."""
    if not isinstance(zone,DNSZone):
        zone = DNSZone(zone)

    stream = _PushbackIterator(_transfer_records(records))
    first = _next_record(stream)
    _soa_key(first)

    try:
        second = next(stream)
    except StopIteration:
        raise ZoneTransferError("Truncated zone transfer")

    if not _is_soa(second):
        return _apply_axfr(first,second,stream)

    if _rr_key(second) == _rr_key(first):
        try:
            next(stream)
        except StopIteration:
            return _new_zone(OrderedDict(((_rr_key(first),deepcopy(first)),)))
        raise ZoneTransferError("Invalid AXFR: records after final SOA")

    return _apply_ixfr(zone,first,second,stream)


def _apply_axfr(first,second,stream):
    candidate = OrderedDict()
    first = deepcopy(first)
    first_key = _rr_key(first)
    candidate[first_key] = first

    second = deepcopy(second)
    candidate[_rr_key(second)] = second

    complete = False
    for record in stream:
        if _is_soa(record):
            if _rr_key(record) != first_key:
                raise ZoneTransferError("Invalid AXFR: mismatched final SOA record")
            complete = True
            try:
                next(stream)
            except StopIteration:
                break
            raise ZoneTransferError("Invalid AXFR: records after final SOA")

        record = deepcopy(record)
        candidate[_rr_key(record)] = record

    if not complete:
        raise ZoneTransferError("Truncated AXFR transfer")

    return _new_zone(candidate)


def _apply_ixfr(zone,final_soa,old_soa,stream):
    final_key = _rr_key(final_soa)
    old_key = _rr_key(old_soa)
    if old_key != _soa_record_key(zone):
        raise ZoneTransferError("IXFR old SOA does not match the zone SOA")
    if final_key == old_key:
        raise ZoneTransferError("IXFR new SOA serial must increase")
    if not _same_soa_place(old_soa,final_soa):
        raise ZoneTransferError("IXFR SOA owner or class changed")
    if not serial_lt(old_soa.rdata.times[0],final_soa.rdata.times[0]):
        raise ZoneTransferError("IXFR final serial is not a RFC 1982 successor")

    candidate = OrderedDict()
    for key,record in zone._records.items():
        candidate[key] = deepcopy(record)

    current_soa = old_soa
    current_key = old_key
    in_add_section = False
    delta_start_keys = set(candidate)
    complete = False

    for record in stream:
        record_key = _rr_key(record)

        if _is_soa(record):
            if not _same_soa_place(current_soa,record):
                raise ZoneTransferError("IXFR SOA owner or class changed")

            if in_add_section:
                if record_key != current_key:
                    raise ZoneTransferError("IXFR version chain is not contiguous")

                try:
                    next_record = next(stream)
                except StopIteration:
                    if current_key != final_key:
                        raise ZoneTransferError("IXFR final SOA does not match the response")
                    complete = True
                    break

                stream.push(next_record)
                if _is_soa(next_record) and _rr_key(next_record) != current_key:
                    raise ZoneTransferError("IXFR version chain is not contiguous")

                in_add_section = False
                delta_start_keys = set(candidate)
            else:
                if record_key == current_key:
                    delta_start_keys = set(candidate)
                    continue

                if not serial_lt(current_soa.rdata.times[0],
                                 record.rdata.times[0]):
                    raise ZoneTransferError("IXFR serial is not a RFC 1982 successor")
                if current_key not in candidate:
                    raise ZoneTransferError("IXFR delete set does not contain old SOA")

                del candidate[current_key]
                record = deepcopy(record)
                current_soa = record
                current_key = _rr_key(record)
                candidate[current_key] = record
                in_add_section = True
                delta_start_keys = set(candidate)
        elif in_add_section:
            record = deepcopy(record)
            candidate[_rr_key(record)] = record
        elif record_key in candidate:
            del candidate[record_key]
        elif record_key not in delta_start_keys:
            raise ZoneTransferError("IXFR delete target does not exist")

    if not complete:
        raise ZoneTransferError("Truncated IXFR transfer")

    return _new_zone(candidate)
