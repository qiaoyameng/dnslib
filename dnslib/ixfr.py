# -*- coding: utf-8 -*-

"""
    Apply incremental zone transfers (IXFR, RFC 1995) to an in-memory zone.

    The entry point is :func:`apply_update` which takes the current zone (a
    list of :class:`dnslib.RR` objects, eg as returned by ``RR.fromZone``)
    and an iterable of RRs making up the transfer response.  The iterable
    may be any iterator, so records can be fed in one at a time as they
    arrive from the network; alternatively :class:`ZoneUpdater` can be used
    directly for a streaming ``feed()``/``finish()`` interface.

    The response is validated as a whole before anything is delivered:

      * The first record must be an SOA giving the target serial.
      * If the second record is an SOA carrying the zone's current serial
        the response is treated as an IXFR: a chain of one or more deltas,
        each of the form ``SOA(old) <deletions> SOA(new) <additions>``.
        Multiple deltas may be chained in a single response as long as the
        versions link up (each delta starts where the previous one ended)
        and the final delta reaches the target serial.  Serial comparisons
        follow the RFC 1982 wrap-around rules.
      * Otherwise the response is treated as a server-fallback AXFR (full
        zone between the opening and closing SOA) and replaces the zone
        wholesale - it is never mistaken for a deletion set.
      * Every deleted record must exist in the zone and every added record
        must not duplicate an existing one.

    Only when the complete response parses and validates cleanly is the new
    zone returned; a truncated response, a break in the version chain or an
    invalid record operation raises :class:`IXFRError` and the original
    zone is left untouched.

    >>> zone = RR.fromZone('''
    ... example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 100 3600 600 86400 60
    ... example.com. 300 IN NS ns1.example.com.
    ... www.example.com. 300 IN A 192.0.2.1
    ... ''')
    >>> delta = RR.fromZone('''
    ... example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 101 3600 600 86400 60
    ... example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 100 3600 600 86400 60
    ... www.example.com. 300 IN A 192.0.2.1
    ... example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 101 3600 600 86400 60
    ... www.example.com. 300 IN A 192.0.2.2
    ... example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 101 3600 600 86400 60
    ... ''')
    >>> new_zone = apply_update(zone,iter(delta))
    >>> print(new_zone[0].rdata.times[0])
    101
    >>> [str(rr.rdata) for rr in new_zone if rr.rtype == QTYPE.A]
    ['192.0.2.2']
"""

from __future__ import print_function

from dnslib.dns import DNSError,QTYPE,RR

__all__ = ['IXFRError','ZoneUpdater','apply_update',
           'SERIAL_MOD','serial_add','serial_lt','serial_le',
           'serial_gt','serial_ge']


class IXFRError(DNSError):
    """
        Raised when a zone transfer response cannot be validated or
        applied.  The original zone is never modified in this case.
    """


# -- RFC 1982 serial number arithmetic --------------------------------------

SERIAL_MOD = 1 << 32          # 2^32 - serial numbers are 32 bit
SERIAL_HALF = 1 << 31         # 2^31 - the undefined boundary

def _check_serial(serial):
    if not isinstance(serial,int) or not 0 <= serial < SERIAL_MOD:
        raise IXFRError("Invalid serial number: %r" % (serial,))
    return serial

def serial_add(serial,n):
    """
        Add n to a serial number (mod 2^32) as per RFC 1982 section 2.
    """
    return (_check_serial(serial) + n) % SERIAL_MOD

def serial_lt(a,b):
    """
        RFC 1982 section 3: a < b iff a != b and (b - a) mod 2^32 < 2^31.
        Handles wrap-around at 2^32 (eg 4294967295 < 1 holds when stepping
        across the boundary).
    """
    _check_serial(a)
    _check_serial(b)
    return a != b and (b - a) % SERIAL_MOD < SERIAL_HALF

def serial_gt(a,b):
    """
        RFC 1982 section 3: a > b iff b < a.
    """
    return serial_lt(b,a)

def serial_le(a,b):
    return a == b or serial_lt(a,b)

def serial_ge(a,b):
    return a == b or serial_gt(a,b)


# -- helpers -----------------------------------------------------------------

def _is_soa(rr):
    return rr.rtype == QTYPE.SOA

def _serial(rr):
    return rr.rdata.times[0]

def _zone_serial(zone):
    for rr in zone:
        if _is_soa(rr):
            return _serial(rr)
    return None


class ZoneUpdater(object):
    """
        Streaming applier for IXFR/AXFR responses.

        Records are fed in one at a time with :meth:`feed` (in the order
        they appear in the response's answer section) and the transfer is
        completed with :meth:`finish`, which returns the new zone as a list
        of RRs.  The zone passed to the constructor is never mutated; if
        any error is raised the original zone remains valid and reusable.
    """

    def __init__(self,zone):
        self.zone = list(zone)
        self.current_serial = _zone_serial(self.zone)
        self._state = 'start'
        self._mode = None
        self._target_serial = None
        self._first_soa = None
        self._deltas = []        # committed (old,new,deletes,adds) tuples
        self._expected = None    # serial the next delta must start from
        self._new_serial = None  # serial of the delta currently in progress
        self._deletes = []
        self._adds = []
        self._axfr = []

    def feed(self,rr):
        """
            Consume the next RR of the transfer response.
        """
        if not isinstance(rr,RR):
            raise IXFRError("Expected RR instance, got %s" % type(rr).__name__)
        handler = getattr(self,'_feed_' + self._state)
        handler(rr)
        return self

    def finish(self):
        """
            Complete the transfer and return the new zone (list of RRs).
            Raises IXFRError if the response was truncated or invalid.
        """
        if self._state == 'start':
            raise IXFRError("Empty transfer response (no SOA)")
        elif self._state == 'first_soa':
            # Single SOA: "up to date" if it matches our serial,
            # otherwise a truncated transfer.
            if self.current_serial is not None and \
                            self._target_serial == self.current_serial:
                return list(self.zone)
            raise IXFRError("Truncated transfer: only initial SOA "
                            "(serial %d) received" % self._target_serial)
        elif self._state != 'end':
            raise IXFRError("Truncated transfer response "
                            "(stopped in state '%s')" % self._state)
        if self._mode == 'axfr':
            return [self._first_soa] + self._axfr
        return self._apply_ixfr()

    # -- state handlers ------------------------------------------------------

    def _feed_start(self,rr):
        if not _is_soa(rr):
            raise IXFRError("Transfer response must start with SOA, "
                            "got %s" % QTYPE.get(rr.rtype,rr.rtype))
        _check_serial(_serial(rr))
        self._first_soa = rr
        self._target_serial = _serial(rr)
        self._state = 'first_soa'

    def _feed_first_soa(self,rr):
        if _is_soa(rr) and self.current_serial is not None and \
                        _serial(rr) == self.current_serial:
            # SOA carrying our current serial: start of an IXFR delta chain
            self._mode = 'ixfr'
            self._expected = self.current_serial
            self._state = 'ixfr_delete'
        elif _is_soa(rr) and _serial(rr) != self._target_serial:
            raise IXFRError("Version chain broken: first delta starts at "
                            "serial %d but zone is at serial %s" % (
                                _serial(rr),self.current_serial))
        elif _is_soa(rr):
            # SOA with the target serial: degenerate AXFR (SOA-only zone)
            self._mode = 'axfr'
            self._state = 'end'
        else:
            # Not an SOA: server fell back to AXFR - collect the full zone
            self._mode = 'axfr'
            self._axfr.append(rr)
            self._state = 'axfr'

    def _feed_axfr(self,rr):
        if _is_soa(rr):
            if _serial(rr) != self._target_serial:
                raise IXFRError("AXFR closing SOA serial %d does not match "
                                "opening serial %d" % (
                                    _serial(rr),self._target_serial))
            self._state = 'end'
        else:
            self._axfr.append(rr)

    def _feed_ixfr_delete(self,rr):
        if _is_soa(rr):
            new_serial = _serial(rr)
            _check_serial(new_serial)
            if not serial_lt(self._expected,new_serial):
                raise IXFRError("Delta version %d does not follow %d "
                                "(RFC 1982)" % (new_serial,self._expected))
            self._new_serial = new_serial
            self._state = 'ixfr_add'
        else:
            self._deletes.append(rr)

    def _feed_ixfr_add(self,rr):
        if _is_soa(rr):
            serial = _serial(rr)
            self._deltas.append((self._expected,self._new_serial,
                                 self._deletes,self._adds))
            self._deletes = []
            self._adds = []
            if serial == self._target_serial:
                if self._new_serial != self._target_serial:
                    raise IXFRError("Version chain broken: last delta ends "
                                    "at serial %d but response targets %d" % (
                                        self._new_serial,self._target_serial))
                self._state = 'end'
            elif serial == self._new_serial:
                # Chained delta: next deletion set starts where we ended
                self._expected = self._new_serial
                self._state = 'ixfr_delete'
            else:
                raise IXFRError("Version chain broken: expected SOA serial "
                                "%d, got %d" % (self._new_serial,serial))
        else:
            self._adds.append(rr)

    def _feed_end(self,rr):
        raise IXFRError("Trailing records after end of transfer")

    # -- application ---------------------------------------------------------

    def _apply_ixfr(self):
        # Work on a copy; the original zone is only replaced on success.
        records = [rr for rr in self.zone if not _is_soa(rr)]
        for old,new,deletes,adds in self._deltas:
            for rr in deletes:
                for i,existing in enumerate(records):
                    if existing == rr:
                        del records[i]
                        break
                else:
                    raise IXFRError("Delete target not present in zone "
                                    "(delta %d->%d): %s" % (old,new,rr))
            for rr in adds:
                if any(existing == rr for existing in records):
                    raise IXFRError("Add would duplicate existing record "
                                    "(delta %d->%d): %s" % (old,new,rr))
                records.append(rr)
        return [self._first_soa] + records


def apply_update(zone,records):
    """
        Apply a zone transfer response (IXFR delta chain or AXFR fallback)
        to an in-memory zone and return the new zone as a list of RRs.

        ``zone`` is the current zone (list of RRs, eg from ``RR.fromZone``)
        and ``records`` is any iterable of RRs - records may arrive one at
        a time from the network.  The input zone is never modified; an
        IXFRError is raised (and the zone left untouched) if the response
        is truncated, the version chain is broken, or a record operation
        is invalid.
    """
    updater = ZoneUpdater(zone)
    for rr in records:
        updater.feed(rr)
    return updater.finish()


if __name__ == '__main__':
    import doctest,sys
    from dnslib.dns import RR
    sys.exit(0 if doctest.testmod(optionflags=doctest.ELLIPSIS).failed == 0 else 1)
