# -*- coding: utf-8 -*-

"""
    RFC2136 (Dynamic DNS UPDATE) message construction/parsing.

    This module only builds and interprets UPDATE wire messages; it never
    modifies any server-side zone data.

    An UPDATE message reuses the four standard DNS sections with
    UPDATE-specific meanings (RFC2136 sections 2.2-2.5):

        Zone         - the single DNSQuestion naming the zone to update
        Prerequisite - the answer section (list of RRs)
        Update       - the authority section (list of RRs)
        Additional   - additional data (e.g. TSIG/OPT)

    The prerequisite/update entries are encoded as ordinary RRs whose
    TYPE/CLASS/TTL/RDATA combinations carry the semantics, so callers do
    not have to assemble sections, classes or empty RDATA themselves.

    Prerequisites (section 2.4):

        * rrset_exists(name, rtype)        - section 2.4.1, CLASS=zone,
                                             RDLENGTH=0
        * name_in_use(name)                - section 2.4.2, TYPE=ANY,
                                             CLASS=zone, RDLENGTH=0
        * rrset_absent(name, rtype)        - section 2.4.3, CLASS=NONE,
                                             RDLENGTH=0
        * name_not_in_use(name)            - section 2.4.4, TYPE=ANY,
                                             CLASS=NONE, RDLENGTH=0
        * rrset_value(name, rtype, rdata)  - section 2.4.5, CLASS=zone,
                                             RDATA given

    Updates (section 2.5):

        * add(name, rtype, rdata, ttl)     - section 2.5.1
        * delete_name(name)                - section 2.5.2, TYPE=ANY,
                                             CLASS=NONE, RDLENGTH=0
        * delete_rrset(name, rtype)        - section 2.5.3, CLASS=NONE,
                                             RDLENGTH=0
        * delete_record(name, rtype, rdata)- section 2.5.4, CLASS=NONE,
                                             TTL=0, RDATA given

    Example:

        >>> from dnslib import A
        >>> msg = DNSUpdate("example.com", id=0x1234)
        >>> msg.rrset_exists("www.example.com", A)
        >>> msg.add("www.example.com", A, A("1.2.3.4"), ttl=300)
        >>> msg.delete_name("old.example.com")
        >>> parsed = DNSUpdate.parse(msg.pack())
        >>> parsed == msg
        True
        >>> [p.kind for p in parsed.prerequisites]
        ['rrset_exists']
    """

from __future__ import print_function

import random

from dnslib.dns import (DNSError, DNSHeader, DNSQuestion, DNSRecord,
                        DNSLabel, RR, RD, EmptyRD, QTYPE, CLASS, OPCODE,
                        RDMAP)

# CLASS NONE (254) is a valid wire value but exposed in the bimap as
# CLASS.None which is awkward to access from Python
CLASS_NONE = getattr(CLASS,"None")
CLASS_ANY = getattr(CLASS,"*")

_MAX_TTL = 0x7FFFFFFF


def _code(value,bimap,name,section):
    """
        Resolve a textual/numeric CLASS or TYPE to its wire code.
    """
    if isinstance(value,int):
        return value
    if isinstance(value,str):
        try:
            return getattr(bimap,value)
        except DNSError:
            pass
    raise DNSError("RFC2136 %s: invalid %s value: %r" % (section,name,value))


def _label(name,section):
    if isinstance(name,DNSLabel):
        return name
    if not isinstance(name,str):
        raise DNSError("RFC2136 %s: name must be a non-empty label [%r]" % (
                            section,name))
    return DNSLabel(name)


def _in_zone(name,zone):
    """
        Return True if `name` is within (or equal to) `zone`.
        Comparison is case-insensitive as DNS names are.
    """
    name = DNSLabel(name) if not isinstance(name,DNSLabel) else name
    zone = DNSLabel(zone) if not isinstance(zone,DNSLabel) else zone
    if len(zone.label) == 0:
        # Root zone owns every name
        return True
    return name == zone or name.matchSuffix(zone)


def _rdata_code(rdata):
    """
        Find the wire TYPE code matching an RD instance class
        (without inspecting RDATA contents - purely a class->type lookup).
    """
    return _RDTYPE_BY_CLASS.get(type(rdata))

_RDTYPE_BY_CLASS = {}
for _type_name,_rd_cls in RDMAP.items():
    _RDTYPE_BY_CLASS.setdefault(_rd_cls,getattr(QTYPE,_type_name))


def _type_code(value,section):
    """
        Resolve a TYPE given as int, name, RD class or RD instance.
    """
    if isinstance(value,int):
        return value
    if isinstance(value,str):
        try:
            return getattr(QTYPE,value)
        except DNSError:
            pass
    if isinstance(value,type) and issubclass(value,RD):
        code = _RDTYPE_BY_CLASS.get(value)
        if code is not None:
            return code
    if isinstance(value,RD):
        code = _rdata_code(value)
        if code is not None:
            return code
    raise DNSError("RFC2136 %s: invalid TYPE value: %r" % (section,value))


class _SectionObject(object):
    """
        Common behaviour for prerequisite/update objects which are both
        high level semantic entries and know how to convert to/from
        wire RRs.
    """

    # 'prerequisite' or 'update'
    section = None
    # semantic kind tag (see the KIND_* constants below)
    kind = None

    def to_rr(self):
        """
            Convert to a wire-format RR.
        """
        raise NotImplementedError

    def __repr__(self):
        return "<%s %s %s>" % (type(self).__name__,self.kind,self.to_zone())

    def to_zone(self):
        """
            Short one-line textual description (used in repr/errors).
        """
        raise NotImplementedError

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        return self.to_rr_tuple() == other.to_rr_tuple()

    def __ne__(self,other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((type(self).__name__,self.to_rr_tuple()))

    def to_rr_tuple(self):
        rr = self.to_rr()
        return (str(rr.rname),rr.rtype,rr.rclass,rr.ttl,
                repr(rr.rdata))


# ---------------------------------------------------------------------------
# Prerequisite section objects (RFC2136 section 2.4)
# ---------------------------------------------------------------------------

class _Prerequisite(_SectionObject):
    section = "prerequisite"


class RRsetExists(_Prerequisite):
    """
        Prerequisite: an RRset of the given TYPE exists at NAME
        (RFC2136 2.4.1). TYPE is explicit (not ANY), CLASS is the zone
        CLASS, TTL=0 and RDATA is zero length.
    """

    kind = "rrset_exists"

    def __init__(self,name,rtype,rclass=None):
        self.name = _label(name,"prerequisite rrset_exists")
        self.rtype = _type_code(rtype,"prerequisite rrset_exists")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 prerequisite rrset_exists (%s): TYPE must not be ANY "
                "(use name_in_use)" % self.name)
        self.rclass = rclass

    def bind_class(self,zone_class):
        if self.rclass is None:
            self.rclass = zone_class
        return self

    def to_rr(self):
        if self.rclass is None:
            raise DNSError(
                "RFC2136 prerequisite rrset_exists (%s): CLASS not bound to "
                "a zone" % self.name)
        return RR(self.name,self.rtype,self.rclass,0,EmptyRD())

    def to_zone(self):
        return "%s %s" % (self.name,QTYPE.get(self.rtype))

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and
                rr.rclass != CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype,rr.rclass)
        return None


class NameInUse(_Prerequisite):
    """
        Prerequisite: NAME owns at least one RRset of any TYPE
        (RFC2136 2.4.2). TYPE=ANY, CLASS is the zone CLASS, TTL=0 and
        RDATA is zero length.
    """

    kind = "name_in_use"

    def __init__(self,name,rclass=None):
        self.name = _label(name,"prerequisite name_in_use")
        self.rclass = rclass

    def bind_class(self,zone_class):
        if self.rclass is None:
            self.rclass = zone_class
        return self

    def to_rr(self):
        if self.rclass is None:
            raise DNSError(
                "RFC2136 prerequisite name_in_use (%s): CLASS not bound to "
                "a zone" % self.name)
        return RR(self.name,QTYPE.ANY,self.rclass,0,EmptyRD())

    def to_zone(self):
        return "%s ANY" % self.name

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype == QTYPE.ANY and
                rr.rclass != CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rclass)
        return None


class RRsetAbsent(_Prerequisite):
    """
        Prerequisite: no RRset of the given TYPE exists at NAME
        (RFC2136 2.4.3). TYPE is explicit, CLASS=NONE, TTL=0 and RDATA
        is zero length.
    """

    kind = "rrset_absent"

    def __init__(self,name,rtype):
        self.name = _label(name,"prerequisite rrset_absent")
        self.rtype = _type_code(rtype,"prerequisite rrset_absent")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 prerequisite rrset_absent (%s): TYPE must not be ANY "
                "(use name_not_in_use)" % self.name)

    def bind_class(self,zone_class):
        return self

    def to_rr(self):
        return RR(self.name,self.rtype,CLASS_NONE,0,EmptyRD())

    def to_zone(self):
        return "%s %s" % (self.name,QTYPE.get(self.rtype))

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and
                rr.rclass == CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype)
        return None


class NameNotInUse(_Prerequisite):
    """
        Prerequisite: NAME owns no RRsets of any TYPE
        (RFC2136 2.4.4). TYPE=ANY, CLASS=NONE, TTL=0, RDATA zero length.
    """

    kind = "name_not_in_use"

    def __init__(self,name):
        self.name = _label(name,"prerequisite name_not_in_use")

    def bind_class(self,zone_class):
        return self

    def to_rr(self):
        return RR(self.name,QTYPE.ANY,CLASS_NONE,0,EmptyRD())

    def to_zone(self):
        return "%s ANY" % self.name

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype == QTYPE.ANY and
                rr.rclass == CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname)
        return None


class RRsetValue(_Prerequisite):
    """
        Prerequisite: the RRset at NAME/TYPE contains exactly RDATA
        (RFC2136 2.4.5). CLASS is the zone CLASS, TTL=0 and RDATA is
        given (non-empty).
    """

    kind = "rrset_value"

    def __init__(self,name,rtype,rdata,rclass=None):
        self.name = _label(name,"prerequisite rrset_value")
        if isinstance(rdata,EmptyRD) or (
                isinstance(rdata,RD) and getattr(rdata,'data',None) == b""):
            raise DNSError(
                "RFC2136 prerequisite rrset_value (%s): RDATA must not be "
                "empty" % _label(name,"prerequisite rrset_value"))
        if rtype is None:
            rtype = _rdata_code(rdata)
            if rtype is None:
                raise DNSError(
                    "RFC2136 prerequisite rrset_value (%s): cannot infer "
                    "TYPE from RDATA %r - specify rtype explicitly" % (
                        _label(name,"prerequisite rrset_value"),rdata))
        self.rtype = _type_code(rtype,"prerequisite rrset_value")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 prerequisite rrset_value (%s): TYPE must not be ANY"
                % self.name)
        if not isinstance(rdata,RD):
            raise DNSError(
                "RFC2136 prerequisite rrset_value (%s): RDATA must be an RD "
                "instance [%s]" % (self.name,type(rdata).__name__))
        self.rdata = rdata
        self.rclass = rclass

    def bind_class(self,zone_class):
        if self.rclass is None:
            self.rclass = zone_class
        return self

    def to_rr(self):
        if self.rclass is None:
            raise DNSError(
                "RFC2136 prerequisite rrset_value (%s): CLASS not bound to "
                "a zone" % self.name)
        return RR(self.name,self.rtype,self.rclass,0,self.rdata)

    def to_zone(self):
        return "%s %s %s" % (self.name,QTYPE.get(self.rtype),self.rdata)

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and
                rr.rclass != CLASS_NONE and
                rr.ttl == 0 and
                not isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype,rr.rdata,rr.rclass)
        return None


# ---------------------------------------------------------------------------
# Update section objects (RFC2136 section 2.5)
# ---------------------------------------------------------------------------

class _Update(_SectionObject):
    section = "update"


class AddRecord(_Update):
    """
        Update action: add an RR to the RRset at NAME/TYPE (RFC2136
        2.5.1). CLASS is the zone CLASS, TTL is given and RDATA is given
        (non-empty).
    """

    kind = "add"

    def __init__(self,name,rtype,rdata,ttl=0,rclass=None):
        self.name = _label(name,"update add")
        if isinstance(rdata,EmptyRD) or (
                isinstance(rdata,RD) and getattr(rdata,'data',None) == b""):
            raise DNSError(
                "RFC2136 update add (%s): RDATA must not be empty" %
                _label(name,"update add"))
        if rtype is None:
            rtype = _rdata_code(rdata)
            if rtype is None:
                raise DNSError(
                    "RFC2136 update add (%s): cannot infer TYPE from RDATA "
                    "%r - specify rtype explicitly" % (
                        _label(name,"update add"),rdata))
        self.rtype = _type_code(rtype,"update add")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 update add (%s): TYPE must not be ANY" % self.name)
        if not isinstance(rdata,RD):
            raise DNSError(
                "RFC2136 update add (%s): RDATA must be an RD instance [%s]"
                % (self.name,type(rdata).__name__))
        if not isinstance(ttl,int) or ttl < 0 or ttl > _MAX_TTL:
            raise DNSError(
                "RFC2136 update add (%s): TTL must be an unsigned 31-bit "
                "integer (0-%d) [%r]" % (self.name,_MAX_TTL,ttl))
        self.rdata = rdata
        self.ttl = ttl
        self.rclass = rclass

    def bind_class(self,zone_class):
        if self.rclass is None:
            self.rclass = zone_class
        return self

    def to_rr(self):
        if self.rclass is None:
            raise DNSError(
                "RFC2136 update add (%s): CLASS not bound to a zone" %
                self.name)
        return RR(self.name,self.rtype,self.rclass,self.ttl,self.rdata)

    def to_zone(self):
        return "%s %d %s %s" % (
                    self.name,self.ttl,QTYPE.get(self.rtype),self.rdata)

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and
                rr.rclass != CLASS_NONE and
                not isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype,rr.rdata,rr.ttl,rr.rclass)
        return None


class DeleteName(_Update):
    """
        Update action: delete every RRset owned by NAME (RFC2136 2.5.2).
        TYPE=ANY, CLASS=NONE, TTL=0, RDATA zero length.
    """

    kind = "delete_name"

    def __init__(self,name):
        self.name = _label(name,"update delete_name")

    def bind_class(self,zone_class):
        return self

    def to_rr(self):
        return RR(self.name,QTYPE.ANY,CLASS_NONE,0,EmptyRD())

    def to_zone(self):
        return "%s ANY" % self.name

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype == QTYPE.ANY and rr.rclass == CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname)
        return None


class DeleteRRset(_Update):
    """
        Update action: delete the whole RRset of the given TYPE at NAME
        (RFC2136 2.5.3). CLASS=NONE, TTL=0, RDATA zero length.
    """

    kind = "delete_rrset"

    def __init__(self,name,rtype):
        self.name = _label(name,"update delete_rrset")
        self.rtype = _type_code(rtype,"update delete_rrset")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 update delete_rrset (%s): TYPE must not be ANY "
                "(use delete_name)" % self.name)

    def bind_class(self,zone_class):
        return self

    def to_rr(self):
        return RR(self.name,self.rtype,CLASS_NONE,0,EmptyRD())

    def to_zone(self):
        return "%s %s" % (self.name,QTYPE.get(self.rtype))

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and rr.rclass == CLASS_NONE and
                rr.ttl == 0 and
                isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype)
        return None


class DeleteRecord(_Update):
    """
        Update action: delete exactly the RRs matching NAME/TYPE/RDATA
        (RFC2136 2.5.4). CLASS=NONE, TTL=0, RDATA given (non-empty).
    """

    kind = "delete_record"

    def __init__(self,name,rtype,rdata):
        self.name = _label(name,"update delete_record")
        if isinstance(rdata,EmptyRD) or (
                isinstance(rdata,RD) and getattr(rdata,'data',None) == b""):
            raise DNSError(
                "RFC2136 update delete_record (%s): RDATA must not be empty" %
                _label(name,"update delete_record"))
        if rtype is None:
            rtype = _rdata_code(rdata)
            if rtype is None:
                raise DNSError(
                    "RFC2136 update delete_record (%s): cannot infer TYPE "
                    "from RDATA %r - specify rtype explicitly" % (
                        _label(name,"update delete_record"),rdata))
        self.rtype = _type_code(rtype,"update delete_record")
        if self.rtype == QTYPE.ANY:
            raise DNSError(
                "RFC2136 update delete_record (%s): TYPE must not be ANY" %
                self.name)
        if not isinstance(rdata,RD):
            raise DNSError(
                "RFC2136 update delete_record (%s): RDATA must be an RD "
                "instance [%s]" % (self.name,type(rdata).__name__))
        self.rdata = rdata

    def bind_class(self,zone_class):
        return self

    def to_rr(self):
        return RR(self.name,self.rtype,CLASS_NONE,0,self.rdata)

    def to_zone(self):
        return "%s %s %s" % (self.name,QTYPE.get(self.rtype),self.rdata)

    @classmethod
    def from_rr(cls,rr):
        if (rr.rtype != QTYPE.ANY and rr.rclass == CLASS_NONE and
                rr.ttl == 0 and
                not isinstance(rr.rdata,EmptyRD)):
            return cls(rr.rname,rr.rtype,rr.rdata)
        return None


# Order matters for classification only where EmptyRD/CLASS/TYPE overlap;
# the classifiers below are themselves exact so the list is just a registry.
_PREREQUISITE_TYPES = (RRsetExists, NameInUse, RRsetAbsent,
                       NameNotInUse, RRsetValue)
_UPDATE_TYPES = (AddRecord, DeleteName, DeleteRRset, DeleteRecord)


def _classify(rr,types,section):
    """
        Turn a wire RR back into exactly one semantic object using only
        the RFC2136 TYPE/CLASS/TTL/RDLENGTH context - RDATA contents are
        never guessed to determine the operation.
    """
    for cls in types:
        obj = cls.from_rr(rr)
        if obj is not None:
            return obj
    raise DNSError(
        "RFC2136 %s: invalid entry '%s' rtype=%s rclass=%s ttl=%d "
        "rdlength_empty=%s (no matching RFC2136 form)" % (
            section,
            rr.rname,
            QTYPE.get(rr.rtype),
            CLASS.get(rr.rclass),
            rr.ttl,
            isinstance(rr.rdata,EmptyRD)))


class DNSUpdate(object):
    """
        High level RFC2136 DNS UPDATE message builder/parser.

        >>> from dnslib import A, MX
        >>> msg = DNSUpdate("example.com", id=0xabcd)
        >>> msg.name_in_use("example.com")
        >>> msg.rrset_absent("host.example.com", A)
        >>> msg.add("host.example.com", A, A("192.0.2.1"), ttl=3600)
        >>> msg.add("host.example.com", MX("mx.example.com", 10), ttl=3600)
        >>> msg.delete_name("gone.example.com")
        >>> msg.delete_rrset("old.example.com", A)
        >>> msg.delete_record("keep.example.com", A, A("192.0.2.2"))
        >>> again = DNSUpdate.parse(msg.pack())
        >>> again == msg
        True
        >>> again.zone_name
        <DNSLabel: 'example.com.'>
        >>> [p.kind for p in again.prerequisites]
        ['name_in_use', 'rrset_absent']
        >>> [u.kind for u in again.updates]
        ['add', 'add', 'delete_name', 'delete_rrset', 'delete_record']
    """

    def __init__(self,zone="",zone_class="IN",id=None,qr=0,rcode=0):
        self.zone_name = DNSLabel(zone)
        self.zone_class = _code(zone_class,CLASS,"CLASS","zone")
        # A zone section must name a real CLASS (IN/CS/CH/HS); NONE/* are
        # meta-classes only legal inside prerequisite/update entries
        if self.zone_class in (CLASS_NONE,CLASS_ANY) or not (
                1 <= self.zone_class <= 4):
            raise DNSError(
                "RFC2136 zone (%s): unsupported zone CLASS code %d" % (
                    self.zone_name,self.zone_class))
        self.prerequisites = []
        self.updates = []
        self.additional = []
        # Mirror DNSHeader: pick a random TXID unless one was supplied
        self.id = random.randint(0,65535) if id is None else id
        self.qr = qr
        self.rcode = rcode

    # -- Prerequisite shortcuts -------------------------------------------

    def rrset_exists(self,name,rtype="A",rclass=None):
        """
            Add a section-2.4.1 prerequisite (RRset of TYPE exists).
        """
        entry = RRsetExists(name,rtype,rclass).bind_class(self.zone_class)
        self._check_in_zone(entry)
        self.prerequisites.append(entry)
        return entry

    def name_in_use(self,name,rclass=None):
        """
            Add a section-2.4.2 prerequisite (NAME owns any RRset).
        """
        entry = NameInUse(name,rclass).bind_class(self.zone_class)
        self._check_in_zone(entry)
        self.prerequisites.append(entry)
        return entry

    def rrset_absent(self,name,rtype="A"):
        """
            Add a section-2.4.3 prerequisite (no RRset of TYPE exists).
        """
        entry = RRsetAbsent(name,rtype)
        self._check_in_zone(entry)
        self.prerequisites.append(entry)
        return entry

    def name_not_in_use(self,name):
        """
            Add a section-2.4.4 prerequisite (NAME owns nothing).
        """
        entry = NameNotInUse(name)
        self._check_in_zone(entry)
        self.prerequisites.append(entry)
        return entry

    def rrset_value(self,name,rdata,rtype=None,rclass=None):
        """
            Add a section-2.4.5 prerequisite (RRset equals RDATA set).
            TYPE is inferred from the RDATA class unless given.
        """
        entry = RRsetValue(name,rtype,rdata,rclass).bind_class(
                            self.zone_class)
        self._check_in_zone(entry)
        self.prerequisites.append(entry)
        return entry

    # -- Update shortcuts -------------------------------------------------

    def add(self,name,rdata,rtype=None,ttl=0,rclass=None):
        """
            Add one or more RRs (section 2.5.1). `rdata` may be a single
            RD instance or an iterable of them (one RR is appended per
            value, all sharing the same NAME/TYPE/CLASS/TTL).
        """
        if isinstance(rdata,RD):
            values = [rdata]
        else:
            values = list(rdata)
        added = []
        for value in values:
            entry = AddRecord(name,rtype,value,ttl,rclass).bind_class(
                                self.zone_class)
            self._check_in_zone(entry)
            self.updates.append(entry)
            added.append(entry)
        return added[0] if len(added) == 1 else added

    def delete_name(self,name):
        """
            Delete all RRsets owned by NAME (section 2.5.2).
        """
        entry = DeleteName(name)
        self._check_in_zone(entry)
        self.updates.append(entry)
        return entry

    def delete_rrset(self,name,rtype="A"):
        """
            Delete the whole RRset of TYPE at NAME (section 2.5.3).
        """
        entry = DeleteRRset(name,rtype)
        self._check_in_zone(entry)
        self.updates.append(entry)
        return entry

    def delete_record(self,name,rdata,rtype=None):
        """
            Delete exactly the RRs matching NAME/TYPE/RDATA (section
            2.5.4). `rdata` may be a single RD instance or an iterable.
        """
        values = [rdata] if isinstance(rdata,RD) else list(rdata)
        deleted = []
        for value in values:
            entry = DeleteRecord(name,rtype,value)
            self._check_in_zone(entry)
            self.updates.append(entry)
            deleted.append(entry)
        return deleted[0] if len(deleted) == 1 else deleted

    # -- Additional section ------------------------------------------------

    def add_ar(self,*rr):
        """
            Add raw additional-section RRs (e.g. EDNS0/TSIG). These go on
            the wire unchanged and may never carry empty RDATA.
        """
        for record in rr:
            if not isinstance(record,RR):
                raise DNSError(
                    "RFC2136 additional: entry must be an RR instance [%s]" %
                    type(record).__name__)
        self.additional.extend(rr)

    # -- Validation --------------------------------------------------------

    def _validate(self):
        """
            Validate every entry against the zone (class + ownership) and
            re-check each operation's own invariants. Error messages
            identify the operation kind.
        """
        for entry in self.prerequisites:
            self._check_in_zone(entry)
            if getattr(entry,'rclass',None) not in (None,CLASS_NONE):
                if entry.rclass != self.zone_class:
                    raise DNSError(
                        "RFC2136 prerequisite %s (%s): CLASS %s does not "
                        "match zone CLASS %s" % (
                            entry.kind,entry.name,
                            CLASS.get(entry.rclass),
                            CLASS.get(self.zone_class)))
            entry.bind_class(self.zone_class)
        for entry in self.updates:
            self._check_in_zone(entry)
            if isinstance(entry,AddRecord):
                if entry.rclass != self.zone_class:
                    raise DNSError(
                        "RFC2136 update %s (%s): CLASS %s does not match "
                        "zone CLASS %s" % (
                            entry.kind,entry.name,
                            CLASS.get(entry.rclass),
                            CLASS.get(self.zone_class)))
            entry.bind_class(self.zone_class)

    def _check_in_zone(self,entry):
        if not _in_zone(entry.name,self.zone_name):
            raise DNSError(
                "RFC2136 %s %s: name '%s' is outside zone '%s'" % (
                    entry.section,entry.kind,entry.name,self.zone_name))

    # -- Packing -----------------------------------------------------------

    def pack(self):
        """
            Validate and encode the UPDATE message to wire bytes.
        """
        self._validate()
        bitmap = (self.qr << 15) | (OPCODE.UPDATE << 11) | (self.rcode & 0xF)
        header = DNSHeader(id=self.id,bitmap=bitmap)
        record = DNSRecord(
            header,
            questions=[DNSQuestion(self.zone_name,QTYPE.SOA,
                                   self.zone_class)],
            rr=[entry.to_rr() for entry in self.prerequisites],
            auth=[entry.to_rr() for entry in self.updates],
            ar=list(self.additional))
        return record.pack()

    # -- Parsing -----------------------------------------------------------

    @classmethod
    def parse(cls,packet):
        """
            Parse an RFC2136 UPDATE message and reconstruct the semantic
            prerequisite/update objects.
        """
        record = DNSRecord.parse(packet)
        if record.header.opcode != OPCODE.UPDATE:
            raise DNSError(
                "RFC2136 parse: not an UPDATE message (opcode=%s)" %
                OPCODE.get(record.header.opcode))
        if record.header.q != 1:
            raise DNSError(
                "RFC2136 parse: zone section must contain exactly 1 entry "
                "[%d]" % record.header.q)
        zone = record.questions[0]
        zone_class = zone.qclass
        if zone_class in (CLASS_NONE,CLASS_ANY) or not (1 <= zone_class <= 4):
            raise DNSError(
                "RFC2136 parse: invalid zone CLASS %s for zone '%s'" % (
                    CLASS.get(zone_class),zone.qname))
        if zone.qtype != QTYPE.SOA:
            raise DNSError(
                "RFC2136 parse: zone section TYPE must be SOA for zone '%s' "
                "[%s]" % (zone.qname,QTYPE.get(zone.qtype)))
        msg = cls(zone.qname,zone_class,
                  id=record.header.id,qr=record.header.qr,
                  rcode=record.header.rcode)
        msg.prerequisites = [_classify(rr,_PREREQUISITE_TYPES,"prerequisite")
                             for rr in record.rr]
        msg.updates = [_classify(rr,_UPDATE_TYPES,"update")
                       for rr in record.auth]
        msg.additional = list(record.ar)
        # Validate class/ownership against the parsed zone
        msg._validate()
        return msg

    # -- Representation / comparison --------------------------------------

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        return (self.zone_name == other.zone_name and
                self.zone_class == other.zone_class and
                self.prerequisites == other.prerequisites and
                self.updates == other.updates)

    def __ne__(self,other):
        return not self.__eq__(other)

    def to_zone(self):
        lines = [
            ";; UPDATE zone=%s class=%s id=%d" % (
                self.zone_name,CLASS.get(self.zone_class),
                self.id),
        ]
        if self.prerequisites:
            lines.append(";; PREREQUISITE SECTION:")
            for entry in self.prerequisites:
                lines.append(";%s\t%s" % (entry.kind,entry.to_zone()))
        if self.updates:
            lines.append(";; UPDATE SECTION:")
            for entry in self.updates:
                lines.append("%s\t%s" % (entry.kind,entry.to_zone()))
        if self.additional:
            lines.append(";; ADDITIONAL SECTION:")
            for rr in self.additional:
                lines.append(str(rr))
        return "\n".join(lines)

    def __repr__(self):
        return "<DNSUpdate zone='%s' class=%s prerequisites=%d updates=%d>" % (
                    self.zone_name,CLASS.get(self.zone_class),
                    len(self.prerequisites),len(self.updates))

    def __str__(self):
        return self.to_zone()
