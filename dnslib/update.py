# -*- coding: utf-8 -*-

"""
    RFC 2136 - DNS UPDATE message construction/parsing

    DNS UPDATE reuses the standard DNS packet sections with different
    semantics:

        Question section    -> Zone section          (exactly one SOA)
        Answer section      -> Prerequisite section  (RFC 2136 section 2.4)
        Authority section   -> Update section        (RFC 2136 section 2.5)
        Additional section  -> Additional section

    DNSUpdate hides the wire-format bookkeeping (section placement, special
    CLASS/TTL values and the empty-RDATA wildcard RRsets) from callers -
    only the intended operation needs to be specified:

        >>> from dnslib.update import DNSUpdate
        >>> from dnslib import A
        >>> u = DNSUpdate("example.com",id=1)
        >>> _ = u.prereq_name_in_use("host.example.com")
        >>> _ = u.prereq_rrset_not_exists("host.example.com","A")
        >>> _ = u.add("host.example.com",3600,A("1.2.3.4"))
        >>> _ = u.delete_rr("old.example.com",A("1.2.3.5"))
        >>> parsed = DNSUpdate.parse(u.pack())
        >>> parsed == u
        True

    Empty RDATA is only legal in the prerequisite/update sections of an
    RFC2136 UPDATE message; a zero-length A/MX (etc) record in a normal
    query response is still rejected by RR.parse.

    This module only constructs/explains messages - it does not modify any
    server-side zone.
"""

from __future__ import print_function

from dnslib.buffer import BufferError
from dnslib.dns import (DNSError,DNSRecord,DNSHeader,DNSQuestion,RR,RD,
                        QTYPE,CLASS,OPCODE,DNSBuffer,DNSLabel,RDMAP)

# RFC 2136 special class values (the CLASS bimap already contains these)
CLASS_NONE = getattr(CLASS,'None')  # 254 - class not set / wildcard NONE
CLASS_ANY  = getattr(CLASS,'*')     # 255 - wildcard ANY
CLASS_MAX  = 0x00FD                 # RFC 2929: meta CLASSes start at 254

# RFC 2136: the TTL sign bit must be zero
TTL_MAX = 0x7FFFFFFF

# Operation labels used in error messages (indicate which kind of update
# operation was invalid)
ZONE             = "zone"
PREREQ_NAME      = "prerequisite name is in use"
PREREQ_NO_NAME   = "prerequisite name is not in use"
PREREQ_RRSET     = "prerequisite rrset exists"
PREREQ_NO_RRSET  = "prerequisite rrset not exists"
PREREQ_RR        = "prerequisite rr is in use"
PREREQ_NO_RR     = "prerequisite rr not in use"
UPDATE_ADD       = "update add"
UPDATE_DEL_NAME  = "update delete name"
UPDATE_DEL_RRSET = "update delete rrset"
UPDATE_DEL_RR    = "update delete rr"

# Labels for the classified forms (used in parse-time error messages)
PREREQ_KIND_LABEL = {
    'name_in_use':      PREREQ_NAME,
    'name_not_in_use':  PREREQ_NO_NAME,
    'rrset_exists':     PREREQ_RRSET,
    'rrset_not_exists': PREREQ_NO_RRSET,
    'rr_in_use':        PREREQ_RR,
    'rr_not_in_use':    PREREQ_NO_RR,
}
UPDATE_KIND_LABEL = {
    'add':          UPDATE_ADD,
    'delete_name':  UPDATE_DEL_NAME,
    'delete_rrset': UPDATE_DEL_RRSET,
    'delete_rr':    UPDATE_DEL_RR,
}

# Reverse map RD subclass -> rtype name (used to infer rtype from rdata)
RD_TO_QTYPE = dict([(cls,name) for name,cls in RDMAP.items()])


def qtype_value(rtype):
    """
        Normalise an rtype (numeric or QTYPE name) to its numeric value
    """
    if isinstance(rtype,str):
        try:
            return getattr(QTYPE,rtype)
        except DNSError as e:
            raise DNSError("Invalid rtype '%s': %s" % (rtype,e))
    return rtype


def rclass_value(rclass):
    """
        Normalise an rclass (numeric or CLASS name) to its numeric value
    """
    if isinstance(rclass,str):
        try:
            return getattr(CLASS,rclass)
        except DNSError as e:
            raise DNSError("Invalid rclass '%s': %s" % (rclass,e))
    return rclass


def _rtype_of(rdata,rtype=None):
    """
        Determine the numeric rtype - use explicit rtype if given,
        otherwise infer from the RD subclass
    """
    if rtype is not None:
        return qtype_value(rtype)
    name = RD_TO_QTYPE.get(rdata.__class__)
    if name is None:
        raise DNSError(
            "Cannot infer rtype from rdata class %s - pass rtype explicitly"
                                    % rdata.__class__.__name__)
    return getattr(QTYPE,name)


def _empty_rdata(rr):
    """
        Return True if the RR packs to zero length RDATA
        (the RFC2136 wildcard RRset form)
    """
    if rr.rtype == QTYPE.OPT or not isinstance(rr.rdata,RD):
        return False
    buf = DNSBuffer()
    rr.rdata.pack(buf)
    return len(buf.data) == 0


def classify_prerequisite(rr,zone_class):
    """
        Determine which RFC2136 section 2.4 form a prerequisite RR encodes
        from the wire context (CLASS/TTL/RDLENGTH - not by guessing at the
        rtype):

            name_in_use        TYPE=ANY  CLASS=NONE(254) RDLENGTH=0
            name_not_in_use    TYPE=ANY  CLASS=ANY(255)  RDLENGTH=0
            rrset_exists       TYPE=type CLASS=NONE(254) RDLENGTH=0
            rrset_not_exists   TYPE=type CLASS=zone      RDLENGTH=0
            rr_in_use          TYPE=type CLASS=zone      RDLENGTH>0
            rr_not_in_use      TYPE=type CLASS=NONE(254) RDLENGTH>0

        Returns None if the RR does not match a legal prerequisite form.
    """
    if rr.rtype == QTYPE.OPT or rr.ttl != 0:
        return None
    if _empty_rdata(rr):
        if rr.rclass == CLASS_NONE and rr.rtype == QTYPE.ANY:
            return 'name_in_use'
        if rr.rclass == CLASS_ANY and rr.rtype == QTYPE.ANY:
            return 'name_not_in_use'
        if rr.rclass == CLASS_NONE and rr.rtype != QTYPE.ANY:
            return 'rrset_exists'
        if rr.rclass == zone_class and rr.rtype != QTYPE.ANY:
            return 'rrset_not_exists'
        return None
    else:
        if rr.rclass == zone_class and rr.rtype != QTYPE.ANY:
            return 'rr_in_use'
        if rr.rclass == CLASS_NONE and rr.rtype != QTYPE.ANY:
            return 'rr_not_in_use'
        return None


def classify_update(rr,zone_class):
    """
        Determine which RFC2136 section 2.5 form an update RR encodes:

            add          CLASS=zone RDLENGTH>0 TTL!=0
            delete_name  TYPE=ANY  CLASS=ANY(255)  RDLENGTH=0 TTL=0
            delete_rrset TYPE=type CLASS=NONE(254) RDLENGTH=0 TTL=0
            delete_rr    TYPE=type CLASS=zone      RDLENGTH>0 TTL=0

        Returns None if the RR does not match a legal update form.
    """
    if rr.rtype == QTYPE.OPT:
        return None
    if _empty_rdata(rr):
        # RFC 2136 section 2.5.2/2.5.3: the TTL of the wildcard forms
        # must be zero
        if rr.ttl != 0:
            return None
        if rr.rclass == CLASS_ANY and rr.rtype == QTYPE.ANY:
            return 'delete_name'
        if rr.rclass == CLASS_NONE and rr.rtype != QTYPE.ANY:
            return 'delete_rrset'
        return None
    else:
        if rr.rclass != zone_class or rr.rtype == QTYPE.ANY:
            return None
        return 'add' if rr.ttl != 0 else 'delete_rr'


class DNSUpdate(DNSRecord):

    """
        RFC 2136 DNS UPDATE message

        >>> from dnslib import A
        >>> u = DNSUpdate("example.com",id=1)
        >>> _ = u.add("host.example.com",300,A("1.2.3.4"))
        >>> u.header.opcode == OPCODE.UPDATE
        True
        >>> DNSUpdate.parse(u.pack()) == u
        True
    """

    @classmethod
    def _parse_update(cls,buffer,header):
        """
            Parse the remaining sections of an UPDATE message after the
            header (called by DNSRecord.parse, which dispatches on the
            UPDATE opcode)
        """
        try:
            zone = []
            prereq = []
            update = []
            ar = []
            for i in range(header.q):
                zone.append(DNSQuestion.parse(buffer))
            # Zero length RDATA is only legal in the prerequisite and
            # update sections of an UPDATE *request* - it is never legal
            # in a response or in the additional section
            allow_empty = header.qr == 0
            for i in range(header.a):
                prereq.append(RR.parse(buffer,allow_empty=allow_empty))
            for i in range(header.auth):
                update.append(RR.parse(buffer,allow_empty=allow_empty))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
        except (DNSError,BufferError) as e:
            raise DNSError("Error unpacking DNSUpdate [offset=%d]: %s" % (
                                    buffer.offset,e))
        rec = cls.__new__(cls)
        DNSRecord.__init__(rec,
                           DNSHeader(header.id,header.bitmap,
                                     header.q,header.a,header.auth,header.ar),
                           questions=zone,rr=prereq,auth=update,ar=ar)
        rec._validate()
        return rec

    @classmethod
    def parse(cls,packet):
        """
            Parse an UPDATE packet (thin wrapper over DNSRecord.parse
            which dispatches on the UPDATE opcode)
        """
        rec = DNSRecord.parse(packet)
        if rec.header.opcode != OPCODE.UPDATE:
            raise DNSError("Not a DNS UPDATE message (opcode=%s)" %
                                OPCODE.get(rec.header.opcode))
        return rec

    def __init__(self,zone=None,zone_class="IN",id=None):
        """
            Create a new UPDATE message for the given zone.

        ``zone_class`` is the zone CLASS (default IN, numeric or name).
        """
        if zone is None:
            raise DNSError("DNSUpdate requires a zone name")
        zclass = rclass_value(zone_class)
        if not (1 <= zclass <= CLASS_MAX):
            raise DNSError("%s: invalid zone class %d (must be in 1-253)" % (
                                ZONE,zclass))
        header = DNSHeader(id=id)
        header.bitmap = 0
        header.opcode = OPCODE.UPDATE
        super(DNSUpdate,self).__init__(
            header=header,
            q=DNSQuestion(DNSLabel(zone),QTYPE.SOA,zclass))

    # Section aliases -------------------------------------------------------

    def get_zone(self):
        return self.questions[0] if self.questions else DNSQuestion()
    zone_rr = property(get_zone)

    def get_zone_name(self):
        return self.zone_rr.qname
    zone_name = property(get_zone_name)

    def get_prereq(self):
        return self.rr
    prereq_rrs = property(get_prereq)

    def get_update(self):
        return self.auth
    update_rrs = property(get_update)

    @property
    def zone_class(self):
        return self.zone_rr.qclass

    # Helpers ---------------------------------------------------------------

    def _in_zone(self,name,op):
        """
            Check name is within the zone being updated (RFC 2136 2.2.3 -
            names in the prerequisite/update sections must be in-zone)
        """
        lbl = name if isinstance(name,DNSLabel) else DNSLabel(name)
        if not lbl.matchSuffix(self.zone_name):
            raise DNSError("%s: name '%s' is outside zone '%s'" % (
                                op,lbl,self.zone_name))
        return lbl

    def _check_ttl(self,ttl,op):
        if not isinstance(ttl,int) or ttl < 0 or ttl > TTL_MAX:
            raise DNSError("%s: invalid TTL %r (must be 0-%d)" % (
                                op,ttl,TTL_MAX))
        return ttl

    def _add_prereq(self,rr,op):
        if classify_prerequisite(rr,self.zone_class) is None:
            raise DNSError(
                "%s: RR '%s' %s class=%s ttl=%d is not a legal "
                "prerequisite form" % (
                    op,rr.rname,QTYPE.get(rr.rtype),
                    CLASS.get(rr.rclass),rr.ttl))
        self.rr.append(rr)
        self.set_header_qa()
        return self

    def _add_update(self,rr,op):
        if classify_update(rr,self.zone_class) is None:
            raise DNSError(
                "%s: RR '%s' %s class=%s ttl=%d is not a legal update form"
                                % (op,rr.rname,QTYPE.get(rr.rtype),
                                   CLASS.get(rr.rclass),rr.ttl))
        self.auth.append(rr)
        self.set_header_qa()
        return self

    # Prerequisites (RFC 2136 section 2.4) ----------------------------------

    def prereq_name_in_use(self,name):
        """2.4.1 - at least one RRset (of ANY type) exists for name"""
        self._add_prereq(
            RR(self._in_zone(name,PREREQ_NAME),
               QTYPE.ANY,CLASS_NONE,0,RD(b"")),PREREQ_NAME)
        return self

    def prereq_name_not_in_use(self,name):
        """2.4.2 - no RRset (of ANY type) exists for name"""
        self._add_prereq(
            RR(self._in_zone(name,PREREQ_NO_NAME),
               QTYPE.ANY,CLASS_ANY,0,RD(b"")),PREREQ_NO_NAME)
        return self

    def prereq_rrset_exists(self,name,rtype):
        """2.4.3 - at least one RR of an RRset of rtype exists for name"""
        rtype = qtype_value(rtype)
        if rtype == QTYPE.ANY:
            raise DNSError("%s: rtype must not be ANY" % PREREQ_RRSET)
        self._add_prereq(
            RR(self._in_zone(name,PREREQ_RRSET),
               rtype,CLASS_NONE,0,RD(b"")),PREREQ_RRSET)
        return self

    def prereq_rrset_not_exists(self,name,rtype):
        """2.4.4 - no RRset of rtype exists for name"""
        rtype = qtype_value(rtype)
        if rtype == QTYPE.ANY:
            raise DNSError("%s: rtype must not be ANY" % PREREQ_NO_RRSET)
        self._add_prereq(
            RR(self._in_zone(name,PREREQ_NO_RRSET),
               rtype,self.zone_class,0,RD(b"")),PREREQ_NO_RRSET)
        return self

    def prereq_rr_in_use(self,name,rdata,rtype=None):
        """2.4.5 - the given RR (type & RDATA) exists for name"""
        lbl = self._in_zone(name,PREREQ_RR)
        rr = RR(lbl,_rtype_of(rdata,rtype),self.zone_class,0,rdata)
        if rr.rtype == QTYPE.ANY or _empty_rdata(rr):
            raise DNSError(
                "%s: rtype must not be ANY and RDATA must be non-empty" %
                    PREREQ_RR)
        self._add_prereq(rr,PREREQ_RR)
        return self

    def prereq_rr_not_in_use(self,name,rdata,rtype=None):
        """2.4.6 - the given RR (type & RDATA) does not exist for name"""
        lbl = self._in_zone(name,PREREQ_NO_RR)
        rr = RR(lbl,_rtype_of(rdata,rtype),CLASS_NONE,0,rdata)
        if rr.rtype == QTYPE.ANY or _empty_rdata(rr):
            raise DNSError(
                "%s: rtype must not be ANY and RDATA must be non-empty" %
                    PREREQ_NO_RR)
        self._add_prereq(rr,PREREQ_NO_RR)
        return self

    # Updates (RFC 2136 section 2.5) ----------------------------------------

    def add(self,name,ttl,rdata,rtype=None):
        """2.5.1 - add the given RR to the zone"""
        lbl = self._in_zone(name,UPDATE_ADD)
        ttl = self._check_ttl(ttl,UPDATE_ADD)
        if ttl == 0:
            raise DNSError(
                "%s: TTL must be non-zero (a TTL of 0 with RDATA encodes "
                "'delete RR')" % UPDATE_ADD)
        rr = RR(lbl,_rtype_of(rdata,rtype),self.zone_class,ttl,rdata)
        if rr.rtype == QTYPE.ANY:
            raise DNSError("%s: rtype must not be ANY" % UPDATE_ADD)
        self._add_update(rr,UPDATE_ADD)
        return self

    def delete_name(self,name):
        """2.5.2 - delete all RRsets of name (name must disappear)"""
        self._add_update(
            RR(self._in_zone(name,UPDATE_DEL_NAME),
               QTYPE.ANY,CLASS_ANY,0,RD(b"")),UPDATE_DEL_NAME)
        return self

    def delete_rrset(self,name,rtype):
        """2.5.3 - delete the whole RRset of rtype from name"""
        rtype = qtype_value(rtype)
        if rtype == QTYPE.ANY:
            raise DNSError(
                "%s: rtype must not be ANY (use delete_name to delete all "
                "RRsets of a name)" % UPDATE_DEL_RRSET)
        self._add_update(
            RR(self._in_zone(name,UPDATE_DEL_RRSET),
               rtype,CLASS_NONE,0,RD(b"")),UPDATE_DEL_RRSET)
        return self

    def delete_rr(self,name,rdata,rtype=None):
        """2.5.4 - delete the given RR (type & RDATA) from name"""
        lbl = self._in_zone(name,UPDATE_DEL_RR)
        rr = RR(lbl,_rtype_of(rdata,rtype),self.zone_class,0,rdata)
        if rr.rtype == QTYPE.ANY or _empty_rdata(rr):
            raise DNSError(
                "%s: rtype must not be ANY and RDATA must be non-empty" %
                    UPDATE_DEL_RR)
        self._add_update(rr,UPDATE_DEL_RR)
        return self

    # Validation (also applied to parsed packets) --------------------------

    def _validate(self):
        """
            Validate the structural/semantic rules for an UPDATE request:

                * exactly one zone SOA question with a valid class
                * every prerequisite RR matches a legal section 2.4 form
                  with an in-zone name
                * every update RR matches a legal section 2.5 form with an
                  in-zone name and a valid TTL
        """
        if self.header.qr == 1:
            # UPDATE response - no structural requirements beyond parsing
            return
        if len(self.questions) != 1:
            raise DNSError("%s: expected exactly one zone section, got %d" %
                                (ZONE,len(self.questions)))
        zone = self.questions[0]
        if zone.qtype != QTYPE.SOA:
            raise DNSError(
                "%s: zone question must be SOA (got %s)" %
                    (ZONE,QTYPE.get(zone.qtype)))
        if not (1 <= zone.qclass <= CLASS_MAX):
            raise DNSError("%s: invalid zone class %d (must be in 1-253)" %
                                (ZONE,zone.qclass))
        zname = zone.qname
        for rr in self.rr:
            kind = classify_prerequisite(rr,zone.qclass)
            if kind is None:
                raise DNSError(
                    "prerequisite: RR '%s' %s class=%s ttl=%d does not "
                    "match any legal prerequisite form" % (
                        rr.rname,QTYPE.get(rr.rtype),
                        CLASS.get(rr.rclass),rr.ttl))
            if not rr.rname.matchSuffix(zname):
                raise DNSError(
                    "prerequisite (%s): name '%s' is outside zone '%s'" % (
                        PREREQ_KIND_LABEL[kind],rr.rname,zname))
        for rr in self.auth:
            kind = classify_update(rr,zone.qclass)
            if kind is None:
                raise DNSError(
                    "update: RR '%s' %s class=%s ttl=%d does not match any "
                    "legal update form" % (
                        rr.rname,QTYPE.get(rr.rtype),
                        CLASS.get(rr.rclass),rr.ttl))
            if not rr.rname.matchSuffix(zname):
                raise DNSError(
                    "update (%s): name '%s' is outside zone '%s'" % (
                        UPDATE_KIND_LABEL[kind],rr.rname,zname))
            if kind == 'add':
                self._check_ttl(rr.ttl,"update add")

    def pack(self):
        """
            Pack the UPDATE message. Constructed requests are normalised
            (opcode UPDATE, no query flags) before packing; responses round
            trip unchanged.
        """
        if self.header.qr == 0:
            self.header.opcode = OPCODE.UPDATE
            # Requests carry no header flags (section 3.1)
            for flag in ('rd','ra','aa','tc','ad','cd'):
                setattr(self.header,flag,0)
        return super(DNSUpdate,self).pack()

    def toZone(self,prefix=""):
        """
            DiG/nsupdate-style text representation using RFC2136 section
            names
        """
        z = self.header.toZone().split("\n")
        if self.questions:
            z.append(";; ZONE SECTION:")
            [ z.extend(q.toZone().split("\n")) for q in self.questions ]
        if self.rr:
            z.append(";; PREREQUISITE SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.rr ]
        if self.auth:
            z.append(";; UPDATE SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.auth ]
        if self.ar:
            z.append(";; ADDITIONAL SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.ar ]
        return prefix + ("\n" + prefix).join(z)
