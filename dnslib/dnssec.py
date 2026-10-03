# -*- coding: utf-8 -*-

"""
    DNSSEC canonical form encoding (RFC 4034 section 6)

    Provides the canonical encoding of an RRset which is the input to
    RRSIG signature generation/verification (RFC 4034 section 3.1.8.1):

        sign( RRSIG_RDATA | RR(1) | RR(2) ... )

    where RRSIG_RDATA is the RRSIG RDATA up to (but excluding) the
    signature field, and RR(i) are the canonical form of the RRs in the
    RRset sorted by canonical RDATA.

    This module only handles the encoding - cryptographic signature
    generation/verification is out of scope.

    Canonical form rules implemented (RFC 4034 sections 6.1/6.2/6.3 and
    RFC 6840 section 5.1):

        - owner names are uncompressed and lowercased
        - wildcard owner names are reconstructed from the RRSIG labels
          field ("*." + rightmost <labels> labels)
        - the TTL is the RRSIG "original TTL" field
        - domain names embedded in the RDATA of the RR types listed in
          RFC 4034 section 6.2 (plus RRSIG/NSEC per RFC 6840 section 5.1)
          are lowercased; all embedded names are uncompressed
        - RDATA of all other types (including TXT and unknown types) is
          copied byte-for-byte
        - RRs are sorted by canonical RDATA treated as left-justified
          unsigned octet sequences; duplicate RRs are removed

    >>> p = lambda x: print(binascii.hexlify(x).decode())

    Canonical owner name (lowercase, uncompressed):

    >>> p(canonical_name("WWW.Example.COM."))
    03777777076578616d706c6503636f6d00

    Canonical A record:

    >>> a = RR("WWW.Example.COM.",QTYPE.A,CLASS.IN,3600,A("192.0.2.1"))
    >>> p(canonical_rr(a))
    03777777076578616d706c6503636f6d000001000100000e100004c0000201

    Domain names in MX RDATA are lowercased (preference untouched):

    >>> mx = RR("Example.COM.",QTYPE.MX,CLASS.IN,3600,MX("Mail.Example.COM.",10))
    >>> p(canonical_rr(mx))
    076578616d706c6503636f6d00000f000100000e100014000a046d61696c076578616d706c6503636f6d00

    TXT RDATA is opaque - case is preserved:

    >>> txt = RR("Example.COM.",QTYPE.TXT,CLASS.IN,3600,TXT(b"AbC"))
    >>> p(canonical_rr(txt))
    076578616d706c6503636f6d000010000100000e10000403416243

    Unknown types are opaque - raw RDATA bytes are preserved (owner is
    still lowercased):

    >>> unk = RR("Example.COM.",65280,CLASS.IN,60,RD(b"\\x03AbC\\x00"))
    >>> p(canonical_rr(unk))
    076578616d706c6503636f6d00ff0000010000003c00050341624300

    Wildcard reconstruction from RRSIG labels/original TTL:

    >>> sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,"Example.COM.",b"")
    >>> p(canonical_rr(a,rrsig=sig))
    012a076578616d706c6503636f6d000001000100000e100004c0000201

    Canonical RRset (sorted by canonical RDATA, duplicates removed):

    >>> rrset = [RR("www.example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.2")),
    ...          RR("WWW.example.com",QTYPE.A,CLASS.IN,3600,A("192.0.2.1")),
    ...          RR("www.example.com",QTYPE.A,CLASS.IN,3600,A("192.0.2.1"))]
    >>> sig = RRSIG(QTYPE.A,8,3,3600,1690844160,1685573632,0x1234,"Example.COM.",b"")
    >>> p(canonical_rrset(rrset,rrsig=sig))
    03777777076578616d706c6503636f6d000001000100000e100004c000020103777777076578616d706c6503636f6d000001000100000e100004c0000202

    Full signature input (RRSIG RDATA prefix + canonical RRset):

    >>> p(rrsig_rdata_prefix(sig))
    0001080300000e1064c83c006477d0001234076578616d706c6503636f6d00
    >>> canonical_signed_data(rrset,rrsig=sig) == rrsig_rdata_prefix(sig) + canonical_rrset(rrset,rrsig=sig)
    True
"""

from __future__ import print_function

import binascii

from dnslib.dns import A,CLASS,DNSError,MX,QTYPE,RD,RR,RRSIG,TXT
from dnslib.label import DNSBuffer,DNSLabel

__all__ = [
    'CanonicalDNSBuffer',
    'LOWERCASE_RDATA_TYPES',
    'canonical_name',
    'canonical_rdata',
    'canonical_rr',
    'canonical_rrset',
    'rrsig_rdata_prefix',
    'canonical_signed_data',
]

# RR types whose RDATA contains embedded domain names which must be
# lowercased in the canonical form (RFC 4034 section 6.2, extended with
# RRSIG/NSEC by RFC 6840 section 5.1). RDATA of all other types (and of
# unknown types) is treated as opaque and copied byte-for-byte.
LOWERCASE_RDATA_TYPES = frozenset([
    2,      # NS
    3,      # MD
    4,      # MF
    5,      # CNAME
    6,      # SOA
    7,      # MB
    8,      # MG
    9,      # MR
    12,     # PTR
    13,     # HINFO
    14,     # MINFO
    15,     # MX
    17,     # RP
    18,     # AFSDB
    21,     # RT
    24,     # SIG
    26,     # PX
    30,     # NXT
    33,     # SRV
    35,     # NAPTR
    36,     # KX
    38,     # A6
    39,     # DNAME
    46,     # RRSIG (RFC 6840 section 5.1)
    47,     # NSEC  (RFC 6840 section 5.1)
])


class CanonicalDNSBuffer(DNSBuffer):

    """
        DNSBuffer which encodes domain names in canonical form -
        uncompressed, and lowercased when `downcase` is set (RFC 4034
        sections 6.1/6.2)

        Both encode_name() and encode_name_nocompress() produce the
        canonical encoding so RD.pack() implementations can be used
        unchanged. Data written with pack()/append() is copied unchanged.

        >>> p = lambda x: print(binascii.hexlify(x).decode())
        >>> b = CanonicalDNSBuffer()
        >>> b.encode_name("WWW.Example.COM.")
        >>> p(b.data)
        03777777076578616d706c6503636f6d00
        >>> b = CanonicalDNSBuffer(downcase=False)
        >>> b.encode_name_nocompress("WWW.Example.COM.")
        >>> p(b.data)
        03575757074578616d706c6503434f4d00
    """

    def __init__(self,data=b'',downcase=True):
        super(CanonicalDNSBuffer,self).__init__(data)
        self.downcase = downcase

    def _encode_canonical_name(self,name):
        if not isinstance(name,DNSLabel):
            name = DNSLabel(name)
        for element in name.label:
            if self.downcase:
                element = element.lower()
            if len(element) > 63:
                raise DNSError("Label component too long: %r" % element)
            self.pack("!B",len(element))
            self.append(element)
        self.append(b'\x00')

    def encode_name(self,name):
        self._encode_canonical_name(name)

    def encode_name_nocompress(self,name):
        self._encode_canonical_name(name)


def canonical_name(name):
    """
        Return the canonical wire-format encoding of a domain name -
        uncompressed and lowercased (RFC 4034 section 6.1)
    """
    buf = CanonicalDNSBuffer()
    buf.encode_name(name)
    return bytes(buf.data)


def canonical_rdata(rtype,rdata):
    """
        Return the canonical wire-format encoding of `rdata` (an RD
        instance) for record type `rtype` (RFC 4034 section 6.2)

        Embedded domain names are lowercased for the RR types listed in
        LOWERCASE_RDATA_TYPES and are never compressed. RDATA of all
        other types (including TXT and unknown types) is copied
        byte-for-byte.
    """
    buf = CanonicalDNSBuffer(downcase=rtype in LOWERCASE_RDATA_TYPES)
    rdata.pack(buf)
    return bytes(buf.data)


def _rrsig_params(rrsig):
    """
        Extract (orig_ttl,labels) from an RRSIG RD instance (or an RR
        wrapping one)
    """
    if isinstance(rrsig,RR):
        rrsig = rrsig.rdata
    if not isinstance(rrsig,RRSIG):
        raise DNSError("Expected RRSIG rdata [%s]" % type(rrsig).__name__)
    return rrsig.orig_ttl,rrsig.labels


def _wildcard_owner(owner,labels):
    """
        Reconstruct the owner name from the RRSIG labels field - if
        `labels` is less than the number of labels in `owner` the RRset
        was synthesised from a wildcard and the owner is
        "*." + rightmost <labels> labels (RFC 4034 section 3.1.3)
    """
    if not isinstance(owner,DNSLabel):
        owner = DNSLabel(owner)
    if labels is None or labels == len(owner.label):
        return owner
    if labels > len(owner.label):
        raise DNSError("RRSIG labels (%d) exceeds owner label count (%d)" %
                                (labels,len(owner.label)))
    return DNSLabel((b'*',) + owner.label[len(owner.label)-labels:])


def _canonical_rr(rr,rdata,orig_ttl,labels):
    """
        Canonical form of `rr` with precomputed canonical `rdata` bytes
    """
    owner = _wildcard_owner(rr.rname,labels)
    ttl = rr.ttl if orig_ttl is None else orig_ttl
    buf = CanonicalDNSBuffer()
    buf.encode_name(owner)
    buf.pack("!HHIH",rr.rtype,rr.rclass,ttl,len(rdata))
    buf.append(rdata)
    return bytes(buf.data)


def canonical_rr(rr,rrsig=None,orig_ttl=None,labels=None):
    """
        Return the canonical form of a single RR (RFC 4034 section 6.2)

        The TTL and owner name are taken from the RRSIG "original TTL"
        and "labels" fields - supply either an RRSIG RD instance (or an
        RR wrapping one) as `rrsig`, or the `orig_ttl`/`labels` values
        directly. Without these the RR's own TTL and owner are used.

        The RR is not modified.

        >>> p = lambda x: print(binascii.hexlify(x).decode())
        >>> mx = RR("Example.COM.",QTYPE.MX,CLASS.IN,60,MX("Mail.Example.COM.",10))
        >>> p(canonical_rr(mx,orig_ttl=3600))
        076578616d706c6503636f6d00000f000100000e100014000a046d61696c076578616d706c6503636f6d00
        >>> mx.ttl
        60
    """
    if rrsig is not None:
        orig_ttl,labels = _rrsig_params(rrsig)
    return _canonical_rr(rr,canonical_rdata(rr.rtype,rr.rdata),orig_ttl,labels)


def canonical_rrset(rrset,rrsig=None,orig_ttl=None,labels=None):
    """
        Return the canonical encoding of an RRset - the sequence of
        canonical RRs sorted by canonical RDATA (treated as left-justified
        unsigned octet sequences) with duplicates removed (RFC 4034
        section 6.3)

        All RRs must have the same owner name (case-insensitive), class
        and type - a DNSError is raised otherwise. TTL/owner are handled
        as in canonical_rr(). The input RRs are not modified.
    """
    rrs = list(rrset)
    if not rrs:
        raise DNSError("Empty RRset")
    if rrsig is not None:
        orig_ttl,labels = _rrsig_params(rrsig)
    first = rrs[0]
    for rr in rrs[1:]:
        if DNSLabel(rr.rname) != DNSLabel(first.rname):
            raise DNSError("RRset owner mismatch: %s != %s" %
                                (rr.rname,first.rname))
        if rr.rclass != first.rclass:
            raise DNSError("RRset class mismatch: %s != %s" %
                                (CLASS.get(rr.rclass),CLASS.get(first.rclass)))
        if rr.rtype != first.rtype:
            raise DNSError("RRset type mismatch: %s != %s" %
                                (QTYPE.get(rr.rtype),QTYPE.get(first.rtype)))
    canonical = {}
    for rr in rrs:
        rdata = canonical_rdata(rr.rtype,rr.rdata)
        record = _canonical_rr(rr,rdata,orig_ttl,labels)
        canonical.setdefault(record,(rdata,record))
    return b"".join(record for (_,record) in
                        sorted(canonical.values(),
                               key=lambda item: (item[0],item[1])))


def rrsig_rdata_prefix(rrsig):
    """
        Return the canonical encoding of the RRSIG RDATA up to (but
        excluding) the signature field (RFC 4034 section 3.1.8.1) - the
        signer's name is lowercased and uncompressed

        Accepts an RRSIG RD instance or an RR wrapping one.
    """
    if isinstance(rrsig,RR):
        rrsig = rrsig.rdata
    if not isinstance(rrsig,RRSIG):
        raise DNSError("Expected RRSIG rdata [%s]" % type(rrsig).__name__)
    buf = CanonicalDNSBuffer()
    buf.pack("!HBBIIIH",rrsig.covered,rrsig.algorithm,rrsig.labels,
                        rrsig.orig_ttl,rrsig.sig_exp,rrsig.sig_inc,
                        rrsig.key_tag)
    buf.encode_name(rrsig.name)
    return bytes(buf.data)


def canonical_signed_data(rrset,rrsig):
    """
        Return the full canonical input to RRSIG signature
        generation/verification (RFC 4034 section 3.1.8.1):

            RRSIG_RDATA (excluding signature) | canonical RRset

        The TTL and owner name are taken from the RRSIG original TTL and
        labels fields. Neither the RRset nor the RRSIG is modified.
    """
    return rrsig_rdata_prefix(rrsig) + canonical_rrset(rrset,rrsig=rrsig)


if __name__ == '__main__':
    import doctest,sys
    sys.exit(0 if doctest.testmod(optionflags=doctest.ELLIPSIS).failed == 0 else 1)
