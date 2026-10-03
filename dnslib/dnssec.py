"""
    DNSSEC canonical form encoding (RFC 4034 Section 6)

    Produces the canonical RR / RRset representation used as the input
    to RRSIG signature generation and verification (RFC 4034 Section
    3.1.8.1):

        signature = Sign( RRSIG_RDATA | RR(1) | RR(2) ... )

    where

        RRSIG_RDATA is the RRSIG RDATA with the Signature field excluded
        RR(i) = name | type | class | OrigTTL | RDATA length | RDATA

    This module only encodes - it does not generate or verify signatures.

    Canonicalisation rules implemented (RFC 4034 Section 6):

        - owner names are fully expanded (no compression) and converted
          to lowercase (6.2)
        - if the RRSIG Labels field is smaller than the number of labels
          in the owner name, the owner was wildcard-expanded and the
          original wildcard name ("*" + rightmost <labels> labels) is
          reconstructed (RFC 4034 3.1.3 / RFC 4035 5.3.1)
        - the RRSIG Original TTL field replaces the RR TTL (6.2)
        - domain names embedded in the RDATA of the RR types listed in
          RFC 4034 6.2 (NS, CNAME, SOA, MX, SRV, RRSIG, NSEC, ...) are
          lowercased and uncompressed; the RDATA of all other types
          (including TXT and unknown/opaque types) is transferred
          without case conversion
        - RRs within an RRset are sorted by canonical RDATA treated as
          a left-justified unsigned octet sequence, and duplicates are
          removed (6.3)

    Input RR objects are never modified.

    >>> rr = RR("WWW.Example.COM.",QTYPE.A,ttl=60,rdata=A("192.0.2.1"))
    >>> sig = RRSIG(QTYPE.A,8,3,3600,1800000000,1790000000,12345,"Example.COM.",b"")
    >>> binascii.hexlify(signing_input([rr],sig)).decode()
    '0001080300000e106b49d2006ab13b803039076578616d706c6503636f6d0003777777076578616d706c6503636f6d000001000100000e100004c0000201'
"""

from __future__ import print_function

import struct

from dnslib.dns import DNSError,RRSIG
from dnslib.label import DNSLabel,DNSLabelError,DNSBuffer

__all__ = [
    "RRsetError",
    "LOWERCASE_RDATA_TYPES",
    "canonical_name",
    "canonical_rdata",
    "canonical_rr",
    "canonical_owner",
    "rrsig_rdata",
    "canonical_rrset",
    "signing_input",
]


class RRsetError(DNSError):
    """
        Raised when a list of RRs is not a valid RRset (mismatched
        owner/class/type) or does not match the RRSIG covering it.
    """


# RFC 4034 Section 6.2 - RR types whose RDATA contains embedded domain
# names which must be converted to lowercase in the canonical form.
# RDATA of all other types (including TXT and unknown/opaque types) is
# transferred without case conversion.
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
    46,     # RRSIG
    47,     # NSEC
])


class _CanonicalBuffer(DNSBuffer):
    """
        DNSBuffer which always encodes names uncompressed (disabling
        the pointer compression used by encode_name) and optionally
        lowercases them, as required by the RFC 4034 canonical form.
    """

    def __init__(self,lowercase=False):
        super(_CanonicalBuffer,self).__init__()
        self.lowercase = lowercase

    def encode_name(self,name):
        self.encode_name_nocompress(name)

    def encode_name_nocompress(self,name):
        if self.lowercase:
            self.append(canonical_name(name))
        else:
            super(_CanonicalBuffer,self).encode_name_nocompress(name)


def canonical_name(name):
    """
        Return the canonical wire format of a domain name: fully
        expanded (no compression) with uppercase US-ASCII letters
        replaced by lowercase (RFC 4034 Section 6.2).

        >>> list(canonical_name("WWW.Example.COM."))
        [3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        >>> canonical_name(".")
        b'\\x00'
    """
    if not isinstance(name,DNSLabel):
        name = DNSLabel(name)
    out = []
    for element in name.label:
        if len(element) > 63:
            raise DNSLabelError("Label component too long: %r" % element)
        out.append(struct.pack("!B",len(element)))
        out.append(element.lower())
    out.append(b"\x00")
    return b"".join(out)


def canonical_rdata(rdata,rtype):
    """
        Return the canonical wire format of an RDATA field (RFC 4034
        Section 6.2): fully expanded, with embedded domain names
        lowercased for the RR types listed in LOWERCASE_RDATA_TYPES.
        RDATA of any other type (TXT, unknown/opaque types, ...) is
        packed without case conversion.
    """
    buffer = _CanonicalBuffer(lowercase=(rtype in LOWERCASE_RDATA_TYPES))
    rdata.pack(buffer)
    return bytes(buffer.data)


def canonical_owner(owner,labels):
    """
        Return the canonical wire format of an RRset owner name, given
        the Labels field of the covering RRSIG. If the owner name has
        more labels than the Labels field it is a wildcard expansion
        and the original wildcard owner name is reconstructed
        (RFC 4034 Section 3.1.3, RFC 4035 Section 5.3.1).

        >>> canonical_owner("Bugs.X.Example.COM.",3)
        b'\\x01*\\x01x\\x07example\\x03com\\x00'
        >>> canonical_owner("WWW.Example.COM.",3)
        b'\\x03www\\x07example\\x03com\\x00'
    """
    if not isinstance(owner,DNSLabel):
        owner = DNSLabel(owner)
    if len(owner.label) > labels:
        owner = DNSLabel([b"*"] + list(owner.label[len(owner.label)-labels:]))
    return canonical_name(owner)


def canonical_rr(rr,ttl=None,owner=None):
    """
        Return the canonical wire format of a single RR (RFC 4034
        Section 6.2):

            owner | type | class | TTL | RDLENGTH | RDATA

        ttl overrides the RR TTL (pass the RRSIG Original TTL when
        building signed data); owner overrides the canonical owner
        (pass canonical_owner(rr.rname,rrsig.labels) for RRsets which
        may be wildcard expansions).
    """
    if ttl is None:
        ttl = rr.ttl
    if owner is None:
        owner = canonical_name(rr.rname)
    rdata = canonical_rdata(rr.rdata,rr.rtype)
    return owner + struct.pack("!HHIH",rr.rtype,rr.rclass,ttl,len(rdata)) + rdata


def rrsig_rdata(rrsig):
    """
        Return the RRSIG RDATA with the Signature field excluded, in
        canonical form (signer name lowercased and uncompressed), as
        used for the signed data (RFC 4034 Section 3.1.8.1).
    """
    buffer = _CanonicalBuffer(lowercase=True)
    buffer.pack("!HBBIIIH",rrsig.covered,rrsig.algorithm,rrsig.labels,
                           rrsig.orig_ttl,rrsig.sig_exp,rrsig.sig_inc,
                           rrsig.key_tag)
    buffer.encode_name(rrsig.name)
    return bytes(buffer.data)


def _validate_rrset(rrset,rrsig):
    if not rrset:
        raise RRsetError("Empty RRset")
    first = rrset[0]
    owner = canonical_name(first.rname)
    for rr in rrset:
        if rr.rtype != first.rtype:
            raise RRsetError("RRset contains mixed types: %d != %d" %
                                    (rr.rtype,first.rtype))
        if rr.rclass != first.rclass:
            raise RRsetError("RRset contains mixed classes: %d != %d" %
                                    (rr.rclass,first.rclass))
        if canonical_name(rr.rname) != owner:
            raise RRsetError("RRset contains mixed owners: %s != %s" %
                                    (rr.rname,first.rname))
    if first.rtype != rrsig.covered:
        raise RRsetError("RRSIG covers type %d but RRset has type %d" %
                                    (rrsig.covered,first.rtype))


def canonical_rrset(rrset,rrsig):
    """
        Return the sorted, deduplicated list of canonical RRs for an
        RRset covered by rrsig (RFC 4034 Sections 6.1-6.3):

            - owner reconstructed from the RRSIG Labels field
              (wildcard expansion) and lowercased
            - TTL replaced by the RRSIG Original TTL
            - RRs sorted by canonical RDATA (left-justified unsigned
              octet sequence) and duplicates removed

        The input RRs are validated (same owner/class/type, matching
        the RRSIG covered type) and are not modified.
    """
    _validate_rrset(rrset,rrsig)
    owner = canonical_owner(rrset[0].rname,rrsig.labels)
    seen = set()
    records = []
    for rr in rrset:
        rdata = canonical_rdata(rr.rdata,rr.rtype)
        if rdata in seen:
            continue
        seen.add(rdata)
        records.append((rdata,owner + struct.pack("!HHIH",
                            rr.rtype,rr.rclass,rrsig.orig_ttl,
                            len(rdata)) + rdata))
    # Sort by canonical RDATA; Python bytes comparison treats a missing
    # octet as smaller, matching RFC 4034 6.3
    records.sort(key=lambda r: r[0])
    return [r[1] for r in records]


def signing_input(rrset,rrsig):
    """
        Return the canonical RRset signed-data input (RFC 4034 Section
        3.1.8.1):

            RRSIG_RDATA | RR(1) | RR(2) ...

        where RRSIG_RDATA excludes the Signature field and the RRs are
        the sorted canonical RRs of the RRset. This is the exact octet
        sequence fed to (or verified against) the signature algorithm.
    """
    return rrsig_rdata(rrsig) + b"".join(canonical_rrset(rrset,rrsig))


if __name__ == '__main__':
    import binascii,doctest,sys
    from dnslib.dns import A,QTYPE,RR
    sys.exit(0 if doctest.testmod(optionflags=doctest.ELLIPSIS).failed == 0 else 1)
