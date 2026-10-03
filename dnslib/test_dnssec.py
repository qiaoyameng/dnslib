#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Test DNSSEC canonical RRset encoding (RFC 4034 section 6)

    All expected byte strings are hand-computed from RFC 4034 section 6.2:

        canonical RR = owner (lowercase, uncompressed)
                     | type | class | original TTL
                     | RDATA length | canonical RDATA

    Runs in unittest mode (also collected by pytest):

        python -m dnslib.test_dnssec
"""

from __future__ import print_function

import binascii,unittest

from dnslib.dns import A,CLASS,DNSError,MX,QTYPE,RD,RR,RRSIG,SOA,TXT
from dnslib.dnssec import (canonical_name,canonical_rdata,canonical_rr,
                           canonical_rrset,canonical_signed_data,
                           rrsig_rdata_prefix)

def hexs(s):
    """ Decode hex string (ignoring whitespace) """
    return binascii.unhexlify("".join(s.split()).encode("ascii"))

# Hand-computed canonical wire forms

# www.example.com. (lowercased, uncompressed)
NAME_WWW = "03777777 076578616d706c65 03636f6d 00"
# example.com.
NAME_EXAMPLE = "076578616d706c65 03636f6d 00"
# *.example.com.
NAME_WILDCARD = "012a 076578616d706c65 03636f6d 00"

# WWW.Example.COM. 3600 IN A 192.0.2.1
A_WWW = NAME_WWW + " 0001 0001 00000e10 0004 c0000201"
# Example.COM. 3600 IN MX 10 Mail.Example.COM.
MX_EXAMPLE = (NAME_EXAMPLE + " 000f 0001 00000e10 0014"
              " 000a 046d61696c 076578616d706c65 03636f6d 00")
# Example.COM. 3600 IN SOA Ns1.Example.COM. Hostmaster.Example.COM. 1 2 3 4 5
SOA_EXAMPLE = (NAME_EXAMPLE + " 0006 0001 00000e10 003d"
               " 036e7331 076578616d706c65 03636f6d 00"
               " 0a686f73746d6173746572 076578616d706c65 03636f6d 00"
               " 00000001 00000002 00000003 00000004 00000005")
# Example.COM. 60 IN TYPE65280 \# 5 0341624300 (RDATA case preserved)
UNKNOWN_EXAMPLE = NAME_EXAMPLE + " ff00 0001 0000003c 0005 0341624300"
# www.example.com. A 192.0.2.1 signed with labels=2 -> *.example.com.
A_WWW_WILDCARD = NAME_WILDCARD + " 0001 0001 00000e10 0004 c0000201"
# RRSIG(A,8,labels=2,orig_ttl=3600,exp=1690844160,inc=1685573632,0x1234,Example.COM.)
RRSIG_PREFIX = ("0001 08 02 00000e10 64c83c00 6477d000 1234"
                " 076578616d706c65 03636f6d 00")


class TestCanonicalName(unittest.TestCase):

    def test_lowercase_uncompressed(self):
        self.assertEqual(canonical_name("WWW.Example.COM."),
                         hexs(NAME_WWW))

    def test_root(self):
        self.assertEqual(canonical_name("."),b"\x00")


class TestCanonicalRR(unittest.TestCase):

    def test_a_record(self):
        rr = RR("WWW.Example.COM.",QTYPE.A,CLASS.IN,3600,A("192.0.2.1"))
        self.assertEqual(canonical_rr(rr),hexs(A_WWW))

    def test_mx_record(self):
        rr = RR("Example.COM.",QTYPE.MX,CLASS.IN,3600,
                MX("Mail.Example.COM.",10))
        self.assertEqual(canonical_rr(rr),hexs(MX_EXAMPLE))

    def test_soa_record(self):
        rr = RR("Example.COM.",QTYPE.SOA,CLASS.IN,3600,
                SOA("Ns1.Example.COM.","Hostmaster.Example.COM.",
                    (1,2,3,4,5)))
        self.assertEqual(canonical_rr(rr),hexs(SOA_EXAMPLE))

    def test_case_variants_identical(self):
        # Case variants of the same records must canonicalise identically
        for (a,b) in [
            (RR("WWW.Example.COM.",QTYPE.A,CLASS.IN,3600,A("192.0.2.1")),
             RR("www.example.com.",QTYPE.A,CLASS.IN,3600,A("192.0.2.1"))),
            (RR("Example.COM.",QTYPE.MX,CLASS.IN,3600,MX("Mail.Example.COM.",10)),
             RR("example.com.",QTYPE.MX,CLASS.IN,3600,MX("mail.example.com.",10))),
            (RR("Example.COM.",QTYPE.SOA,CLASS.IN,3600,
                SOA("Ns1.Example.COM.","Hostmaster.Example.COM.",(1,2,3,4,5))),
             RR("example.com.",QTYPE.SOA,CLASS.IN,3600,
                SOA("ns1.example.com.","hostmaster.example.com.",(1,2,3,4,5)))),
        ]:
            self.assertEqual(canonical_rr(a),canonical_rr(b))

    def test_txt_rdata_case_preserved(self):
        # TXT RDATA is opaque - must not be lowercased
        rr = RR("Example.COM.",QTYPE.TXT,CLASS.IN,3600,TXT(b"AbC"))
        self.assertEqual(canonical_rdata(rr.rtype,rr.rdata),
                         hexs("03416243"))

    def test_unknown_type_rdata_preserved(self):
        # Unknown type RDATA copied byte-for-byte (case preserved),
        # owner still lowercased
        rr = RR("Example.COM.",65280,CLASS.IN,60,RD(b"\x03AbC\x00"))
        self.assertEqual(canonical_rdata(rr.rtype,rr.rdata),
                         hexs("0341624300"))
        self.assertEqual(canonical_rr(rr),hexs(UNKNOWN_EXAMPLE))

    def test_wildcard_reconstruction(self):
        # labels=2 < 3 labels in www.example.com. -> *.example.com.
        rr = RR("www.example.com.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))
        sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,
                    "Example.COM.",b"")
        self.assertEqual(canonical_rr(rr,rrsig=sig),hexs(A_WWW_WILDCARD))
        # Same result passing orig_ttl/labels directly
        self.assertEqual(canonical_rr(rr,orig_ttl=3600,labels=2),
                         hexs(A_WWW_WILDCARD))

    def test_wildcard_labels_exceeding_owner(self):
        rr = RR("www.example.com.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))
        with self.assertRaises(DNSError):
            canonical_rr(rr,labels=4)

    def test_does_not_modify_input(self):
        rr = RR("WWW.Example.COM.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))
        canonical_rr(rr,orig_ttl=3600,labels=2)
        self.assertEqual(str(rr.rname),"WWW.Example.COM.")
        self.assertEqual(rr.ttl,60)


class TestCanonicalRRset(unittest.TestCase):

    def setUp(self):
        self.sig = RRSIG(QTYPE.A,8,3,3600,1690844160,1685573632,0x1234,
                         "Example.COM.",b"")

    def test_sorted_and_deduplicated(self):
        rrset = [RR("www.example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.2")),
                 RR("WWW.example.com",QTYPE.A,CLASS.IN,3600,A("192.0.2.1")),
                 RR("www.example.com",QTYPE.A,CLASS.IN,3600,A("192.0.2.1"))]
        # TTL normalised to original TTL (3600) so duplicate removed;
        # sorted by canonical RDATA (192.0.2.1 < 192.0.2.2)
        expected = (NAME_WWW + " 0001 0001 00000e10 0004 c0000201"
                    + NAME_WWW + " 0001 0001 00000e10 0004 c0000202")
        self.assertEqual(canonical_rrset(rrset,rrsig=self.sig),
                         hexs(expected))

    def test_rrset_wildcard(self):
        rrset = [RR("www.example.com.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))]
        sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,
                    "Example.COM.",b"")
        self.assertEqual(canonical_rrset(rrset,rrsig=sig),
                         hexs(A_WWW_WILDCARD))

    def test_rrset_unknown_type(self):
        rrset = [RR("Example.COM.",65280,CLASS.IN,60,RD(b"\x03AbC\x00"))]
        self.assertEqual(canonical_rrset(rrset),hexs(UNKNOWN_EXAMPLE))

    def test_empty_rrset(self):
        with self.assertRaises(DNSError):
            canonical_rrset([])

    def test_owner_mismatch(self):
        rrset = [RR("www.example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.1")),
                 RR("other.example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))]
        with self.assertRaises(DNSError):
            canonical_rrset(rrset)

    def test_class_mismatch(self):
        rrset = [RR("www.example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.1")),
                 RR("www.example.com",QTYPE.A,3,60,A("192.0.2.1"))]
        with self.assertRaises(DNSError):
            canonical_rrset(rrset)

    def test_type_mismatch(self):
        rrset = [RR("example.com",QTYPE.A,CLASS.IN,60,A("192.0.2.1")),
                 RR("example.com",QTYPE.MX,CLASS.IN,60,MX("mail.example.com.",10))]
        with self.assertRaises(DNSError):
            canonical_rrset(rrset)

    def test_does_not_modify_input(self):
        rrset = [RR("WWW.Example.COM.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))]
        sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,
                    "Example.COM.",b"")
        canonical_rrset(rrset,rrsig=sig)
        self.assertEqual(str(rrset[0].rname),"WWW.Example.COM.")
        self.assertEqual(rrset[0].ttl,60)


class TestSignedData(unittest.TestCase):

    def test_rrsig_rdata_prefix(self):
        sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,
                    "Example.COM.",b"\xde\xad")
        self.assertEqual(rrsig_rdata_prefix(sig),hexs(RRSIG_PREFIX))

    def test_signed_data(self):
        rrset = [RR("www.example.com.",QTYPE.A,CLASS.IN,60,A("192.0.2.1"))]
        sig = RRSIG(QTYPE.A,8,2,3600,1690844160,1685573632,0x1234,
                    "Example.COM.",b"\xde\xad")
        self.assertEqual(canonical_signed_data(rrset,sig),
                         hexs(RRSIG_PREFIX + " " + A_WWW_WILDCARD))

    def test_not_rrsig(self):
        with self.assertRaises(DNSError):
            rrsig_rdata_prefix(A("192.0.2.1"))


if __name__ == '__main__':
    unittest.main()
