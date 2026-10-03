#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Test RFC 4034 Section 6 canonical form encoding (dnslib.dnssec)

    All expected values are hand-computed byte strings (see comments)
    so the tests can be checked against RFC 4034 by hand.
"""

import struct
import unittest

from dnslib.dns import A, MX, QTYPE, RD, RR, RRSIG, SOA, TXT
from dnslib.dnssec import (RRsetError, canonical_name, canonical_owner,
                           canonical_rdata, canonical_rr, canonical_rrset,
                           rrsig_rdata, signing_input)

# Hand-written canonical wire-format names (lowercase, uncompressed)
WWW_EXAMPLE_COM       = b"\x03www\x07example\x03com\x00"
EXAMPLE_COM           = b"\x07example\x03com\x00"
MAIL_EXAMPLE_COM      = b"\x04mail\x07example\x03com\x00"
NS1_EXAMPLE_COM       = b"\x03ns1\x07example\x03com\x00"
HOSTMASTER_EXAMPLE_COM = b"\x0ahostmaster\x07example\x03com\x00"
STAR_X_EXAMPLE_COM    = b"\x01*\x01x\x07example\x03com\x00"

# RRSIG parameters used throughout (signature itself is never encoded)
SIG_EXP = 1800000000
SIG_INC = 1790000000
KEY_TAG = 12345
ORIG_TTL = 3600  # 0x00000e10


def make_sig(covered, labels, name="Example.COM."):
    return RRSIG(covered, 8, labels, ORIG_TTL, SIG_EXP, SIG_INC,
                 KEY_TAG, name, b"dummy-signature")


def expected_rrsig_rdata(covered, labels):
    # type covered | algorithm | labels | orig TTL | exp | inc | key tag
    # + canonical signer name (lowercase example.com.)
    return struct.pack("!HBBIIIH", covered, 8, labels, ORIG_TTL,
                       SIG_EXP, SIG_INC, KEY_TAG) + EXAMPLE_COM


class TestCanonicalName(unittest.TestCase):

    def test_lowercase(self):
        self.assertEqual(canonical_name("WWW.Example.COM."), WWW_EXAMPLE_COM)

    def test_root(self):
        self.assertEqual(canonical_name("."), b"\x00")

    def test_wildcard_reconstruction(self):
        # 4 labels in owner, RRSIG labels = 3 -> *. + rightmost 3 labels
        self.assertEqual(canonical_owner("Bugs.X.Example.COM.", 3),
                         STAR_X_EXAMPLE_COM)
        # Same label count -> no wildcard
        self.assertEqual(canonical_owner("WWW.Example.COM.", 3),
                         WWW_EXAMPLE_COM)


class TestCanonicalRR(unittest.TestCase):

    def test_a_record(self):
        rr = RR("WWW.Example.COM.", QTYPE.A, ttl=60, rdata=A("192.0.2.1"))
        # owner | A(1) IN(1) | TTL 3600 | RDLENGTH 4 | 192.0.2.1
        expected = (WWW_EXAMPLE_COM +
                    b"\x00\x01\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x04" + b"\xc0\x00\x02\x01")
        self.assertEqual(canonical_rrset([rr], make_sig(QTYPE.A, 3)),
                         [expected])

    def test_mx_record(self):
        rr = RR("Example.COM.", QTYPE.MX, ttl=60,
                rdata=MX("Mail.Example.COM.", 10))
        # preference 10 | mail.example.com. (RDLENGTH = 2 + 18 = 20)
        rdata = b"\x00\x0a" + MAIL_EXAMPLE_COM
        expected = (EXAMPLE_COM +
                    b"\x00\x0f\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x14" + rdata)
        self.assertEqual(canonical_rrset([rr], make_sig(QTYPE.MX, 2)),
                         [expected])

    def test_soa_record(self):
        times = (2026100201, 7200, 3600, 1209600, 3600)
        rr = RR("Example.COM.", QTYPE.SOA, ttl=60,
                rdata=SOA("Ns1.Example.COM.", "Hostmaster.Example.COM.",
                          times))
        # mname | rname | serial refresh retry expire minimum
        # (RDLENGTH = 17 + 24 + 20 = 61)
        rdata = (NS1_EXAMPLE_COM + HOSTMASTER_EXAMPLE_COM +
                 struct.pack("!IIIII", *times))
        expected = (EXAMPLE_COM +
                    b"\x00\x06\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x3d" + rdata)
        self.assertEqual(canonical_rrset([rr], make_sig(QTYPE.SOA, 2)),
                         [expected])

    def test_txt_not_lowercased(self):
        # TXT RDATA is opaque character-string data: case preserved
        rr = RR("Example.COM.", QTYPE.TXT, ttl=60, rdata=TXT(b"AbC.dEf"))
        self.assertEqual(canonical_rdata(rr.rdata, QTYPE.TXT),
                         b"\x07AbC.dEf")

    def test_unknown_type_not_lowercased(self):
        # Unknown (opaque) RDATA transferred without case conversion,
        # even though it contains uppercase ASCII bytes
        rr = RR("Example.COM.", 65280, ttl=60, rdata=RD(b"ABC\x00\xff"))
        self.assertEqual(canonical_rdata(rr.rdata, 65280), b"ABC\x00\xff")
        # owner | TYPE65280(0xff00) IN(1) | TTL 3600 | RDLENGTH 5 | raw
        expected = (EXAMPLE_COM +
                    b"\xff\x00\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x05" + b"ABC\x00\xff")
        self.assertEqual(canonical_rrset([rr], make_sig(65280, 2)),
                         [expected])


class TestCaseInsensitivity(unittest.TestCase):

    def test_case_variants_identical(self):
        # Owner/RDATA case and original TTL must not affect the output
        rrset1 = [RR("WWW.EXAMPLE.COM.", QTYPE.A, ttl=60,
                     rdata=A("192.0.2.1"))]
        rrset2 = [RR("www.example.com.", QTYPE.A, ttl=7200,
                     rdata=A("192.0.2.1"))]
        sig = make_sig(QTYPE.A, 3)
        self.assertEqual(signing_input(rrset1, sig),
                         signing_input(rrset2, sig))

    def test_mx_case_variants_identical(self):
        rrset1 = [RR("EXAMPLE.COM.", QTYPE.MX, ttl=60,
                     rdata=MX("MAIL.EXAMPLE.COM.", 10))]
        rrset2 = [RR("example.com.", QTYPE.MX, ttl=60,
                     rdata=MX("mail.example.com.", 10))]
        sig = make_sig(QTYPE.MX, 2)
        self.assertEqual(signing_input(rrset1, sig),
                         signing_input(rrset2, sig))


class TestSortAndDedup(unittest.TestCase):

    def test_sorted_by_canonical_rdata(self):
        rrset = [RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.10")),
                 RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.2"))]
        out = canonical_rrset(rrset, make_sig(QTYPE.A, 2))
        self.assertEqual(len(out), 2)
        # c0000202 < c000020a -> 192.0.2.2 record first
        self.assertTrue(out[0].endswith(b"\x00\x04\xc0\x00\x02\x02"))
        self.assertTrue(out[1].endswith(b"\x00\x04\xc0\x00\x02\x0a"))

    def test_duplicates_removed(self):
        # Same RDATA (TTL/case differences canonicalised away) -> one RR
        rrset = [RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.1")),
                 RR("EXAMPLE.COM.", QTYPE.A, ttl=7200, rdata=A("192.0.2.1"))]
        self.assertEqual(len(canonical_rrset(rrset, make_sig(QTYPE.A, 2))), 1)


class TestSigningInput(unittest.TestCase):

    def test_rrsig_rdata_excludes_signature(self):
        sig = make_sig(QTYPE.A, 3)
        expected = expected_rrsig_rdata(QTYPE.A, 3)
        self.assertEqual(rrsig_rdata(sig), expected)
        self.assertNotIn(b"dummy-signature", rrsig_rdata(sig))

    def test_unknown_type_fixed_bytes(self):
        rr = RR("Example.COM.", 65280, ttl=60, rdata=RD(b"ABC\x00\xff"))
        expected = (expected_rrsig_rdata(65280, 2) +
                    EXAMPLE_COM +
                    b"\xff\x00\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x05" + b"ABC\x00\xff")
        self.assertEqual(signing_input([rr], make_sig(65280, 2)), expected)

    def test_wildcard_fixed_bytes(self):
        # bugs.x.example.com. signed by RRSIG with labels=3 covers the
        # wildcard *.x.example.com.
        rr = RR("Bugs.X.Example.COM.", QTYPE.A, ttl=60,
                rdata=A("192.0.2.99"))
        expected = (expected_rrsig_rdata(QTYPE.A, 3) +
                    STAR_X_EXAMPLE_COM +
                    b"\x00\x01\x00\x01\x00\x00\x0e\x10" +
                    b"\x00\x04" + b"\xc0\x00\x02\x63")
        self.assertEqual(signing_input([rr], make_sig(QTYPE.A, 3)), expected)


class TestValidation(unittest.TestCase):

    def test_empty_rrset(self):
        self.assertRaises(RRsetError, canonical_rrset, [],
                          make_sig(QTYPE.A, 2))

    def test_mixed_type(self):
        rrset = [RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.1")),
                 RR("example.com.", QTYPE.TXT, ttl=60, rdata=TXT(b"x"))]
        self.assertRaises(RRsetError, canonical_rrset, rrset,
                          make_sig(QTYPE.A, 2))

    def test_mixed_class(self):
        rrset = [RR("example.com.", QTYPE.A, rclass=1, ttl=60,
                    rdata=A("192.0.2.1")),
                 RR("example.com.", QTYPE.A, rclass=3, ttl=60,
                    rdata=A("192.0.2.1"))]
        self.assertRaises(RRsetError, canonical_rrset, rrset,
                          make_sig(QTYPE.A, 2))

    def test_mixed_owner(self):
        rrset = [RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.1")),
                 RR("www.example.com.", QTYPE.A, ttl=60,
                    rdata=A("192.0.2.1"))]
        self.assertRaises(RRsetError, canonical_rrset, rrset,
                          make_sig(QTYPE.A, 2))

    def test_covered_mismatch(self):
        rrset = [RR("example.com.", QTYPE.A, ttl=60, rdata=A("192.0.2.1"))]
        self.assertRaises(RRsetError, canonical_rrset, rrset,
                          make_sig(QTYPE.MX, 2))


class TestNoMutation(unittest.TestCase):

    def test_input_objects_unchanged(self):
        rr = RR("WWW.Example.COM.", QTYPE.A, ttl=60, rdata=A("192.0.2.1"))
        mx = RR("Example.COM.", QTYPE.MX, ttl=60,
                rdata=MX("Mail.Example.COM.", 10))
        signing_input([rr], make_sig(QTYPE.A, 3))
        signing_input([mx], make_sig(QTYPE.MX, 2))
        self.assertEqual(rr.ttl, 60)
        self.assertEqual(str(rr.rname), "WWW.Example.COM.")
        self.assertEqual(str(mx.rdata.label), "Mail.Example.COM.")


if __name__ == "__main__":
    unittest.main()
