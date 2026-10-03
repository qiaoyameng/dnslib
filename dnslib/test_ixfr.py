# -*- coding: utf-8 -*-

"""
    Tests for dnslib.ixfr (applying IXFR/AXFR responses to in-memory zones)

    Everything runs in memory - no DNS server is needed.  Zones and
    transfer responses are built from zone-file text via RR.fromZone and
    fed through dnslib.ixfr.apply_update / ZoneUpdater.

    Run directly (unittest) or via pytest.
"""

from __future__ import print_function

import unittest

from dnslib.dns import QTYPE,RR
from dnslib.ixfr import IXFRError,ZoneUpdater,apply_update, \
                        serial_add,serial_lt,serial_gt,serial_le,serial_ge

def clean(text):
    """ Strip per-line indentation so zone text can be indented in source """
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())

def zone_text(serial,extra=""):
    return clean("""
        example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. %d 3600 600 86400 60
        example.com. 300 IN NS ns1.example.com.
        ns1.example.com. 300 IN A 192.0.2.53
    """ % serial + "\n" + extra)

def make_zone(serial,extra=""):
    return RR.fromZone(zone_text(serial,extra))

def soa(serial):
    return RR.fromZone(
        "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. "
        "%d 3600 600 86400 60" % serial)[0]

def delta(old,new,deletes=(),adds=()):
    """ One IXFR delta: SOA(old) <deletes> SOA(new) <adds> """
    return [soa(old)] + list(deletes) + [soa(new)] + list(adds)

def ixfr_response(current,target,deltas):
    """ Full IXFR response: SOA(target) <deltas...> SOA(target) """
    assert deltas[0][0] == current and deltas[-1][1] == target
    rrs = [soa(target)]
    for old,new,deletes,adds in deltas:
        rrs.extend(delta(old,new,deletes,adds))
    rrs.append(soa(target))
    return rrs

def a(name,ip):
    return RR.fromZone("%s 300 IN A %s" % (name,ip))[0]

def txt(name,value):
    return RR.fromZone('%s 300 IN TXT "%s"' % (name,value))[0]

def names(zone):
    return sorted("%s %s" % (rr.rname,QTYPE[rr.rtype]) for rr in zone)

def zone_serial(zone):
    return [rr.rdata.times[0] for rr in zone if rr.rtype == QTYPE.SOA][0]


class TestSerialArithmetic(unittest.TestCase):

    def test_basic(self):
        self.assertTrue(serial_lt(1,2))
        self.assertTrue(serial_gt(2,1))
        self.assertTrue(serial_le(1,1))
        self.assertTrue(serial_ge(1,1))
        self.assertFalse(serial_lt(2,2))

    def test_wraparound(self):
        # RFC 1982: comparison across the 2^32 boundary
        self.assertTrue(serial_lt(4294967294,4294967295))
        self.assertTrue(serial_lt(4294967295,0))
        self.assertTrue(serial_lt(4294967295,1))
        self.assertTrue(serial_gt(1,4294967295))
        self.assertEqual(serial_add(4294967295,1),0)
        self.assertEqual(serial_add(4294967295,2),1)
        # 2^31 away is the undefined boundary - not less either way
        self.assertFalse(serial_lt(0,1 << 31))
        self.assertFalse(serial_lt(1 << 31,0))

    def test_invalid(self):
        self.assertRaises(IXFRError,serial_lt,-1,0)
        self.assertRaises(IXFRError,serial_lt,0,1 << 32)


class TestIXFR(unittest.TestCase):

    def test_single_delta(self):
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1")
        response = ixfr_response(100,101,[
            (100,101,[a("www.example.com.","192.0.2.1")],
                     [a("www.example.com.","192.0.2.2")]),
        ])
        new_zone = apply_update(zone,response)
        self.assertEqual(zone_serial(new_zone),101)
        self.assertIn("www.example.com. A",names(new_zone))
        self.assertEqual([str(rr.rdata) for rr in new_zone
                          if rr.rtype == QTYPE.A and
                             str(rr.rname) == "www.example.com."],["192.0.2.2"])
        # original zone untouched
        self.assertEqual(zone_serial(zone),100)

    def test_chained_deltas_single_response(self):
        # Multiple increments strung together in one response
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1")
        response = ixfr_response(100,102,[
            (100,101,[a("www.example.com.","192.0.2.1")],
                     [a("www.example.com.","192.0.2.2")]),
            (101,102,[],[txt("www.example.com.","hello")]),
        ])
        new_zone = apply_update(zone,response)
        self.assertEqual(zone_serial(new_zone),102)
        self.assertIn("www.example.com. TXT",names(new_zone))
        self.assertEqual(len([rr for rr in new_zone
                              if str(rr.rname) == "www.example.com." and
                                 rr.rtype == QTYPE.A]),1)

    def test_serial_wraparound(self):
        # Chain crosses the 2^32 boundary: 4294967294 -> 4294967295 -> 1
        zone = make_zone(4294967294,"old.example.com. 300 IN A 192.0.2.1")
        response = ixfr_response(4294967294,1,[
            (4294967294,4294967295,[a("old.example.com.","192.0.2.1")],[]),
            (4294967295,1,[],[a("new.example.com.","192.0.2.2")]),
        ])
        new_zone = apply_update(zone,response)
        self.assertEqual(zone_serial(new_zone),1)
        self.assertIn("new.example.com. A",names(new_zone))
        self.assertNotIn("old.example.com. A",names(new_zone))

    def test_iterator_input(self):
        # Records arriving one at a time (generator, not a list)
        zone = make_zone(7)
        response = ixfr_response(7,8,[(7,8,[],[a("www.example.com.","192.0.2.9")])])
        new_zone = apply_update(zone,iter(response))
        self.assertEqual(zone_serial(new_zone),8)
        self.assertIn("www.example.com. A",names(new_zone))

    def test_streaming_feed(self):
        zone = make_zone(7)
        response = ixfr_response(7,8,[(7,8,[],[a("www.example.com.","192.0.2.9")])])
        updater = ZoneUpdater(zone)
        for rr in response:
            updater.feed(rr)
        new_zone = updater.finish()
        self.assertEqual(zone_serial(new_zone),8)

    def test_up_to_date(self):
        # Single SOA with our serial: nothing to do
        zone = make_zone(100)
        new_zone = apply_update(zone,[soa(100)])
        self.assertEqual(names(new_zone),names(zone))

    def test_duplicate_records(self):
        # Zone legitimately holds two identical RRs; a delete removes
        # exactly one instance
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1\n"
                             "www.example.com. 300 IN A 192.0.2.1")
        response = ixfr_response(100,101,[
            (100,101,[a("www.example.com.","192.0.2.1")],[]),
        ])
        new_zone = apply_update(zone,response)
        remaining = [rr for rr in new_zone
                     if str(rr.rname) == "www.example.com." and
                        rr.rtype == QTYPE.A]
        self.assertEqual(len(remaining),1)

    def test_add_duplicate_rejected(self):
        # Adding a record that already exists is a validation failure
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1")
        response = ixfr_response(100,101,[
            (100,101,[],[a("www.example.com.","192.0.2.1")]),
        ])
        self.assertRaises(IXFRError,apply_update,zone,response)
        self.assertEqual(zone_serial(zone),100)

    def test_missing_delete_target(self):
        # Deleting a record that is not in the zone must fail
        zone = make_zone(100)
        response = ixfr_response(100,101,[
            (100,101,[a("ghost.example.com.","192.0.2.99")],[]),
        ])
        self.assertRaises(IXFRError,apply_update,zone,response)
        # zone unmodified
        self.assertEqual(zone_serial(zone),100)
        self.assertEqual(len(zone),3)

    def test_truncated_response(self):
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1")
        full = ixfr_response(100,101,[
            (100,101,[a("www.example.com.","192.0.2.1")],[]),
        ])
        before = names(zone)
        for cut in range(len(full)):
            self.assertRaises(IXFRError,apply_update,zone,full[:cut])
        self.assertEqual(names(zone),before)

    def test_broken_version_chain(self):
        zone = make_zone(100)
        # First delta starts at 99, not our current serial 100
        response = ixfr_response(99,101,[(99,101,[],[])])
        self.assertRaises(IXFRError,apply_update,zone,response)
        # Chain breaks between deltas (100->101 then 103->104)
        response = [soa(104)] + delta(100,101) + delta(103,104) + [soa(104)]
        self.assertRaises(IXFRError,apply_update,zone,response)
        # Last delta does not reach the target serial
        response = [soa(105)] + delta(100,101) + [soa(105)]
        self.assertRaises(IXFRError,apply_update,zone,response)
        self.assertEqual(zone_serial(zone),100)

    def test_non_forward_delta_rejected(self):
        # Delta whose "new" serial does not follow the old one (RFC 1982)
        zone = make_zone(100)
        response = [soa(99)] + delta(100,99) + [soa(99)]
        self.assertRaises(IXFRError,apply_update,zone,response)

    def test_trailing_garbage(self):
        zone = make_zone(100)
        response = ixfr_response(100,101,[(100,101,[],[])])
        response.append(a("extra.example.com.","192.0.2.1"))
        self.assertRaises(IXFRError,apply_update,zone,response)

    def test_not_starting_with_soa(self):
        zone = make_zone(100)
        self.assertRaises(IXFRError,apply_update,zone,
                          [a("www.example.com.","192.0.2.1")])

    def test_failure_recovery(self):
        # A failed transfer leaves the zone object valid and reusable
        zone = make_zone(100,"www.example.com. 300 IN A 192.0.2.1")
        before = names(zone)
        bad = ixfr_response(100,101,[
            (100,101,[a("ghost.example.com.","192.0.2.99")],[]),
        ])
        self.assertRaises(IXFRError,apply_update,zone,bad)
        self.assertEqual(names(zone),before)
        # A subsequent valid transfer on the same zone succeeds
        good = ixfr_response(100,101,[
            (100,101,[a("www.example.com.","192.0.2.1")],
                     [a("www.example.com.","192.0.2.2")]),
        ])
        new_zone = apply_update(zone,good)
        self.assertEqual(zone_serial(new_zone),101)
        self.assertEqual(names(zone),before)


class TestAXFRFallback(unittest.TestCase):

    def test_full_replacement(self):
        # Server falls back to AXFR: SOA <all records> SOA
        zone = make_zone(100,"stale.example.com. 300 IN A 192.0.2.1")
        response = RR.fromZone(clean("""
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
            example.com. 300 IN NS ns2.example.com.
            ns2.example.com. 300 IN A 192.0.2.54
            fresh.example.com. 300 IN A 192.0.2.2
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
        """))
        new_zone = apply_update(zone,response)
        self.assertEqual(zone_serial(new_zone),200)
        # Complete replacement: stale record gone, new content present
        self.assertNotIn("stale.example.com. A",names(new_zone))
        self.assertNotIn("ns1.example.com. A",names(new_zone))
        self.assertIn("fresh.example.com. A",names(new_zone))
        self.assertIn("ns2.example.com. A",names(new_zone))

    def test_axfr_not_mistaken_for_delete_set(self):
        # The AXFR body records do not exist in the current zone; if they
        # were (mis)treated as a deletion set this would have to fail
        zone = make_zone(100)
        response = RR.fromZone(clean("""
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
            unseen.example.com. 300 IN A 192.0.2.77
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
        """))
        new_zone = apply_update(zone,response)
        self.assertIn("unseen.example.com. A",names(new_zone))

    def test_axfr_truncated(self):
        zone = make_zone(100)
        response = RR.fromZone(clean("""
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
            fresh.example.com. 300 IN A 192.0.2.2
        """))
        self.assertRaises(IXFRError,apply_update,zone,response)
        self.assertEqual(zone_serial(zone),100)

    def test_axfr_serial_mismatch(self):
        zone = make_zone(100)
        response = RR.fromZone(clean("""
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 200 3600 600 86400 60
            fresh.example.com. 300 IN A 192.0.2.2
            example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 201 3600 600 86400 60
        """))
        self.assertRaises(IXFRError,apply_update,zone,response)


if __name__ == '__main__':
    unittest.main()
