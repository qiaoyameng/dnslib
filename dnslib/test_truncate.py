from __future__ import print_function

import copy
import unittest

from dnslib.dns import DNSRecord, DNSError, EDNS0, QTYPE, RR


def response():
    query = DNSRecord.question("example.com")
    reply = query.reply()
    reply.add_answer(*RR.fromZone("example.com 60 IN A 192.0.2.1"))
    reply.add_answer(*RR.fromZone("example.com 60 IN A 192.0.2.2"))
    reply.add_auth(*RR.fromZone("example.com 60 IN NS ns.example.com"))
    reply.add_ar(*RR.fromZone("ns.example.com 60 IN A 192.0.2.10"))
    return reply


class TruncateTest(unittest.TestCase):

    def test_exact_boundary_needs_no_tc(self):
        reply = response()
        full = reply.pack()

        truncated = reply.truncate(len(full))
        packet = truncated.pack()

        self.assertEqual(packet, full)
        self.assertEqual(len(packet), len(full))
        self.assertEqual(truncated.header.tc, 0)

    def test_removes_sections_in_order_and_rebuilds_packet(self):
        reply = response()

        truncated = reply.truncate(93)
        packet = truncated.pack()

        self.assertEqual(len(packet), 78)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.header.a, 2)
        self.assertEqual(truncated.header.auth, 1)
        self.assertEqual(truncated.header.ar, 0)
        self.assertEqual(DNSRecord.parse(packet), truncated)

        truncated = reply.truncate(78)
        packet = truncated.pack()

        self.assertEqual(len(packet), 78)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.header.a, 2)
        self.assertEqual(truncated.header.auth, 1)
        self.assertEqual(truncated.header.ar, 0)
        self.assertEqual(DNSRecord.parse(packet), truncated)

        truncated = reply.truncate(62)
        packet = truncated.pack()

        self.assertEqual(len(packet), 61)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.header.a, 2)
        self.assertEqual(truncated.header.auth, 0)
        self.assertEqual(truncated.header.ar, 0)
        self.assertEqual(DNSRecord.parse(packet), truncated)

    def test_noncontiguous_rrset_removal_recomputes_compression(self):
        query = DNSRecord.question("question.example")
        reply = query.reply()
        reply.add_answer(*RR.fromZone("z.test. 60 IN A 192.0.2.1"))
        reply.add_answer(*RR.fromZone("b.test. 60 IN CNAME z.test."))
        reply.add_answer(*RR.fromZone("z.test. 60 IN A 192.0.2.2"))

        truncated = reply.truncate(len(reply.pack()) - 1)
        packet = truncated.pack()

        self.assertEqual(len(packet), 56)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(
            [(str(rr.rname), QTYPE[rr.rtype]) for rr in truncated.rr],
            [("b.test.", "CNAME")])
        self.assertEqual(packet[-4:], b"\x01z\xc0\x24")
        self.assertEqual(DNSRecord.parse(packet), truncated)

    def test_opt_is_kept_separate_and_announces_responder_limit(self):
        reply = response()
        reply.add_ar(EDNS0(flags="do", udp_len=4096))

        truncated = reply.truncate(89)
        packet = truncated.pack()

        self.assertEqual(len(packet), 89)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.header.a, 2)
        self.assertEqual(truncated.header.auth, 1)
        self.assertEqual(truncated.header.ar, 1)
        self.assertEqual(truncated.ar[0].rtype, QTYPE.OPT)
        self.assertEqual(truncated.ar[0].rclass, 512)
        self.assertEqual(truncated.ar[0].edns_len, 512)
        self.assertEqual(DNSRecord.parse(packet), truncated)

        original_opt = reply.ar[-1]
        self.assertEqual(original_opt.rclass, 4096)
        self.assertEqual(original_opt.edns_len, 4096)

    def test_opt_declared_size_is_default_budget(self):
        reply = response()
        reply.add_ar(EDNS0(flags="do", udp_len=4096))
        full = reply.pack()

        truncated = reply.truncate()

        self.assertEqual(truncated.pack(), full)
        self.assertEqual(truncated.header.tc, 0)
        self.assertEqual(truncated.ar[-1].rclass, 4096)

    def test_opt_is_dropped_whole_when_it_does_not_fit(self):
        query = DNSRecord.question("example.com")
        reply = query.reply()
        reply.add_answer(*RR.fromZone("example.com 60 IN TXT %s" % ("x" * 64)))
        reply.add_ar(EDNS0(udp_len=4096))

        truncated = reply.truncate(110)
        packet = truncated.pack()

        self.assertLessEqual(len(packet), 110)
        self.assertEqual(len(packet), 106)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.header.ar, 0)
        self.assertEqual(DNSRecord.parse(packet), truncated)

    def test_header_and_question_must_fit(self):
        query = DNSRecord.question("a-very-long-label-that-does-not-fit.example.com")
        reply = query.reply()
        reply.add_answer(*RR.fromZone(
            "a-very-long-label-that-does-not-fit.example.com 60 IN A "
            "192.0.2.1"))

        with self.assertRaises(DNSError):
            reply.truncate(20)

    def test_source_record_is_unchanged(self):
        reply = response()
        reply.add_ar(EDNS0(flags="do", udp_len=4096))
        snapshot = copy.deepcopy(reply)

        reply.truncate(77)

        self.assertEqual(reply, snapshot)
        self.assertEqual(reply.pack(), snapshot.pack())
        self.assertEqual(reply.ar[-1].rclass, 4096)
        self.assertEqual(reply.ar[-1].edns_len, 4096)


if __name__ == "__main__":
    unittest.main()
