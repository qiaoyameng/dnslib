#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Test EDNS Client Subnet (ECS) option support (RFC 7871)

    Covers structured encoding/parsing of the ECS option (IPv4, IPv6,
    zero-length and non-octet-aligned prefixes), validation of malformed
    wire data, request/response correspondence checks, cache scope
    handling, duplicate ECS rejection and round-tripping of unknown
    EDNS options. No real DNS queries are performed.
"""

from __future__ import print_function

import struct,unittest

from dnslib.dns import DNSRecord,DNSQuestion,DNSError,EDNS0,EDNSOption, \
                       ECSOption,ECSNetwork,QTYPE,check_ecs_response

def wire(family,srclen,scopelen,addr=b""):
    return struct.pack("!HBB",family,srclen,scopelen) + addr

class TestECSEncode(unittest.TestCase):

    def test_zero_prefix_v4(self):
        # /0 - no address octets on the wire
        opt = ECSOption("192.0.2.130",0)
        self.assertEqual(opt.family,1)
        self.assertEqual(opt.data,wire(1,0,0))
        self.assertEqual(opt.address,"0.0.0.0")
        self.assertEqual(str(opt.source_network),"0.0.0.0/0")

    def test_zero_prefix_v6(self):
        opt = ECSOption("2001:db8::1",0)
        self.assertEqual(opt.family,2)
        self.assertEqual(opt.data,wire(2,0,0))
        self.assertEqual(opt.address,"::")
        self.assertEqual(str(opt.source_network),"::/0")

    def test_prefix_17(self):
        # /17 - 3 address octets, bits beyond the prefix masked off
        opt = ECSOption("192.0.2.128",17)
        self.assertEqual(opt.data,wire(1,17,0,b"\xc0\x00\x00"))
        self.assertEqual(opt.address,"192.0.0.0")
        self.assertEqual(str(opt.source_network),"192.0.0.0/17")

    def test_prefix_57_v6(self):
        # /57 - 8 address octets, only the top bit of the last octet kept
        opt = ECSOption("2001:db8:abcd:1234:5678:9abc:def0:1234",57)
        self.assertEqual(opt.data,
                wire(2,57,0,b"\x20\x01\x0d\xb8\xab\xcd\x12\x00"))
        self.assertEqual(opt.address,"2001:db8:abcd:1200::")
        self.assertEqual(str(opt.source_network),"2001:db8:abcd:1200::/57")

    def test_full_prefix_v4(self):
        opt = ECSOption("192.0.2.130",32)
        self.assertEqual(opt.data,wire(1,32,0,b"\xc0\x00\x02\x82"))
        self.assertEqual(opt.address,"192.0.2.130")

    def test_full_prefix_v6(self):
        opt = ECSOption("2001:db8::1")
        self.assertEqual(opt.srclen,128)
        self.assertEqual(len(opt.data),4 + 16)
        self.assertEqual(opt.address,"2001:db8::1")

    def test_default_prefix_is_full_address(self):
        self.assertEqual(ECSOption("192.0.2.1").srclen,32)
        self.assertEqual(ECSOption("2001:db8::1").srclen,128)

    def test_scope_encoded(self):
        opt = ECSOption("192.0.2.0",24,20)
        self.assertEqual(opt.data,wire(1,24,20,b"\xc0\x00\x02"))

class TestECSParse(unittest.TestCase):

    def roundtrip(self,data):
        opt = ECSOption.from_data(data)
        self.assertEqual(opt.data,data)
        return opt

    def test_parse_zero_prefix(self):
        opt = self.roundtrip(wire(1,0,0))
        self.assertEqual((opt.family,opt.srclen,opt.scopelen),(1,0,0))
        opt = self.roundtrip(wire(2,0,0))
        self.assertEqual((opt.family,opt.srclen,opt.scopelen),(2,0,0))

    def test_parse_prefix_17(self):
        opt = self.roundtrip(wire(1,17,0,b"\xc0\x00\x00"))
        self.assertEqual(opt.address,"192.0.0.0")
        self.assertEqual(opt.srclen,17)

    def test_parse_prefix_57(self):
        opt = self.roundtrip(wire(2,57,0,b"\x20\x01\x0d\xb8\xab\xcd\x12\x80"))
        self.assertEqual(opt.address,"2001:db8:abcd:1280::")
        self.assertEqual(opt.srclen,57)

    def test_parse_full_prefix(self):
        opt = self.roundtrip(wire(1,32,0,b"\xc0\x00\x02\x82"))
        self.assertEqual(opt.address,"192.0.2.130")
        opt = self.roundtrip(wire(2,128,0,b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"))
        self.assertEqual(opt.address,"2001:db8::1")

    def test_parse_scope(self):
        opt = self.roundtrip(wire(1,24,20,b"\xc0\x00\x02"))
        self.assertEqual(opt.scopelen,20)
        self.assertEqual(str(opt.scope_network),"192.0.0.0/20")

    def test_truncated_header(self):
        self.assertRaises(DNSError,ECSOption.from_data,b"\x00\x01\x18")

    def test_unknown_family(self):
        self.assertRaises(DNSError,ECSOption.from_data,wire(3,0,0))
        self.assertRaises(DNSError,ECSOption.from_data,wire(0,0,0))

    def test_prefix_too_long(self):
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(1,33,0,b"\x00" * 5))
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(2,0,129))

    def test_address_length_mismatch(self):
        # /17 needs exactly 3 octets
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(1,17,0,b"\xc0\x00"))
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(1,17,0,b"\xc0\x00\x00\x00"))
        # /0 must not carry any address octets
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(1,0,0,b"\xc0"))
        # /57 needs exactly 8 octets
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(2,57,0,b"\x20\x01\x0d\xb8\xab\xcd\x12"))

    def test_nonzero_trailing_bits(self):
        # /17 - low 7 bits of the third octet must be zero
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(1,17,0,b"\xc0\x00\x01"))
        # /57 - low 7 bits of the eighth octet must be zero
        self.assertRaises(DNSError,ECSOption.from_data,
                wire(2,57,0,b"\x20\x01\x0d\xb8\xab\xcd\x12\x01"))
        # /24 - whole octets, no trailing bits to check
        self.roundtrip(wire(1,24,0,b"\xc0\x00\x02"))

    def test_constructor_range_checks(self):
        self.assertRaises(ValueError,ECSOption,"192.0.2.1",33)
        self.assertRaises(ValueError,ECSOption,"2001:db8::1",0,129)
        self.assertRaises(ValueError,ECSOption,"192.0.2.1",-1)
        self.assertRaises(ValueError,ECSOption,"not-an-address")

class TestECSResponseCheck(unittest.TestCase):

    def test_matching_response_returns_scope_network(self):
        query = ECSOption("192.0.2.130",24)
        response = ECSOption("192.0.2.0",24,20)
        network = check_ecs_response(query,response)
        self.assertEqual(network,ECSNetwork(
                ECSOption("192.0.2.0")._packed,20))
        self.assertEqual(str(network),"192.0.0.0/20")

    def test_scope_network_partitions_cache(self):
        query = ECSOption("192.0.2.130",24)
        network = check_ecs_response(query,ECSOption("192.0.2.0",24,20))
        # Clients inside the declared scope can reuse the cached answer
        self.assertTrue(network.contains("192.0.2.77"))
        self.assertTrue(network.contains("192.0.0.1"))
        # ...clients outside it cannot - the answer is not authoritative
        # for arbitrary queries
        self.assertFalse(network.contains("192.0.16.1"))
        self.assertFalse(network.contains("198.51.100.1"))
        self.assertFalse(network.contains("2001:db8::1"))

    def test_zero_scope_not_a_wildcard(self):
        # Scope /0 is specific to the querying client (RFC 7871 section
        # 7.2.1) - the answer must not be cached or used to answer
        # other queries, so no cache network is returned
        query = ECSOption("192.0.2.130",24)
        self.assertIsNone(check_ecs_response(query,ECSOption("192.0.2.0",24,0)))

    def test_source_prefix_mismatch(self):
        query = ECSOption("192.0.2.0",24)
        # Different source prefix length
        self.assertRaises(DNSError,check_ecs_response,
                query,ECSOption("192.0.2.0",16,16))
        # Different client prefix
        self.assertRaises(DNSError,check_ecs_response,
                query,ECSOption("192.0.3.0",24,24))
        # Different address family
        self.assertRaises(DNSError,check_ecs_response,
                query,ECSOption("2001:db8::",24,24))

    def test_response_to_other_query_rejected(self):
        # A response to a /0 query must not answer a /24 query (and the
        # other way round)
        self.assertRaises(DNSError,check_ecs_response,
                ECSOption("192.0.2.130",0),ECSOption("192.0.2.0",24,24))
        self.assertRaises(DNSError,check_ecs_response,
                ECSOption("192.0.2.130",24),ECSOption("0.0.0.0",0,0))

    def test_scope_broader_than_source(self):
        # A scope shorter than the source prefix declares the answer
        # valid for a broader range of clients - but still only for
        # clients inside the scope network, not arbitrary queries
        query = ECSOption("192.0.2.130",24)
        network = check_ecs_response(query,ECSOption("192.0.2.0",24,16))
        self.assertEqual(str(network),"192.0.0.0/16")
        self.assertTrue(network.contains("192.0.255.1"))
        self.assertFalse(network.contains("192.1.0.1"))

    def test_v6_response_check(self):
        query = ECSOption("2001:db8:abcd:1234::1",57)
        response = ECSOption("2001:db8:abcd:1200::",57,48)
        network = check_ecs_response(query,response)
        self.assertEqual(str(network),"2001:db8:abcd::/48")
        self.assertTrue(network.contains("2001:db8:abcd:ffff::1"))
        self.assertFalse(network.contains("2001:db8:abce::1"))

class TestECSPacket(unittest.TestCase):

    def make_packet(self,opts):
        record = DNSRecord(q=DNSQuestion("example.com",QTYPE.A))
        record.add_ar(EDNS0(flags="do",udp_len=4096,opts=opts))
        return record

    def get_options(self,record):
        ar = record.ar[-1]
        self.assertEqual(ar.rtype,QTYPE.OPT)
        return ar.rdata

    def test_packet_roundtrip(self):
        opts = [ECSOption("192.0.2.130",24),EDNSOption(65001,b"\xde\xad\xbe\xef")]
        packet = self.make_packet(opts).pack()
        parsed = DNSRecord.parse(packet)
        parsed_opts = self.get_options(parsed)
        # ECS option parsed into structured form
        self.assertIsInstance(parsed_opts[0],ECSOption)
        self.assertEqual(parsed_opts[0],opts[0])
        self.assertEqual(parsed_opts[0].address,"192.0.2.0")
        # Unknown option round-trips unchanged
        self.assertEqual(type(parsed_opts[1]),EDNSOption)
        self.assertEqual(parsed_opts[1].code,65001)
        self.assertEqual(parsed_opts[1].data,b"\xde\xad\xbe\xef")
        # Whole packet repacks identically
        self.assertEqual(parsed.pack(),packet)

    def test_zero_prefix_packet_roundtrip(self):
        packet = self.make_packet([ECSOption("2001:db8::1",0)]).pack()
        parsed = DNSRecord.parse(packet)
        opt = self.get_options(parsed)[0]
        self.assertIsInstance(opt,ECSOption)
        self.assertEqual((opt.family,opt.srclen),(2,0))
        self.assertEqual(parsed.pack(),packet)

    def test_duplicate_ecs_rejected(self):
        packet = self.make_packet(
                [ECSOption("192.0.2.0",24),ECSOption("198.51.100.0",24)]).pack()
        self.assertRaises(DNSError,DNSRecord.parse,packet)

    def test_malformed_ecs_rejected(self):
        # Non-zero trailing bits in a /17 ECS option inside a full packet
        bad = EDNSOption(8,wire(1,17,0,b"\xc0\x00\x01"))
        packet = self.make_packet([bad]).pack()
        self.assertRaises(DNSError,DNSRecord.parse,packet)

    def test_zone_output(self):
        opt = ECSOption("192.0.2.130",24,20)
        self.assertEqual(opt.toZone(),"; CLIENT-SUBNET: 192.0.2.0/24/20")
        self.assertIn("CLIENT-SUBNET",self.make_packet([opt]).toZone())

if __name__ == '__main__':
    unittest.main()
