#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import unittest

from io import StringIO

from dnslib import QTYPE, RR
from dnslib.dns import TXT, ZoneParseError


class ZoneParserTest(unittest.TestCase):

    def test_generate_forward_zone(self):
        zone = '''$ORIGIN example.com.
$TTL 60
$GENERATE 1-3 host-$ 1h IN A 10.0.0.$
$GENERATE 4-5/1 host-${,2,d} 30 IN A 10.1.0.${-1,2,d}
www A 10.0.0.10
$GENERATE 1-2 cname-$ IN CNAME host-$.example.com.
'''
        records = RR.fromZone(zone)

        self.assertEqual([str(rr.rname) for rr in records[:3]], [
            'host-1.example.com.',
            'host-2.example.com.',
            'host-3.example.com.',
        ])
        self.assertEqual([rr.ttl for rr in records[:3]], [3600, 3600, 3600])
        self.assertEqual([str(rr.rdata) for rr in records[:3]], [
            '10.0.0.1', '10.0.0.2', '10.0.0.3',
        ])
        self.assertEqual(str(records[3].rname), 'host-04.example.com.')
        self.assertEqual(records[3].ttl, 30)
        self.assertEqual(str(records[3].rdata), '10.1.0.3')
        self.assertEqual(str(records[5].rname), 'www.example.com.')
        self.assertEqual(records[5].ttl, 60)
        self.assertEqual(str(records[6].rdata), 'host-1.example.com.')

    def test_generate_reverse_zone_and_bases(self):
        zone = '''$ORIGIN 168.192.in-addr.arpa.
$GENERATE 0-2 ${0,2,n} PTR host-$
$GENERATE 010-010 oct A 10.0.0.$
$GENERATE 0xa-0xc/0x2 hex-${0,3,X} A 10.0.0.$
$GENERATE 1-1 nib-${0,2,N} TXT "nibble ${0,2,n}"
'''
        records = RR.fromZone(zone)

        self.assertEqual([str(rr.rname) for rr in records[:3]], [
            '0.0.168.192.in-addr.arpa.',
            '1.0.168.192.in-addr.arpa.',
            '2.0.168.192.in-addr.arpa.',
        ])
        self.assertEqual(str(records[3].rname), 'oct.168.192.in-addr.arpa.')
        self.assertEqual(str(records[3].rdata), '10.0.0.8')
        self.assertEqual(str(records[4].rname), 'hex-00A.168.192.in-addr.arpa.')
        self.assertEqual(str(records[4].rdata), '10.0.0.10')
        self.assertEqual(str(records[5].rname), 'hex-00C.168.192.in-addr.arpa.')
        self.assertEqual(str(records[5].rdata), '10.0.0.12')
        self.assertEqual(str(records[6].rname), 'nib-1.0.168.192.in-addr.arpa.')
        self.assertEqual(records[6].rdata.data, [b'nibble 1.0'])

    def test_generate_escapes_and_quoted_text(self):
        records = RR.fromZone(
            '$GENERATE 1-1 txt TXT "value $; cost \\$${-1,2,d}" keep\\;this\n')

        self.assertEqual(records[0].rtype, QTYPE.TXT)
        self.assertEqual(records[0].rdata.data, [
            b'value 1; cost $00',
            b'keep;this',
        ])

    def test_escaped_dollar_is_literal_in_owner(self):
        records = RR.fromZone('$GENERATE 1-1 cost-\\$-$ A 192.0.2.$\n')

        self.assertEqual(str(records[0].rname), 'cost-$-1.')

    def test_generated_records_mix_with_continuation_and_ttl(self):
        zone = '''$ORIGIN example.org.
$TTL 120
$GENERATE 1-2 a-$ A 192.0.2.$
    TXT "same owner"
$TTL 240
ordinary A 192.0.2.10
'''
        records = RR.fromZone(zone)

        self.assertEqual(len(records), 4)
        self.assertEqual(str(records[1].rname), 'a-2.example.org.')
        self.assertEqual(records[1].ttl, 120)
        self.assertEqual(str(records[2].rname), 'a-2.example.org.')
        self.assertEqual(records[2].rtype, QTYPE.TXT)
        self.assertEqual(records[2].ttl, 120)

    def test_errors_include_directive_line(self):
        zone = '''$TTL 60
$ORIGIN example.com.
; comment
$GENERATE 1-0 bad A 192.0.2.$
'''
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone(zone)
        self.assertIn('line 4', str(ctx.exception))

        zone = '''$TTL 60
$ORIGIN example.com.
; comment
$GENERATE 1-2 bad A 192.0.2.${
'''
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone(zone)
        self.assertIn('line 4', str(ctx.exception))

        zone = '''$TTL 60
$ORIGIN example.com.
; comment
$GENERATE 1-3 bad A not-an-address
'''
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone(zone)
        self.assertIn('line 4', str(ctx.exception))

    def test_generate_limit_rejects_before_records(self):
        zone = '$GENERATE 1-4 bad A 192.0.2.$\n'
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone(zone, max_generate_records=3)
        self.assertIn('line 1', str(ctx.exception))
        self.assertIn('limit 3', str(ctx.exception))

    def test_plain_zone_regression(self):
        zone = '''$ORIGIN example.net.
$TTL 300
@ IN SOA ns.example.net. admin.example.net. 1 7200 3600 1209600 60
@ IN NS ns.example.net.
www 5m IN A 192.0.2.20
text IN TXT (
    "parenthesized text"
)
'''
        records = RR.fromZone(zone)

        self.assertEqual(len(records), 4)
        self.assertEqual(records[0].rtype, QTYPE.SOA)
        self.assertEqual(records[1].rtype, QTYPE.NS)
        self.assertEqual(records[2].ttl, 300)
        self.assertEqual(records[3].ttl, 300)
        self.assertIsInstance(records[3].rdata, TXT)
        self.assertEqual(records[3].rdata.data, [b'parenthesized text'])

    def test_generate_from_file_object(self):
        records = RR.fromZone(StringIO(
            '$ORIGIN example.com.\n$GENERATE 1-1 www A 192.0.2.$\n'))

        self.assertEqual(str(records[0].rname), 'www.example.com.')
        self.assertEqual(str(records[0].rdata), '192.0.2.1')

    def test_invalid_octal_keeps_directive_line(self):
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone('\n$GENERATE 08-09 host A 192.0.2.$\n')
        self.assertIn('line 2', str(ctx.exception))

    def test_range_number_must_be_64_bit(self):
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone('$GENERATE 0x10000000000000000-0x10000000000000000 host A 192.0.2.1\n')
        self.assertIn('line 1', str(ctx.exception))

    def test_trailing_escape_keeps_directive_line(self):
        with self.assertRaises(ZoneParseError) as ctx:
            RR.fromZone('$GENERATE 1-1 host TXT "value $\\"\n')
        self.assertIn('line 1', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
