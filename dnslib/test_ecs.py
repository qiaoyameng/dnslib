# -*- coding: utf-8 -*-
"""
    Tests for RFC 7871 EDNS Client Subnet (ECS) support

    Covers structured encoding/parsing of ECS options (IPv4, IPv6 and
    zero-length prefixes), wire-format validation (including non-zero
    trailing bits for non-octet-aligned prefixes), duplicate ECS
    rejection, round-tripping of unknown EDNS options and response
    source-prefix/scope checks used for ECS-aware caching.

    No real DNS queries are performed - all packets are built and
    parsed locally.
"""

import binascii
import struct

import pytest

from dnslib.dns import DNSRecord,DNSError,EDNS0,EDNSOption,ECSOption


def option_wire(opt):
    return struct.pack("!HH",opt.code,len(opt.data)) + opt.data


def record_with_opts(opts):
    q = DNSRecord.question("example.com")
    q.add_ar(EDNS0(udp_len=1232,opts=opts))
    return q


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def test_encode_ipv4_zero_prefix():
    ecs = ECSOption("0.0.0.0",0)
    assert ecs.family == 1
    assert ecs.srclen == 0
    assert ecs.scopelen == 0
    assert ecs.addr == b""
    assert ecs.data == binascii.unhexlify(b"00010000")


def test_encode_ipv6_zero_prefix():
    ecs = ECSOption("::",0)
    assert ecs.family == 2
    assert ecs.addr == b""
    assert ecs.data == binascii.unhexlify(b"00020000")


def test_encode_ipv4_17():
    ecs = ECSOption("192.0.128.0",17)
    # /17 -> 3 address bytes, top bit of third byte only
    assert ecs.addr == binascii.unhexlify(b"c00080")
    assert ecs.data == binascii.unhexlify(b"00011100c00080")


def test_encode_ipv4_17_masks_host_bits():
    # 192.0.2.200 -> bits beyond /17 must be zeroed (c0 00 02 -> c0 00 00)
    ecs = ECSOption("192.0.2.200",17)
    assert ecs.addr == binascii.unhexlify(b"c00000")
    assert ecs.data == binascii.unhexlify(b"00011100c00000")


def test_encode_ipv6_57():
    ecs = ECSOption("2001:db8:85a3:180::",57)
    # /57 -> 8 address bytes, top bit of eighth byte only
    assert ecs.addr == binascii.unhexlify(b"20010db885a30180")
    assert ecs.data == binascii.unhexlify(b"0002390020010db885a30180")


def test_encode_ipv6_57_masks_host_bits():
    ecs = ECSOption("2001:db8:85a3:1ff::",57)
    assert ecs.addr == binascii.unhexlify(b"20010db885a30180")


def test_encode_ipv4_full_prefix_default():
    ecs = ECSOption("192.0.2.1")
    assert ecs.srclen == 32
    assert ecs.addr == binascii.unhexlify(b"c0000201")
    assert ecs.data == binascii.unhexlify(b"00012000c0000201")


def test_encode_ipv6_full_prefix_default():
    ecs = ECSOption("2001:db8::1")
    assert ecs.srclen == 128
    assert ecs.addr == binascii.unhexlify(b"20010db8000000000000000000000001")
    assert ecs.data == binascii.unhexlify(
                        b"0002800020010db8000000000000000000000001")


def test_encode_scope_prefix():
    ecs = ECSOption("192.0.2.0",24,scopelen=24)
    assert ecs.data == binascii.unhexlify(b"00011818c00002")


@pytest.mark.parametrize("kwargs",[
    dict(address="192.0.2.1",srclen=33),
    dict(address="192.0.2.1",srclen=-1),
    dict(address="192.0.2.1",srclen=24,scopelen=33),
    dict(address="2001:db8::1",srclen=129),
    dict(address="2001:db8::1",srclen=64,scopelen=129),
])
def test_encode_invalid_prefix_length(kwargs):
    with pytest.raises(DNSError):
        ECSOption(**kwargs)


# ---------------------------------------------------------------------------
# Parsing / wire validation
# ---------------------------------------------------------------------------

def test_parse_roundtrip():
    for wire in [b"00010000",
                 b"00020000",
                 b"00011100c00080",
                 b"0002390020010db885a30180",
                 b"00012000c0000201",
                 b"0002800020010db8000000000000000000000001",
                 b"00011818c00002"]:
        ecs = ECSOption(data=binascii.unhexlify(wire))
        assert ecs.data == binascii.unhexlify(wire)


def test_parse_ipv4_17_fields():
    ecs = ECSOption(data=binascii.unhexlify(b"00011100c00080"))
    assert (ecs.family,ecs.srclen,ecs.scopelen) == (1,17,0)
    assert ecs.addr == binascii.unhexlify(b"c00080")
    assert str(ecs.source_network) == "192.0.128.0/17"


def test_parse_ipv6_57_fields():
    ecs = ECSOption(data=binascii.unhexlify(b"0002390020010db885a30180"))
    assert (ecs.family,ecs.srclen,ecs.scopelen) == (2,57,0)
    assert str(ecs.source_network) == "2001:db8:85a3:180::/57"


def test_parse_ipv4_nonzero_trailing_bits():
    # /17 keeps only the top bit of the third address byte
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00011100c00001"))


def test_parse_ipv6_nonzero_trailing_bits():
    # /57 keeps only the top bit of the eighth address byte
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"0002390020010db885a30181"))


def test_parse_address_length_mismatch():
    # too many address bytes for /17
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00011100c0000000"))
    # too few address bytes for /17
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00011100c000"))
    # zero prefix must carry no address bytes
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00010000c0"))


def test_parse_prefix_too_long():
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00012100c000000000"))
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00011821c00000"))


def test_parse_unknown_family():
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"00030000"))


def test_parse_truncated():
    with pytest.raises(DNSError):
        ECSOption(data=binascii.unhexlify(b"000100"))


# ---------------------------------------------------------------------------
# DNS message round-trip
# ---------------------------------------------------------------------------

def test_message_roundtrip():
    q = record_with_opts([ECSOption("192.0.128.0",17)])
    pkt = q.pack()
    r = DNSRecord.parse(pkt)
    assert r.pack() == pkt
    opts = r.ar[0].rdata
    assert len(opts) == 1
    assert opts[0].code == ECSOption.CODE
    ecs = ECSOption(data=opts[0].data)
    assert (ecs.srclen,ecs.scopelen) == (17,0)
    assert str(ecs.source_network) == "192.0.128.0/17"


def test_unknown_option_roundtrip():
    unknown = EDNSOption(65001,binascii.unhexlify(b"deadbeef"))
    q = record_with_opts([unknown,ECSOption("192.0.128.0",17)])
    pkt = q.pack()
    r = DNSRecord.parse(pkt)
    assert r.pack() == pkt
    opts = r.ar[0].rdata
    assert opts[0] == unknown
    assert opts[0].data == binascii.unhexlify(b"deadbeef")


def test_duplicate_ecs_rejected_on_construct():
    with pytest.raises(DNSError):
        record_with_opts([ECSOption("192.0.2.0",24),ECSOption("192.0.2.0",24)])


def test_duplicate_ecs_rejected_on_parse():
    ecs = ECSOption("192.0.2.0",24)
    opts = option_wire(ecs) + option_wire(ecs)
    opt_rr = b"\x00" + struct.pack("!HHIH",41,1232,0,len(opts)) + opts
    q = DNSRecord.question("example.com")
    pkt = bytearray(q.pack())
    struct.pack_into("!H",pkt,10,1)     # ARCOUNT = 1
    pkt = bytes(pkt) + opt_rr
    with pytest.raises(DNSError):
        DNSRecord.parse(pkt)


# ---------------------------------------------------------------------------
# Response correspondence & cache scope
# ---------------------------------------------------------------------------

def test_matches_query():
    q = ECSOption("192.0.2.0",24)
    assert ECSOption("192.0.2.0",24,scopelen=24).matches_query(q)
    assert ECSOption("192.0.2.0",24,scopelen=16).matches_query(q)
    # source prefix correspondence is checked independently of scope
    assert not ECSOption("192.0.2.0",25,scopelen=24).matches_query(q)
    assert not ECSOption("192.0.3.0",24,scopelen=24).matches_query(q)
    assert not ECSOption("2001:db8::",32,scopelen=32).matches_query(q)


def test_validate_response():
    q = ECSOption("192.0.2.0",24)
    ECSOption("192.0.2.0",24,scopelen=24).validate_response(q)
    with pytest.raises(DNSError):
        ECSOption("192.0.3.0",24,scopelen=24).validate_response(q)


def test_cache_key():
    r = ECSOption("192.0.2.0",24,scopelen=24)
    assert r.cache_key() == (1,"192.0.2.0/24")
    assert r.cache_key() == ECSOption("192.0.2.0",24,scopelen=24).cache_key()
    assert r.cache_key() != ECSOption("192.0.2.0",24,scopelen=16).cache_key()
    assert str(r.scope_network) == "192.0.2.0/24"


def test_scope_covers_query():
    r = ECSOption("192.0.2.0",24,scopelen=24)
    assert r.covers(ECSOption("192.0.2.0",24))
    assert r.covers(ECSOption("192.0.2.128",25))
    # a /24 answer does not cover a broader (/16) query
    assert not r.covers(ECSOption("192.0.0.0",16))
    assert not r.covers(ECSOption("192.0.3.0",24))


def test_broader_scope_not_valid_for_arbitrary_query():
    # response declares a broad (/16) cache scope
    r = ECSOption("192.0.2.0",24,scopelen=16)
    # valid for queries inside the declared scope ...
    assert r.covers(ECSOption("192.0.2.0",24))
    assert r.covers(ECSOption("192.0.3.0",24))
    # ... but must not be used as an answer for arbitrary queries
    assert not r.covers(ECSOption("198.51.100.0",24))
    assert not r.covers(ECSOption("203.0.113.0",24))


def test_zero_scope_covers_family():
    r = ECSOption("0.0.0.0",0,scopelen=0)
    assert r.covers(ECSOption("198.51.100.0",24))
    assert r.covers(ECSOption("192.0.2.0",24))
    # /0 only covers queries from the same address family
    assert not r.covers(ECSOption("2001:db8::",48))


def test_ipv6_scope():
    r = ECSOption("2001:db8:abcd::",48,scopelen=32)
    assert r.covers(ECSOption("2001:db8:abcd::",48))
    assert r.covers(ECSOption("2001:db8:ffff::",48))
    assert not r.covers(ECSOption("2001:db9::",48))
    assert not r.covers(ECSOption("192.0.2.0",24))
    assert str(r.scope_network) == "2001:db8::/32"


def test_full_prefix_scope():
    q = ECSOption("192.0.2.1")
    r = ECSOption("192.0.2.1",32,scopelen=32)
    assert r.matches_query(q)
    assert r.covers(q)
    assert not r.covers(ECSOption("192.0.2.2"))
    q6 = ECSOption("2001:db8::1")
    r6 = ECSOption("2001:db8::1",128,scopelen=128)
    assert r6.matches_query(q6)
    assert r6.covers(q6)
    assert not r6.covers(ECSOption("2001:db8::2"))


def test_repr_and_zone():
    ecs = ECSOption("192.0.128.0",17,scopelen=17)
    assert repr(ecs) == "<EDNS ECS: 192.0.128.0/17 scope 17>"
    assert ecs.toZone() == "; CLIENT-SUBNET: 192.0.128.0/17/17"
    assert str(ecs) == ecs.toZone()
