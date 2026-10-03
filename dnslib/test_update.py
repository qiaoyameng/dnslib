#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Tests for the RFC 2136 DNS UPDATE construction/parsing interface
    (dnslib.update.DNSUpdate).

    The hand-written wire bytes in this file (HEX_*) were written
    independently of the encoder against RFC 2136 sections 2.4/2.5 - both
    pack()->bytes and bytes->parse() are checked against them so the
    semantics are not validated by circular/type-guessing logic.
"""

import pytest

from dnslib import A, MX, RR, RD, QTYPE, CLASS, OPCODE, RCODE, DNSRecord
from dnslib.update import DNSUpdate, classify_prerequisite, classify_update

ZONE = "example.com"

# Header + zone section shared by all single-RR hand-written packets:
#   id=0000 flags=2800(opcode UPDATE) zo=1
#   example.com  SOA(6) IN(1)
HDR_ZONE = ("000028000001"
            # PR / UP / AR counts filled in per packet below
            )
ZONE_WIRE = "076578616d706c6503636f6d0000060001"
# example.com name encoded as compression pointer to zone name
NAME_PTR = "c00c"

# One-RR prerequisite packets (rrname compresses to the zone name).
# Tuple: (form, hex after zone section)
PREREQ_WIRE = {
    # ANY NONE ttl0 rdlen0
    'name_in_use':
        "000100000000" + NAME_PTR + "00ff00fe000000000000",
    # ANY ANY ttl0 rdlen0
    'name_not_in_use':
        "000100000000" + NAME_PTR + "00ff00ff000000000000",
    # MX(15) NONE(254) ttl0 rdlen0
    'rrset_exists':
        "000100000000" + NAME_PTR + "000f00fe000000000000",
    # MX(15) IN(1)   ttl0 rdlen0
    'rrset_not_exists':
        "000100000000" + NAME_PTR + "000f0001000000000000",
    # MX(15) IN(1) ttl0 rdlen7 RDATA: pref 10 + mx.example.com(ptr c00c)
    'rr_in_use':
        "000100000000" + NAME_PTR + "000f0001000000000007000a026d78c00c",
    # MX(15) NONE(254) ttl0 rdlen7 RDATA: as above
    'rr_not_in_use':
        "000100000000" + NAME_PTR + "000f00fe000000000007000a026d78c00c",
}

# One-RR update packets
UPDATE_WIRE = {
    # A IN ttl3600 rdlen4 192.0.2.4
    'add':
        "000000010000" + NAME_PTR + "0001000100000e100004c0000204",
    # ANY ANY ttl0 rdlen0
    'delete_name':
        "000000010000" + NAME_PTR + "00ff00ff000000000000",
    # A NONE ttl0 rdlen0
    'delete_rrset':
        "000000010000" + NAME_PTR + "000100fe000000000000",
    # A IN ttl0 rdlen4 192.0.2.5
    'delete_rr':
        "000000010000" + NAME_PTR + "00010001000000000004c0000205",
}


def _prereq_expected(form):
    return bytes.fromhex(HDR_ZONE + PREREQ_WIRE[form][:12] +
                         ZONE_WIRE + PREREQ_WIRE[form][12:])


def _update_expected(form):
    return bytes.fromhex(HDR_ZONE + UPDATE_WIRE[form][:12] +
                         ZONE_WIRE + UPDATE_WIRE[form][12:])


def _build_prereq(form):
    u = DNSUpdate(ZONE, id=0)
    {
        'name_in_use':      lambda: u.prereq_name_in_use(ZONE),
        'name_not_in_use':  lambda: u.prereq_name_not_in_use(ZONE),
        'rrset_exists':     lambda: u.prereq_rrset_exists(ZONE, "MX"),
        'rrset_not_exists': lambda: u.prereq_rrset_not_exists(ZONE, "MX"),
        'rr_in_use':        lambda: u.prereq_rr_in_use(
                                    ZONE, MX("mx.example.com", 10)),
        'rr_not_in_use':    lambda: u.prereq_rr_not_in_use(
                                    ZONE, MX("mx.example.com", 10)),
    }[form]()
    return u


def _build_update(form):
    u = DNSUpdate(ZONE, id=0)
    {
        'add':          lambda: u.add(ZONE, 3600, A("192.0.2.4")),
        'delete_name':  lambda: u.delete_name(ZONE),
        'delete_rrset': lambda: u.delete_rrset(ZONE, "A"),
        'delete_rr':    lambda: u.delete_rr(ZONE, A("192.0.2.5")),
    }[form]()
    return u


# --------------------------------------------------------------------------
# Pack/parse round trips for every prerequisite/update form
# --------------------------------------------------------------------------

@pytest.mark.parametrize("form", sorted(PREREQ_WIRE))
def test_prereq_roundtrip(form):
    u = _build_prereq(form)
    raw = u.pack()
    # byte-exact comparison with independently written protocol bytes
    assert raw == _prereq_expected(form)
    parsed = DNSRecord.parse(raw)
    assert isinstance(parsed, DNSUpdate)
    assert parsed == u
    assert len(parsed.prereq_rrs) == 1
    assert classify_prerequisite(parsed.prereq_rrs[0], CLASS.IN) == form
    assert parsed.header.a == 1 and parsed.header.auth == 0


@pytest.mark.parametrize("form", sorted(UPDATE_WIRE))
def test_update_roundtrip(form):
    u = _build_update(form)
    raw = u.pack()
    assert raw == _update_expected(form)
    parsed = DNSRecord.parse(raw)
    assert isinstance(parsed, DNSUpdate)
    assert parsed == u
    assert len(parsed.update_rrs) == 1
    assert classify_update(parsed.update_rrs[0], CLASS.IN) == form
    assert parsed.header.a == 0 and parsed.header.auth == 1


def test_handwritten_bytes_parse_without_type_guessing():
    # Parse the hand-written delete_rrset MX packet and verify the empty
    # RDATA is the opaque base RD, not an MX instance
    raw = _prereq_expected('rrset_exists')
    p = DNSUpdate.parse(raw)
    rr = p.prereq_rrs[0]
    assert rr.rtype == QTYPE.MX
    assert type(rr.rdata) is RD
    assert rr.rdata.data == b""
    # The operation is identified by section context (class NONE), not rtype
    assert classify_prerequisite(rr, CLASS.IN) == 'rrset_exists'


# --------------------------------------------------------------------------
# Composite packet against a fully hand-written minimal message
# --------------------------------------------------------------------------

def test_minimal_composite_packet():
    u = DNSUpdate(ZONE, zone_class="IN", id=0xABCD)
    u.prereq_name_in_use("host.example.com")
    u.add("host.example.com", 3600, A("192.0.2.4"))
    expected = bytes.fromhex(
        "ABCD28000001000100010000"
        "076578616d706c6503636f6d0000060001"
        # prereq host.example.com ANY NONE ttl0 rdlen0
        "04686f7374c00c"
        "00ff00fe000000000000"
        # update host.example.com A IN ttl3600 rdlen4 192.0.2.4
        "c01d"
        "0001000100000e100004c0000204")
    assert u.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed == u
    assert classify_prerequisite(parsed.prereq_rrs[0], CLASS.IN) \
        == 'name_in_use'
    assert classify_update(parsed.update_rrs[0], CLASS.IN) == 'add'


def test_delete_composite_packet():
    expected = bytes.fromhex(
        "111128000001000000020000"
        "076578616d706c6503636f6d0000060001"
        "04686f7374c00c"
        # delete all RRsets of the name: ANY ANY
        "00ff00ff000000000000"
        "c01d"
        # delete one RR: A IN ttl0 192.0.2.5
        "00010001000000000004c0000205")
    p = DNSUpdate.parse(expected)
    assert [classify_update(r, CLASS.IN) for r in p.update_rrs] == \
           ['delete_name', 'delete_rr']
    u = DNSUpdate(ZONE, id=0x1111)
    u.delete_name("host.example.com")
    u.delete_rr("host.example.com", A("192.0.2.5"))
    assert u.pack() == expected
    assert DNSUpdate.parse(u.pack()) == u


# --------------------------------------------------------------------------
# Empty RDATA legality is context dependent
# --------------------------------------------------------------------------

def test_empty_rdata_rejected_in_query_response():
    # ordinary QUERY/RESPONSE containing an answer RR with RDLENGTH 0 (A)
    raw = bytes.fromhex(
        "123481800001000100000000"
        "016103636f6d0000010001"
        "016103636f6d0000010001000000000000")
    with pytest.raises(Exception, match="Empty RR"):
        DNSRecord.parse(raw)


def test_empty_mx_rejected_in_query_response():
    raw = bytes.fromhex(
        "123481800001000100000000"
        "016103636f6d00000f0001"
        "016103636f6d00000f0001000000000000")
    with pytest.raises(Exception, match="Empty RR"):
        DNSRecord.parse(raw)


def test_empty_rdata_rejected_in_additional_section():
    u = DNSUpdate(ZONE, id=0)
    u.add("x.example.com", 60, A("1.2.3.4"))
    pkt = bytearray(u.pack())
    pkt[10:12] = (1).to_bytes(2, 'big')  # ARCOUNT = 1
    # empty A RR
    pkt += bytes.fromhex("04686f737403636f6d0000010001000000000000")
    with pytest.raises(Exception, match="Empty RR"):
        DNSRecord.parse(bytes(pkt))


def test_empty_rdata_rejected_in_update_response():
    u = DNSUpdate(ZONE, id=0)
    u.prereq_name_in_use(ZONE)
    raw = bytearray(u.pack())
    raw[2] |= 0x80  # set QR
    with pytest.raises(Exception, match="Empty RR"):
        DNSRecord.parse(bytes(raw))


def test_nonempty_rdata_in_additional_passes():
    u = DNSUpdate(ZONE, id=0)
    u.add("h.example.com", 60, A("1.2.3.4"))
    u.add_ar(RR("h.example.com", rtype=QTYPE.A, ttl=0, rdata=A("1.2.3.4")))
    p = DNSRecord.parse(u.pack())
    assert len(p.ar) == 1
    assert type(p.ar[0].rdata) is A


# --------------------------------------------------------------------------
# Validation: zone / class / TTL / out-of-zone names with operation context
# --------------------------------------------------------------------------

def test_zone_section_layout():
    u = DNSUpdate(ZONE)
    assert u.header.opcode == OPCODE.UPDATE
    assert u.zone_name == ZONE
    assert u.zone_rr.qtype == QTYPE.SOA
    assert u.zone_rr.qclass == CLASS.IN


def test_invalid_zone_class():
    for bad in (254, 255, 999, -1):
        with pytest.raises(Exception, match="zone"):
            DNSUpdate(ZONE, zone_class=bad)
    with pytest.raises(Exception, match="Invalid rclass"):
        DNSUpdate(ZONE, zone_class="BOGUS")


def test_missing_zone():
    with pytest.raises(Exception, match="zone name"):
        DNSUpdate()


@pytest.mark.parametrize("method,args,oplabel", [
    ("prereq_name_in_use",      ("x.other.com",),               "name is in use"),
    ("prereq_name_not_in_use",  ("x.other.com",),               "name is not in use"),
    ("prereq_rrset_exists",     ("x.other.com", "A"),           "rrset exists"),
    ("prereq_rrset_not_exists", ("x.other.com", "A"),           "rrset not exists"),
    ("prereq_rr_in_use",        ("x.other.com", A("1.1.1.1")),  "rr is in use"),
    ("prereq_rr_not_in_use",    ("x.other.com", A("1.1.1.1")),  "rr not in use"),
    ("add",                     ("x.other.com", 60, A("1.1.1.1")), "update add"),
    ("delete_name",             ("x.other.com",),               "delete name"),
    ("delete_rrset",            ("x.other.com", "A"),           "delete rrset"),
    ("delete_rr",               ("x.other.com", A("1.1.1.1")),  "delete rr"),
])
def test_out_of_zone_names_rejected(method, args, oplabel):
    u = DNSUpdate(ZONE)
    with pytest.raises(Exception) as ei:
        getattr(u, method)(*args)
    assert oplabel in str(ei.value)
    assert "outside zone" in str(ei.value)


def test_add_ttl_rules():
    u = DNSUpdate(ZONE)
    with pytest.raises(Exception, match="update add"):
        u.add("h.example.com", 0, A("1.2.3.4"))
    with pytest.raises(Exception, match="invalid TTL"):
        u.add("h.example.com", 0x80000000, A("1.2.3.4"))
    with pytest.raises(Exception, match="update add"):
        u.add("h.example.com", -5, A("1.2.3.4"))


def test_any_rtype_only_for_name_wildcards():
    u = DNSUpdate(ZONE)
    with pytest.raises(Exception, match="rrset exists"):
        u.prereq_rrset_exists("h.example.com", "ANY")
    with pytest.raises(Exception, match="rrset not exists"):
        u.prereq_rrset_not_exists("h.example.com", "ANY")
    with pytest.raises(Exception, match="delete rrset"):
        u.delete_rrset("h.example.com", "ANY")
    with pytest.raises(Exception, match="delete rr"):
        u.delete_rr("h.example.com", A("1.2.3.4"), rtype="ANY")


# --------------------------------------------------------------------------
# Parse-time validation reports which kind of operation was invalid
# --------------------------------------------------------------------------

def _append_raw_rr(update, wire_rr, count_offset=8):
    pkt = bytearray(update.pack())
    pkt[count_offset:count_offset + 2] = (
        int.from_bytes(pkt[count_offset:count_offset + 2], 'big') + 1
    ).to_bytes(2, 'big')
    return bytes(pkt) + bytes.fromhex(wire_rr)


def test_parse_out_of_zone_update_name():
    u = DNSUpdate(ZONE)
    # add an in-zone RR first, then append an out-of-zone add RR
    u.add("h.example.com", 60, A("1.2.3.4"))
    raw = _append_raw_rr(
        u,
        "0178056f74686572036e657400"  # x.other.net
        "000100010000003c000409090909")
    with pytest.raises(Exception,
                       match=r"update \(update add\):.*outside zone"):
        DNSRecord.parse(raw)


def test_parse_malformed_prerequisite():
    # class ANY(255) + concrete type A + empty rdata is not a legal form
    u = DNSUpdate(ZONE)
    u.prereq_rrset_exists("h.example.com", "A")
    raw = bytearray(u.pack())
    i = raw.find(bytes.fromhex("000100fe000000000000"))
    assert i >= 0
    raw[i + 2:i + 4] = b"\x00\xff"
    with pytest.raises(Exception, match="prerequisite:"):
        DNSRecord.parse(bytes(raw))


def test_parse_malformed_update():
    # zone class + concrete type + empty rdata is not legal in update sec
    u = DNSUpdate(ZONE)
    u.delete_rrset("h.example.com", "A")
    raw = bytearray(u.pack())
    i = raw.find(bytes.fromhex("000100fe000000000000"))
    assert i >= 0
    raw[i + 2:i + 4] = b"\x00\x01"
    with pytest.raises(Exception, match="update:"):
        DNSRecord.parse(bytes(raw))


def test_parse_wildcard_delete_with_nonzero_ttl():
    # delete_rrset form (ANY rtype/class) with TTL != 0 is illegal
    u = DNSUpdate(ZONE)
    u.delete_rrset("h.example.com", "A")
    raw = bytearray(u.pack())
    i = raw.find(bytes.fromhex("000100fe000000000000"))
    assert i >= 0
    raw[i + 4:i + 8] = (100).to_bytes(4, 'big')
    with pytest.raises(Exception, match="update:"):
        DNSRecord.parse(bytes(raw))


def test_parse_wrong_zone_qtype():
    raw = bytearray(DNSUpdate(ZONE).pack())
    # zone question type SOA(6) -> A(1)
    raw[raw.find(bytes.fromhex("00060001")):raw.find(bytes.fromhex("00060001"))+2] = b"\x00\x01"
    with pytest.raises(Exception, match="zone question must be SOA"):
        DNSRecord.parse(bytes(raw))


def test_parse_non_update_rejected():
    q = DNSRecord.question(ZONE, "SOA")
    with pytest.raises(Exception, match="Not a DNS UPDATE"):
        DNSUpdate.parse(q.pack())


def test_update_response_parses():
    u = DNSUpdate(ZONE)
    u.header.qr = 1
    u.header.rcode = RCODE.YXDOMAIN
    p = DNSRecord.parse(u.pack())
    assert isinstance(p, DNSUpdate)
    assert p.header.qr == 1
    assert p.header.rcode == RCODE.YXDOMAIN


# --------------------------------------------------------------------------
# Misc construction details
# --------------------------------------------------------------------------

def test_inferred_rtype_vs_explicit():
    u1 = DNSUpdate(ZONE, id=0)
    u1.add("h.example.com", 60, A("1.2.3.4"))
    u2 = DNSUpdate(ZONE, id=0)
    u2.add("h.example.com", 60, A("1.2.3.4"), rtype="A")
    assert u1.pack() == u2.pack()

    # raw/unknown rdata requires explicit rtype and round trips verbatim
    u3 = DNSUpdate(ZONE)
    u3.add("h.example.com", 60, RD(b"\x01\x02"), rtype=999)
    p = DNSRecord.parse(u3.pack())
    rr = p.update_rrs[0]
    assert rr.rtype == 999
    assert rr.rdata.data == b"\x01\x02"
    assert classify_update(rr, CLASS.IN) == 'add'


def test_class_chaining_and_counts():
    u = DNSUpdate(ZONE)
    ret = u.prereq_name_in_use("a.example.com").add(
        "a.example.com", 30, A("1.2.3.4"))
    assert ret is u
    raw = u.pack()
    assert raw[4:12] == bytes.fromhex("0001000100010000")
    flags = int.from_bytes(raw[2:4], 'big')
    assert (flags >> 11) & 0xF == OPCODE.UPDATE
    # request packets carry no other flags
    assert flags == OPCODE.UPDATE << 11
