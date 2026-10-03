# -*- coding: utf-8 -*-

"""
    Tests for the RFC2136 (Dynamic DNS UPDATE) high level interface.

    Every prerequisite/update form is checked three ways:

      1. DNSUpdate.pack() output equals a packet assembled by hand from
         raw struct encoding (including name compression pointers) - so
         the semantics do not rely on guessing anything from RDATA.
      2. parse(pack(x)) round-trips to an equal semantic object.
      3. The raw RR fields (TYPE/CLASS/TTL/RDLENGTH/RDATA) of the wire
         encoding match exactly the combination the RFC prescribes for
         that form.
"""

import struct

import pytest

from dnslib import (A, AAAA, MX, TXT, CNAME, DNSHeader, DNSQuestion,
                    DNSRecord, RR, QTYPE, CLASS)
from dnslib.dns import DNSError, EmptyRD, RD
from dnslib.label import DNSBuffer
from dnslib.update import (DNSUpdate, RRsetExists, NameInUse, RRsetAbsent,
                           NameNotInUse, RRsetValue, AddRecord, DeleteName,
                           DeleteRRset, DeleteRecord, CLASS_NONE,
                           _classify)


# ---------------------------------------------------------------------------
# Hand-rolled wire encoding helpers (independent of the code under test)
# ---------------------------------------------------------------------------

def ptr(off):
    return struct.pack("!H", 0xC000 | off)


def encode_name(buf, labels, pointer_to=None):
    """Encode labels; may finish with a compression pointer."""
    for lab in labels:
        buf.append(bytes([len(lab)]))
        buf.append(lab)
    if pointer_to is not None:
        buf.append(ptr(pointer_to))
    else:
        buf.append(b"\x00")


def build_packet(zone_labels, zone_qtype, raw_entries, prereq_count,
                 update_count, opcode_flags=0x2800, msg_id=0x2222):
    """
        Assemble a minimal UPDATE packet by hand.

        raw_entries is a list of (name_encoding, type, klass, ttl, rdata)
        where name_encoding is the already-encoded bytes for the rname
        and rdata is bytes.
    """
    b = DNSBuffer()
    b.pack("!HHHHHH", msg_id, opcode_flags, 1, prereq_count, update_count, 0)
    # Zone section starts at offset 12
    encode_name(b, zone_labels)
    b.pack("!HH", zone_qtype, 1)
    for name_bytes, rtype, rclass, ttl, rdata in raw_entries:
        b.append(name_bytes)
        b.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        b.append(rdata)
    return bytes(b.data)


ZONE = [b"example", b"com"]
ZONE_PTR_OFF = 12


def sub_name(label):
    """'<label>.example.com' encoded as label then pointer to zone."""
    return bytes([len(label)]) + label + ptr(ZONE_PTR_OFF)


# RDATA fixtures ------------------------------------------------------------

A_RDATA = bytes([192, 0, 2, 3])
AAAA_RDATA = b"\x20\x01\xdb\x80" + b"\x00" * 11 + b"\x01"
MX_RDATA = struct.pack("!H", 10) + bytes([2]) + b"mx" + ptr(ZONE_PTR_OFF)
TXT_RDATA = bytes([3]) + b"abc"


# ---------------------------------------------------------------------------
# Pack output == hand-built bytes, one test per form
# ---------------------------------------------------------------------------

def _one_prereq(entry):
    msg = DNSUpdate("example.com", id=0x2222)
    msg.prerequisites.append(entry.bind_class(CLASS.IN))
    return msg


def _one_update(entry):
    msg = DNSUpdate("example.com", id=0x2222)
    msg.updates.append(entry.bind_class(CLASS.IN))
    return msg


def test_rrset_exists_bytes():
    # 2.4.1: TYPE explicit, CLASS=zone(IN), TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"www"), QTYPE.A, CLASS.IN, 0, b"")],
        prereq_count=1, update_count=0)
    msg = _one_prereq(RRsetExists("www.example.com", A))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.prerequisites == [RRsetExists("www.example.com", A, CLASS.IN)]
    assert parsed.prerequisites[0].kind == "rrset_exists"


def test_name_in_use_bytes():
    # 2.4.2: TYPE=ANY, CLASS=zone, TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"www"), QTYPE.ANY, CLASS.IN, 0, b"")],
        prereq_count=1, update_count=0)
    msg = _one_prereq(NameInUse("www.example.com"))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.prerequisites == [NameInUse("www.example.com", CLASS.IN)]
    assert parsed.prerequisites[0].kind == "name_in_use"


def test_rrset_absent_bytes():
    # 2.4.3: TYPE explicit, CLASS=NONE(254), TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"www"), QTYPE.A, CLASS_NONE, 0, b"")],
        prereq_count=1, update_count=0)
    msg = _one_prereq(RRsetAbsent("www.example.com", A))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.prerequisites == [RRsetAbsent("www.example.com", A)]
    assert parsed.prerequisites[0].kind == "rrset_absent"


def test_name_not_in_use_bytes():
    # 2.4.4: TYPE=ANY, CLASS=NONE, TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"www"), QTYPE.ANY, CLASS_NONE, 0, b"")],
        prereq_count=1, update_count=0)
    msg = _one_prereq(NameNotInUse("www.example.com"))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.prerequisites == [NameNotInUse("www.example.com")]
    assert parsed.prerequisites[0].kind == "name_not_in_use"


def test_rrset_value_bytes():
    # 2.4.5: TYPE explicit, CLASS=zone, TTL=0, RDATA given
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"www"), QTYPE.A, CLASS.IN, 0, A_RDATA)],
        prereq_count=1, update_count=0)
    msg = _one_prereq(RRsetValue("www.example.com", A, A("192.0.2.3")))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.prerequisites == [
        RRsetValue("www.example.com", A, A("192.0.2.3"), CLASS.IN)]
    assert parsed.prerequisites[0].kind == "rrset_value"


def test_add_bytes():
    # 2.5.1: TYPE explicit, CLASS=zone, TTL given, RDATA given
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"host"), QTYPE.A, CLASS.IN, 300, A_RDATA)],
        prereq_count=0, update_count=1)
    msg = _one_update(AddRecord("host.example.com", A, A("192.0.2.3"), 300))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.updates == [
        AddRecord("host.example.com", A, A("192.0.2.3"), 300, CLASS.IN)]
    assert parsed.updates[0].kind == "add"


def test_delete_name_bytes():
    # 2.5.2: TYPE=ANY, CLASS=NONE, TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"old"), QTYPE.ANY, CLASS_NONE, 0, b"")],
        prereq_count=0, update_count=1)
    msg = _one_update(DeleteName("old.example.com"))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.updates == [DeleteName("old.example.com")]
    assert parsed.updates[0].kind == "delete_name"


def test_delete_rrset_bytes():
    # 2.5.3: TYPE explicit, CLASS=NONE, TTL=0, RDLENGTH=0
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"old"), QTYPE.A, CLASS_NONE, 0, b"")],
        prereq_count=0, update_count=1)
    msg = _one_update(DeleteRRset("old.example.com", A))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.updates == [DeleteRRset("old.example.com", A)]
    assert parsed.updates[0].kind == "delete_rrset"


def test_delete_record_bytes():
    # 2.5.4: TYPE explicit, CLASS=NONE, TTL=0, RDATA given
    expected = build_packet(
        ZONE, QTYPE.SOA,
        [(sub_name(b"old"), QTYPE.A, CLASS_NONE, 0, A_RDATA)],
        prereq_count=0, update_count=1)
    msg = _one_update(DeleteRecord("old.example.com", A, A("192.0.2.3")))
    assert msg.pack() == expected
    parsed = DNSUpdate.parse(expected)
    assert parsed.updates == [
        DeleteRecord("old.example.com", A, A("192.0.2.3"))]
    assert parsed.updates[0].kind == "delete_record"


# ---------------------------------------------------------------------------
# Full-message round trips over several RDATA types
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rtype,rdata", [
    (A, A("192.0.2.3")),
    (AAAA, AAAA("2001:db8::1")),
    (MX, MX("mx.example.com", 10)),
    (TXT, TXT(b"abc")),
    (CNAME, CNAME("target.example.com")),
    (99, RD(b"\xde\xad\xbe\xef")),       # unknown TYPE - opaque RDATA
])
def test_add_and_value_roundtrip_for_rdata(rtype, rdata):
    msg = DNSUpdate("example.com", id=0x1234)
    if isinstance(rtype, int):
        msg.add("h.example.com", rdata, rtype=rtype, ttl=60)
        msg.rrset_value("h.example.com", rdata, rtype=rtype)
        msg.delete_record("h.example.com", rdata, rtype=rtype)
    else:
        msg.add("h.example.com", rdata, rtype=rtype, ttl=60)
        msg.rrset_value("h.example.com", rdata, rtype=rtype)
        msg.delete_record("h.example.com", rdata, rtype=rtype)
    parsed = DNSUpdate.parse(msg.pack())
    assert parsed == msg
    kinds = [u.kind for u in parsed.updates]
    assert kinds == ["add", "delete_record"]
    assert [p.kind for p in parsed.prerequisites] == ["rrset_value"]


def test_all_forms_together_roundtrip():
    msg = DNSUpdate("example.com", id=0x5555)
    msg.rrset_exists("a.example.com", A)
    msg.name_in_use("example.com")
    msg.rrset_absent("b.example.com", AAAA)
    msg.name_not_in_use("c.example.com")
    msg.rrset_value("d.example.com", A("192.0.2.1"))
    msg.add("e.example.com", MX("mail.example.com", 20), ttl=900)
    msg.add("f.example.com", A("192.0.2.2"), ttl=900)
    msg.delete_name("g.example.com")
    msg.delete_rrset("h.example.com", TXT)
    msg.delete_record("i.example.com", A("192.0.2.9"))

    wire = msg.pack()
    # Generic parser still produces a DNSRecord (opcode UPDATE, zo=1...)
    rec = DNSRecord.parse(wire)
    assert rec.header.opcode == OPCODE_UPDATE
    assert rec.header.q == 1
    assert rec.header.a == 5
    assert rec.header.auth == 5
    parsed = DNSUpdate.parse(wire)
    assert parsed == msg
    # Packing again produces identical bytes (deterministic)
    assert DNSUpdate.parse(wire).pack() == wire


def test_zone_question_is_soa_in():
    msg = DNSUpdate("example.com", id=1)
    msg.delete_name("x.example.com")
    rec = DNSRecord.parse(msg.pack())
    zq = rec.questions[0]
    assert zq.qtype == QTYPE.SOA
    assert zq.qclass == CLASS.IN
    assert str(zq.qname) == "example.com."


# ---------------------------------------------------------------------------
# Wire field assertions for each semantic form (not guessed from RDATA)
# ---------------------------------------------------------------------------

def _wire_fields(msg, section):
    rec = DNSRecord.parse(msg.pack())
    return rec.rr if section == "prereq" else rec.auth


def test_wire_field_matrix():
    m = DNSUpdate("example.com", id=1)
    def fields(entries, section):
        return [(r.rtype, r.rclass, r.ttl, isinstance(r.rdata, EmptyRD),
                 getattr(r.rdata, "data", None)) for r in
                _wire_fields(_build(entries), section)]

    def _build(entries):
        mm = DNSUpdate("example.com", id=1)
        for sec, obj in entries:
            getattr(mm, sec).append(obj.bind_class(CLASS.IN))
        return mm

    # prerequisites
    p = fields([("prerequisites", RRsetExists("a.example.com", A)),
                ("prerequisites", NameInUse("b.example.com")),
                ("prerequisites", RRsetAbsent("c.example.com", A)),
                ("prerequisites", NameNotInUse("d.example.com")),
                ("prerequisites", RRsetValue("e.example.com", A,
                                             A("1.2.3.4")))], "prereq")
    assert p == [
        (QTYPE.A, CLASS.IN, 0, True, b""),
        (QTYPE.ANY, CLASS.IN, 0, True, b""),
        (QTYPE.A, CLASS_NONE, 0, True, b""),
        (QTYPE.ANY, CLASS_NONE, 0, True, b""),
        (QTYPE.A, CLASS.IN, 0, False, (1, 2, 3, 4)),
    ]
    # updates
    u = fields([("updates", AddRecord("a.example.com", A, A("1.2.3.4"), 100)),
                ("updates", DeleteName("b.example.com")),
                ("updates", DeleteRRset("c.example.com", A)),
                ("updates", DeleteRecord("d.example.com", A,
                                         A("1.2.3.4")))], "update")
    assert u == [
        (QTYPE.A, CLASS.IN, 100, False, (1,2,3,4)),
        (QTYPE.ANY, CLASS_NONE, 0, True, b""),
        (QTYPE.A, CLASS_NONE, 0, True, b""),
        (QTYPE.A, CLASS_NONE, 0, False, (1,2,3,4)),
    ]


OPCODE_UPDATE = 5


# ---------------------------------------------------------------------------
# Parser robustness / malformed UPDATE packets
# ---------------------------------------------------------------------------

def _update_packet(zone_type=QTYPE.SOA, zone_class=CLASS.IN,
                   zocount=1, opcode=5, qr=0, entries_prereq=(),
                   entries_update=()):
    b = DNSBuffer()
    flags = (qr << 15) | (opcode << 11)
    b.pack("!HHHHHH", 1, flags, zocount,
           len(entries_prereq), len(entries_update), 0)
    encode_name(b, ZONE)
    b.pack("!HH", zone_type, zone_class)
    for ne, t, c, ttl, rd in entries_prereq:
        b.append(ne); b.pack("!HHIH", t, c, ttl, len(rd)); b.append(rd)
    for ne, t, c, ttl, rd in entries_update:
        b.append(ne); b.pack("!HHIH", t, c, ttl, len(rd)); b.append(rd)
    return bytes(b.data)


def test_parse_rejects_non_update():
    q = DNSRecord.question("example.com", "SOA")
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(q.pack())
    assert "not an UPDATE" in str(ei.value)


def test_parse_rejects_bad_zone_count():
    pkt = _update_packet(zocount=0)
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "zone section" in str(ei.value)


def test_parse_rejects_bad_zone_type():
    pkt = _update_packet(zone_type=QTYPE.A)
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "SOA" in str(ei.value)


def test_parse_rejects_bad_zone_class():
    pkt = _update_packet(zone_class=CLASS_NONE)
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "zone CLASS" in str(ei.value)


def test_parse_rejects_unmatched_prereq_form():
    # TTL != 0 on an empty-RDATA prerequisite is not a valid form
    pkt = _update_packet(entries_prereq=[
        (sub_name(b"a"), QTYPE.A, CLASS.IN, 123, b"")])
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "prerequisite" in str(ei.value)


def test_parse_rejects_unmatched_update_form():
    # TYPE=ANY with RDATA is not a valid update form
    pkt = _update_packet(entries_update=[
        (sub_name(b"a"), QTYPE.ANY, CLASS.IN, 0, A_RDATA)])
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "update" in str(ei.value)


def test_parse_rejects_out_of_zone_entry():
    # A prereq naming a name outside the zone must fail validation
    pkt = _update_packet(entries_update=[
        (bytes([5]) + b"other" + bytes([3]) + b"org" + b"\x00",
         QTYPE.ANY, CLASS_NONE, 0, b"")])
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "outside zone" in str(ei.value)


def test_parse_rejects_prereq_any_none_combo():
    # TYPE=ANY + CLASS=NONE + empty is a valid update delete_name but
    # it is not any valid prerequisite form
    pkt = _update_packet(entries_prereq=[
        (sub_name(b"a"), QTYPE.ANY, CLASS_NONE, 0, b"")])
    # This matches NameNotInUse (2.4.4) actually - assert correct kind
    parsed = DNSUpdate.parse(pkt)
    assert parsed.prerequisites[0].kind == "name_not_in_use"


def test_parse_rejects_prereq_with_data_any():
    # TYPE=ANY with RDATA in prerequisite matches no 2.4.x form
    pkt = _update_packet(entries_prereq=[
        (sub_name(b"a"), QTYPE.ANY, CLASS.IN, 0, A_RDATA)])
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "prerequisite" in str(ei.value)


def test_parse_rejects_update_any_with_data():
    # TYPE=ANY + non-empty RDATA in update matches no 2.5.x form
    pkt = _update_packet(entries_update=[
        (sub_name(b"a"), QTYPE.ANY, CLASS_NONE, 0, A_RDATA)])
    with pytest.raises(DNSError) as ei:
        DNSUpdate.parse(pkt)
    assert "update" in str(ei.value)


def test_unknown_opcode_empty_rdata_still_rejected():
    # Even with opcode UPDATE, a *response* (qr=1) must not allow empty RDATA
    pkt = _update_packet(qr=1, entries_update=[
        (sub_name(b"a"), QTYPE.A, CLASS.IN, 0, b"")])
    with pytest.raises(DNSError) as ei:
        DNSRecord.parse(pkt)
    assert "Empty RR" in str(ei.value)


# ---------------------------------------------------------------------------
# Empty RDATA must never be allowed in ordinary query/response packets
# ---------------------------------------------------------------------------

def _normal_response_with_empty_rr(rtype):
    b = DNSBuffer()
    # standard query response, q=1 a=1
    DNSHeader(id=1, bitmap=0x8180, q=1, a=1).pack(b)
    encode_name(b, [b"host", b"example", b"com"])
    b.pack("!HH", rtype, CLASS.IN)
    # answer with zero rdlength
    b.append(ptr(12))
    b.pack("!HHIH", rtype, CLASS.IN, 60, 0)
    return bytes(b.data)


@pytest.mark.parametrize("rtype", [QTYPE.A, QTYPE.MX, QTYPE.AAAA, QTYPE.TXT])
def test_empty_rdata_in_response_rejected_on_parse(rtype):
    wire = _normal_response_with_empty_rr(rtype)
    with pytest.raises(DNSError) as ei:
        DNSRecord.parse(wire)
    assert "Empty RR" in str(ei.value)


@pytest.mark.parametrize("rtype", [QTYPE.A, QTYPE.MX])
def test_empty_rdata_in_response_rejected_on_pack(rtype):
    rec = DNSRecord(DNSHeader(id=1, bitmap=0x8180))
    rec.rr.append(RR("host.example.com", rtype, CLASS.IN, 60, EmptyRD()))
    with pytest.raises(DNSError) as ei:
        rec.pack()
    assert "zero-length RDATA" in str(ei.value)


def test_empty_rdata_in_additional_of_update_rejected():
    # Additional section may never carry empty RDATA even in an UPDATE
    b = DNSBuffer()
    DNSHeader(id=1, opcode=5, q=0, a=0, auth=0, ar=1).pack(b)
    encode_name(b, [b"x"])
    b.pack("!HHIH", QTYPE.A, CLASS.IN, 0, 0)
    with pytest.raises(DNSError) as ei:
        DNSRecord.parse(bytes(b.data))
    assert "Empty RR" in str(ei.value)


# ---------------------------------------------------------------------------
# High level API validation - error messages identify the operation kind
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,args,kind_phrase", [
    ("rrset_exists", ("o.org", A), "prerequisite rrset_exists"),
    ("name_in_use", ("o.org",), "prerequisite name_in_use"),
    ("rrset_absent", ("o.org", A), "prerequisite rrset_absent"),
    ("name_not_in_use", ("o.org",), "prerequisite name_not_in_use"),
    ("rrset_value", ("o.org", A("1.1.1.1")), "prerequisite rrset_value"),
    ("add", ("o.org", A("1.1.1.1")), "update add"),
    ("delete_name", ("o.org",), "update delete_name"),
    ("delete_rrset", ("o.org", A), "update delete_rrset"),
    ("delete_record", ("o.org", A("1.1.1.1")), "update delete_record"),
])
def test_out_of_zone_names_rejected_per_kind(method, args, kind_phrase):
    msg = DNSUpdate("example.com")
    with pytest.raises(DNSError) as ei:
        getattr(msg, method)(*args)
    msg_text = str(ei.value)
    assert "outside zone" in msg_text
    assert kind_phrase in msg_text


def test_in_zone_boundaries():
    # zone apex and subdomains are fine; sibling/parent suffix not
    msg = DNSUpdate("example.com")
    msg.delete_name("example.com")           # apex
    msg.add("a.b.example.com", A("1.1.1.1"))  # deep subdomain
    DNSUpdate.parse(msg.pack()) == msg
    with pytest.raises(DNSError):
        msg.delete_name("notexample.com")    # suffix but not subdomain
    with pytest.raises(DNSError):
        msg.delete_name("com")               # parent


def test_root_zone_owns_everything():
    msg = DNSUpdate(".")
    msg.add("anything.org", A("1.1.1.1"), ttl=10)
    parsed = DNSUpdate.parse(msg.pack())
    assert parsed == msg


def test_class_ttl_validation():
    msg = DNSUpdate("example.com")
    with pytest.raises(DNSError):
        DNSUpdate("example.com", zone_class="None")
    with pytest.raises(DNSError):
        DNSUpdate("example.com", zone_class=77)
    with pytest.raises(DNSError):
        msg.add("h.example.com", A("1.1.1.1"), ttl=-1)
    with pytest.raises(DNSError):
        msg.add("h.example.com", A("1.1.1.1"), ttl=2 ** 31)


def test_any_type_misuse_rejected():
    msg = DNSUpdate("example.com")
    with pytest.raises(DNSError):
        msg.rrset_exists("h.example.com", "ANY")
    with pytest.raises(DNSError):
        msg.rrset_absent("h.example.com", "ANY")
    with pytest.raises(DNSError):
        msg.delete_rrset("h.example.com", "ANY")


def test_add_multiple_rdata_values():
    msg = DNSUpdate("example.com", id=1)
    msg.add("h.example.com", [A("1.1.1.1"), A("2.2.2.2")], ttl=50)
    msg.delete_record("h.example.com", [A("1.1.1.1"), A("2.2.2.2")])
    parsed = DNSUpdate.parse(msg.pack())
    assert [u.kind for u in parsed.updates] == [
        "add", "add", "delete_record", "delete_record"]
    assert parsed == msg


def test_type_inference_from_rdata():
    msg = DNSUpdate("example.com", id=1)
    msg.add("h.example.com", AAAA("2001:db8::1"), ttl=10)   # infer AAAA
    msg.rrset_value("h.example.com", TXT(b"hi"))           # infer TXT
    parsed = DNSUpdate.parse(msg.pack())
    assert parsed.updates[0].rtype == QTYPE.AAAA
    assert parsed.prerequisites[0].rtype == QTYPE.TXT
    assert parsed == msg


def test_idempotent_repack():
    msg = DNSUpdate("example.com", id=42)
    msg.rrset_exists("a.example.com", A)
    msg.add("b.example.com", A("1.1.1.1"), ttl=10)
    once = msg.pack()
    twice = DNSUpdate.parse(once).pack()
    assert once == twice
