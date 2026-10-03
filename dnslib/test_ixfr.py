from __future__ import print_function

import pytest

from dnslib import A
from dnslib.dns import DNSRecord,QTYPE,RR,SOA
from dnslib.ixfr import DNSZone,ZoneTransferError,apply_ixfr,serial_lt


ORIGIN = "example.com."


def soa(serial,ttl=3600):
    return RR(ORIGIN,QTYPE.SOA,ttl=ttl,rdata=SOA(
        "ns.example.com.",
        "admin.example.com.",
        (serial,7200,3600,1209600,3600)))


def rr(name,address,ttl=300):
    return RR(name,QTYPE.A,ttl=ttl,rdata=A(address))


def rrset(zone):
    return {(str(record.rname),record.rtype,str(record.rdata))
            for record in zone.records
            if record.rtype != QTYPE.SOA}


def initial_zone():
    return DNSZone([
        soa(4294967295),
        rr("ns.example.com.","192.0.2.1"),
        rr("old.example.com.","192.0.2.10"),
    ])


def single_ixfr(old,new):
    return iter([
        soa(new),
        soa(old),
        rr("old.example.com.","192.0.2.10"),
        soa(new),
        rr("new.example.com.","192.0.2.20"),
        rr("new.example.com.","192.0.2.20"),
        soa(new),
    ])


def test_rfc1982_serial_wrapping():
    assert serial_lt(4294967295,0)
    assert serial_lt(0,1)
    assert not serial_lt(0,4294967295)
    assert not serial_lt(1,1)


def test_apply_single_ixfr_with_iterator_and_duplicate_add():
    old_zone = initial_zone()

    new_zone = apply_ixfr(old_zone,single_ixfr(4294967295,0))

    assert new_zone.serial == 0
    assert rrset(new_zone) == {
        ("ns.example.com.",QTYPE.A,"192.0.2.1"),
        ("new.example.com.",QTYPE.A,"192.0.2.20"),
    }
    assert old_zone.serial == 4294967295
    assert rrset(old_zone) == {
        ("ns.example.com.",QTYPE.A,"192.0.2.1"),
        ("old.example.com.",QTYPE.A,"192.0.2.10"),
    }


def test_duplicate_delete_is_idempotent_and_duplicate_add_updates_ttl():
    old_zone = initial_zone()
    records = iter([
        soa(0,3601),
        soa(4294967295),
        rr("old.example.com.","192.0.2.10"),
        rr("old.example.com.","192.0.2.10"),
        soa(0,3601),
        rr("new.example.com.","192.0.2.20",300),
        rr("new.example.com.","192.0.2.20",900),
        soa(0,3601),
    ])

    new_zone = apply_ixfr(old_zone,records)
    added = [record for record in new_zone
             if str(record.rname) == "new.example.com."]

    assert len(added) == 1
    assert added[0].ttl == 900


def test_apply_multiple_ixfr_deltas_in_one_response():
    old_zone = initial_zone()
    sequence = iter([
        soa(1),
        soa(4294967295),
        rr("old.example.com.","192.0.2.10"),
        soa(0),
        rr("zero.example.com.","192.0.2.20"),
        soa(0),
        soa(0),
        rr("zero.example.com.","192.0.2.20"),
        soa(1),
        rr("one.example.com.","192.0.2.21"),
        soa(1),
    ])

    new_zone = apply_ixfr(old_zone,sequence)

    assert new_zone.serial == 1
    assert rrset(new_zone) == {
        ("ns.example.com.",QTYPE.A,"192.0.2.1"),
        ("one.example.com.",QTYPE.A,"192.0.2.21"),
    }


def test_empty_ixfr_delta_only_advances_serial():
    old_zone = initial_zone()
    records = iter([
        soa(0),
        soa(4294967295),
        soa(0),
        soa(0),
    ])

    new_zone = apply_ixfr(old_zone,records)

    assert new_zone.serial == 0
    assert rrset(new_zone) == rrset(old_zone)


def test_final_soa_mismatch_is_rejected():
    old_zone = initial_zone()
    records = iter([
        soa(1),
        soa(4294967295),
        soa(0),
        soa(0),
    ])

    with pytest.raises(ZoneTransferError,match="final SOA"):
        apply_ixfr(old_zone,records)


def test_accepts_dns_record_containing_answer_sequence():
    old_zone = initial_zone()
    response = DNSRecord(q=DNSRecord.question(ORIGIN,"IXFR").q)
    response.add_answer(*list(single_ixfr(4294967295,0)))

    new_zone = old_zone.apply_ixfr(response)

    assert new_zone.serial == 0
    assert ("new.example.com.",QTYPE.A,"192.0.2.20") in rrset(new_zone)


def test_missing_delete_target_is_atomic_failure():
    old_zone = initial_zone()
    records = iter([
        soa(0),
        soa(4294967295),
        rr("missing.example.com.","192.0.2.99"),
        soa(0),
        soa(0),
    ])

    with pytest.raises(ZoneTransferError,match="delete target"):
        apply_ixfr(old_zone,records)

    assert old_zone.serial == 4294967295
    assert rrset(old_zone) == {
        ("ns.example.com.",QTYPE.A,"192.0.2.1"),
        ("old.example.com.",QTYPE.A,"192.0.2.10"),
    }


def test_truncated_ixfr_does_not_change_zone():
    old_zone = initial_zone()

    with pytest.raises(ZoneTransferError,match="Truncated IXFR"):
        apply_ixfr(old_zone,iter([
            soa(0),
            soa(4294967295),
            rr("old.example.com.","192.0.2.10"),
            soa(0),
        ]))

    assert old_zone.serial == 4294967295
    assert ("old.example.com.",QTYPE.A,"192.0.2.10") in rrset(old_zone)


def test_noncontiguous_version_chain_rejected():
    old_zone = initial_zone()

    with pytest.raises(ZoneTransferError,match="contiguous"):
        apply_ixfr(old_zone,iter([
            soa(1),
            soa(4294967295),
            soa(0),
            rr("zero.example.com.","192.0.2.20"),
            soa(0),
            soa(4294967295),
            soa(1),
            soa(1),
        ]))


def test_axfr_is_full_replacement_not_delete_set():
    old_zone = initial_zone()
    records = iter([
        soa(100),
        rr("fresh.example.com.","198.51.100.5"),
        soa(100),
    ])

    new_zone = apply_ixfr(old_zone,records)

    assert new_zone.serial == 100
    assert rrset(new_zone) == {
        ("fresh.example.com.",QTYPE.A,"198.51.100.5"),
    }
    assert ("old.example.com.",QTYPE.A,"192.0.2.10") not in rrset(new_zone)
    assert ("ns.example.com.",QTYPE.A,"192.0.2.1") not in rrset(new_zone)


def test_empty_axfr_is_full_replacement():
    old_zone = initial_zone()

    new_zone = apply_ixfr(old_zone,iter([soa(100),soa(100)]))

    assert new_zone.serial == 100
    assert rrset(new_zone) == set()
    assert len(new_zone) == 1


def test_failed_axfr_keeps_original_zone():
    old_zone = initial_zone()

    with pytest.raises(ZoneTransferError,match="Truncated AXFR"):
        apply_ixfr(old_zone,iter([soa(100),rr("fresh.example.com.","198.51.100.5")]))

    assert old_zone.serial == 4294967295
    assert rrset(old_zone) == {
        ("ns.example.com.",QTYPE.A,"192.0.2.1"),
        ("old.example.com.",QTYPE.A,"192.0.2.10"),
    }
