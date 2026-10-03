#!/usr/bin/env python
"""In-memory AXFR/IXFR application example."""

from __future__ import print_function

from dnslib import A,QTYPE,RR,SOA
from dnslib.ixfr import DNSZone,ZoneTransferError,apply_ixfr


def soa(serial):
    return RR("example.com.",QTYPE.SOA,ttl=3600,rdata=SOA(
        "ns.example.com.","admin.example.com.",
        (serial,7200,3600,1209600,3600)))


def a(name,address):
    return RR(name,QTYPE.A,ttl=300,rdata=A(address))


def show(label,zone):
    print(label,"serial",zone.serial)
    for record in zone.records:
        print(" ",record.toZone())


def main():
    zone = DNSZone([
        soa(4294967295),
        a("ns.example.com.","192.0.2.1"),
        a("old.example.com.","192.0.2.10"),
    ])

    ixfr = iter([
        soa(0),
        soa(4294967295),
        a("old.example.com.","192.0.2.10"),
        soa(0),
        a("new.example.com.","192.0.2.20"),
        a("new.example.com.","192.0.2.20"),
        soa(0),
    ])
    zone = apply_ixfr(zone,ixfr)
    show("After IXFR across 2**32:",zone)

    axfr = iter([
        soa(1),
        a("fresh.example.com.","198.51.100.5"),
        soa(1),
    ])
    zone = apply_ixfr(zone,axfr)
    show("After AXFR fallback:",zone)

    bad = iter([
        soa(2),
        soa(1),
        a("missing.example.com.","198.51.100.9"),
        soa(2),
        soa(2),
    ])
    try:
        apply_ixfr(zone,bad)
    except ZoneTransferError as error:
        print("Invalid IXFR rejected:",error)
    show("Original zone remains:",zone)


if __name__ == "__main__":
    main()
