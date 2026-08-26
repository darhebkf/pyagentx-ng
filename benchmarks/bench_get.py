#!/usr/bin/env python3
"""Benchmark GET request latency: snmpkit vs pysnmp."""

import asyncio
import os
import time
from statistics import mean, stdev

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
)
from snmpkit.manager import Manager

SNMP_HOST = os.environ.get("SNMP_HOST", "localhost")
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")
OID = "1.3.6.1.2.1.1.1.0"


async def benchmark_snmpkit_get(iterations: int = 100) -> list[float]:
    times = []
    async with Manager(SNMP_HOST, community=SNMP_COMMUNITY, timeout=5.0) as mgr:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            await mgr.get(OID)
            end = time.perf_counter_ns()
            times.append((end - start) / 1_000_000)
    return times


async def benchmark_pysnmp_get(iterations: int = 100) -> list[float]:
    times = []
    snmpEngine = SnmpEngine()
    transport = await UdpTransportTarget.create((SNMP_HOST, 161))

    for _ in range(iterations):
        start = time.perf_counter_ns()
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            snmpEngine,
            CommunityData(SNMP_COMMUNITY),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(OID)),
        )
        end = time.perf_counter_ns()
        times.append((end - start) / 1_000_000)
        if errorIndication:
            raise RuntimeError(f"SNMP error: {errorIndication}")

    return times


async def run_benchmarks():
    print("=" * 60)
    print("GET Request Benchmark: snmpkit vs pysnmp")
    print(f"Target: {SNMP_HOST} (community: {SNMP_COMMUNITY})")
    print("=" * 60)
    print()

    iterations = 100

    print("Warming up...")
    try:
        await benchmark_snmpkit_get(5)
        await benchmark_pysnmp_get(5)
    except Exception as e:
        print(f"Error: {e}")
        print()
        print("Ensure snmpd is running: sudo systemctl start snmpd")
        print("Or: SNMP_HOST=192.168.1.1 pdm run python benchmarks/bench_get.py")
        return None

    print(f"Running {iterations} iterations...")
    print()

    snmpkit_times = await benchmark_snmpkit_get(iterations)
    snmpkit_mean = mean(snmpkit_times)
    snmpkit_std = stdev(snmpkit_times)

    pysnmp_times = await benchmark_pysnmp_get(iterations)
    pysnmp_mean = mean(pysnmp_times)
    pysnmp_std = stdev(pysnmp_times)

    speedup = pysnmp_mean / snmpkit_mean

    print(f"{'Library':<15} {'Mean (ms)':<15} {'Std Dev (ms)':<15}")
    print("-" * 45)
    print(f"{'snmpkit':<15} {snmpkit_mean:<15.3f} {snmpkit_std:<15.3f}")
    print(f"{'pysnmp':<15} {pysnmp_mean:<15.3f} {pysnmp_std:<15.3f}")
    print()
    print(f"Speedup: {speedup:.1f}x faster")
    print()

    return {
        "snmpkit": {"mean": snmpkit_mean, "std": snmpkit_std},
        "pysnmp": {"mean": pysnmp_mean, "std": pysnmp_std},
        "speedup": speedup,
    }


if __name__ == "__main__":
    asyncio.run(run_benchmarks())
