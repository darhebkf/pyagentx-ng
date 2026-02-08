#!/usr/bin/env python3
"""Benchmark WALK throughput: snmpkit vs pysnmp."""

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
    bulk_walk_cmd,
)
from snmpkit.manager import Manager

SNMP_HOST = os.environ.get("SNMP_HOST", "localhost")
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")
WALK_OID = os.environ.get("WALK_OID", "1.3.6.1.2.1.1")


async def benchmark_snmpkit_walk(iterations: int = 10) -> tuple[list[float], int]:
    times = []
    count = 0
    async with Manager(SNMP_HOST, community=SNMP_COMMUNITY, timeout=10.0) as mgr:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            count = 0
            async for oid, value in mgr.bulk_walk(WALK_OID, bulk_size=25):
                count += 1
            end = time.perf_counter_ns()
            times.append((end - start) / 1_000_000)
    return times, count


async def benchmark_pysnmp_walk(iterations: int = 10) -> tuple[list[float], int]:
    times = []
    count = 0
    snmpEngine = SnmpEngine()
    transport = await UdpTransportTarget.create((SNMP_HOST, 161))

    for _ in range(iterations):
        start = time.perf_counter_ns()
        count = 0
        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            snmpEngine,
            CommunityData(SNMP_COMMUNITY),
            transport,
            ContextData(),
            0,
            25,
            ObjectType(ObjectIdentity(WALK_OID)),
        ):
            if errorIndication:
                raise RuntimeError(f"SNMP error: {errorIndication}")
            for varBind in varBinds:
                count += 1
        end = time.perf_counter_ns()
        times.append((end - start) / 1_000_000)

    return times, count


async def run_benchmarks():
    print("=" * 60)
    print("WALK Benchmark: snmpkit vs pysnmp")
    print(f"Target: {SNMP_HOST} (community: {SNMP_COMMUNITY})")
    print(f"Walking OID: {WALK_OID}")
    print("=" * 60)
    print()

    iterations = 10

    print("Warming up...")
    try:
        await benchmark_snmpkit_walk(1)
        await benchmark_pysnmp_walk(1)
    except Exception as e:
        print(f"Error: {e}")
        print()
        print("Ensure snmpd is running: sudo systemctl start snmpd")
        print("Or: SNMP_HOST=192.168.1.1 uv run python benchmarks/bench_walk.py")
        return None

    print(f"Running {iterations} iterations...")
    print()

    snmpkit_times, snmpkit_count = await benchmark_snmpkit_walk(iterations)
    snmpkit_mean = mean(snmpkit_times)
    snmpkit_std = stdev(snmpkit_times) if len(snmpkit_times) > 1 else 0

    pysnmp_times, pysnmp_count = await benchmark_pysnmp_walk(iterations)
    pysnmp_mean = mean(pysnmp_times)
    pysnmp_std = stdev(pysnmp_times) if len(pysnmp_times) > 1 else 0

    speedup = pysnmp_mean / snmpkit_mean if snmpkit_mean > 0 else 0

    print(f"OIDs walked per iteration: {snmpkit_count}")
    print()
    print(f"{'Library':<15} {'Mean (ms)':<15} {'Std Dev (ms)':<15} {'OIDs/sec':<15}")
    print("-" * 60)
    snmpkit_rate = (snmpkit_count / snmpkit_mean) * 1000 if snmpkit_mean > 0 else 0
    pysnmp_rate = (pysnmp_count / pysnmp_mean) * 1000 if pysnmp_mean > 0 else 0
    print(f"{'snmpkit':<15} {snmpkit_mean:<15.1f} {snmpkit_std:<15.1f} {snmpkit_rate:<15.0f}")
    print(f"{'pysnmp':<15} {pysnmp_mean:<15.1f} {pysnmp_std:<15.1f} {pysnmp_rate:<15.0f}")
    print()
    print(f"Speedup: {speedup:.1f}x faster")
    print()

    return {
        "snmpkit": {"mean": snmpkit_mean, "std": snmpkit_std, "count": snmpkit_count},
        "pysnmp": {"mean": pysnmp_mean, "std": pysnmp_std, "count": pysnmp_count},
        "speedup": speedup,
    }


if __name__ == "__main__":
    asyncio.run(run_benchmarks())
