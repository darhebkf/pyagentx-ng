#!/usr/bin/env python3
"""Benchmark BER encoding speed: snmpkit vs pysnmp."""

import time
from statistics import mean, stdev

# pysnmp imports
from pyasn1.codec.ber import encoder
from pyasn1.type import univ
from pysnmp.proto import api

# snmpkit imports
from snmpkit.core import Oid, encode_snmp_get_v2c

# Get SNMPv2c protocol module
pMod = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


def benchmark_snmpkit_encode(iterations: int = 10000) -> list[float]:
    """Benchmark snmpkit BER encoding."""
    oids = [Oid("1.3.6.1.2.1.1.1.0")]
    times = []

    for _ in range(iterations):
        start = time.perf_counter_ns()
        encode_snmp_get_v2c("public", 1, oids)
        end = time.perf_counter_ns()
        times.append((end - start) / 1000)  # Convert to microseconds

    return times


def benchmark_pysnmp_encode(iterations: int = 10000) -> list[float]:
    """Benchmark pysnmp BER encoding."""
    times = []

    for _ in range(iterations):
        start = time.perf_counter_ns()

        # Build PDU
        reqPDU = pMod.GetRequestPDU()
        pMod.apiPDU.set_defaults(reqPDU)
        pMod.apiPDU.set_varbinds(
            reqPDU,
            ((univ.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 1, 0)), pMod.Null()),),
        )

        # Build message
        reqMsg = pMod.Message()
        pMod.apiMessage.set_defaults(reqMsg)
        pMod.apiMessage.set_community(reqMsg, "public")
        pMod.apiMessage.set_pdu(reqMsg, reqPDU)

        # Encode
        encoder.encode(reqMsg)

        end = time.perf_counter_ns()
        times.append((end - start) / 1000)

    return times


def run_benchmarks():
    """Run all BER encoding benchmarks."""
    print("=" * 60)
    print("BER Encoding Benchmark: snmpkit vs pysnmp")
    print("=" * 60)
    print()

    # Warmup
    print("Warming up...")
    benchmark_snmpkit_encode(100)
    benchmark_pysnmp_encode(100)

    iterations = 10000
    print(f"Running {iterations} iterations...")
    print()

    # snmpkit
    snmpkit_times = benchmark_snmpkit_encode(iterations)
    snmpkit_mean = mean(snmpkit_times)
    snmpkit_std = stdev(snmpkit_times)

    # pysnmp
    pysnmp_times = benchmark_pysnmp_encode(iterations)
    pysnmp_mean = mean(pysnmp_times)
    pysnmp_std = stdev(pysnmp_times)

    # Results
    speedup = pysnmp_mean / snmpkit_mean

    print(f"{'Library':<15} {'Mean (us)':<15} {'Std Dev (us)':<15}")
    print("-" * 45)
    print(f"{'snmpkit':<15} {snmpkit_mean:<15.2f} {snmpkit_std:<15.2f}")
    print(f"{'pysnmp':<15} {pysnmp_mean:<15.2f} {pysnmp_std:<15.2f}")
    print()
    print(f"Speedup: {speedup:.1f}x faster")
    print()

    return {
        "snmpkit": {"mean": snmpkit_mean, "std": snmpkit_std},
        "pysnmp": {"mean": pysnmp_mean, "std": pysnmp_std},
        "speedup": speedup,
    }


if __name__ == "__main__":
    run_benchmarks()
