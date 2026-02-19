#!/usr/bin/env python3
"""Run all snmpkit benchmarks."""

import asyncio
import json
from datetime import datetime

from benchmarks.bench_ber import run_benchmarks as run_ber
from benchmarks.bench_get import run_benchmarks as run_get
from benchmarks.bench_walk import run_benchmarks as run_walk


async def main():
    """Run all benchmarks and generate report."""
    print()
    print("=" * 70)
    print("  snmpkit Benchmark Suite")
    print(f"  {datetime.now().isoformat()}")
    print("=" * 70)
    print()

    results = {}

    # BER encoding (no network required)
    print()
    results["ber"] = run_ber()

    # GET requests (requires SNMP target)
    print()
    get_results = await run_get()
    if get_results:
        results["get"] = get_results

    # WALK (requires SNMP target)
    print()
    walk_results = await run_walk()
    if walk_results:
        results["walk"] = walk_results

    # Summary
    print()
    print("=" * 70)
    print("  Summary")
    print("=" * 70)
    print()
    print(f"{'Benchmark':<20} {'snmpkit':<15} {'pysnmp':<15} {'Speedup':<10}")
    print("-" * 60)

    if "ber" in results:
        r = results["ber"]
        print(
            f"{'BER encode':<20} {r['snmpkit']['mean']:.1f}us{'':<8} "
            f"{r['pysnmp']['mean']:.1f}us{'':<8} {r['speedup']:.1f}x"
        )

    if "get" in results:
        r = results["get"]
        print(
            f"{'GET request':<20} {r['snmpkit']['mean']:.2f}ms{'':<7} "
            f"{r['pysnmp']['mean']:.2f}ms{'':<7} {r['speedup']:.1f}x"
        )

    if "walk" in results:
        r = results["walk"]
        print(
            f"{'WALK':<20} {r['snmpkit']['mean']:.1f}ms{'':<8} "
            f"{r['pysnmp']['mean']:.1f}ms{'':<8} {r['speedup']:.1f}x"
        )

    print()

    # Save results (append to manager.runs)
    output_file = "benchmarks/results.json"
    try:
        with open(output_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"agent": {}, "manager": {"runs": []}}

    if "manager" not in data:
        data["manager"] = {"runs": []}

    data["manager"]["runs"].append(
        {
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }
    )

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {output_file} ({len(data['manager']['runs'])} manager runs)")
    print()

    return results


if __name__ == "__main__":
    asyncio.run(main())
