#!/usr/bin/env python3
"""Benchmark MIB loading: snmpkit vs pysmi.

Parsing is a one-time startup cost, so the numbers that matter are wall-clock
to get a set of MIBs into a queryable state and the memory the result holds.
Lookup is measured too, but at sub-microsecond it never competes with a UDP
round trip.

Both parsers are given the identical module list and the identical search
path, and per-module timings are reported only over the modules each actually
resolved.
"""

import gc
import os
import resource
import time
from pathlib import Path
from statistics import mean, stdev

# The vendored fixtures are dependency-closed: every IMPORT they make is
# satisfied inside the set. Comparing on an arbitrary slice of a big corpus
# measures import failures, not parsing.
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "mibs" / "smiv2"
CORPUS = Path("/usr/share/snmp/mibs")
# A single parse is milliseconds, so one sample is mostly noise.
RUNS = int(os.environ.get("MIB_RUNS", "7"))


def _rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def _source_dirs() -> list[Path]:
    if not CORPUS.is_dir():
        return [FIXTURES]
    dirs = [CORPUS] + [p for p in sorted(CORPUS.iterdir()) if p.is_dir()]
    return dirs


def _module_set(dirs: list[Path]) -> dict[str, Path]:
    """Module name -> file, preferring the first directory that defines it."""
    found: dict[str, Path] = {}
    for d in dirs:
        for f in sorted(d.iterdir()):
            if f.is_file() and f.name not in found:
                found[f.name] = f
    return found


def benchmark_snmpkit(modules: dict[str, Path], names: list[str]) -> dict:
    """Parse and resolve exactly `names` with snmpkit."""
    from snmpkit.mib import MibTree

    paths = [str(modules[n]) for n in names]

    def once() -> tuple[float, float, "MibTree"]:
        tree = MibTree()
        start = time.perf_counter()
        for path in paths:
            tree.load_file(path)
        parse = time.perf_counter() - start
        start = time.perf_counter()
        tree.lookup("sysUpTime")  # first query builds the resolved tree
        return parse, time.perf_counter() - start, tree

    once()  # warm the page cache so the first timed run is not an outlier

    gc.collect()
    before = _rss_mb()
    parses, resolves = [], []
    for _ in range(RUNS):
        parse, resolve, tree = once()
        parses.append(parse)
        resolves.append(resolve)
    memory = _rss_mb() - before

    loaded = len(paths)
    parse = mean(parses)
    resolve = mean(resolves)
    totals = [p + r for p, r in zip(parses, resolves)]

    iterations = 100_000
    probe = next((n for n in ("sysDescr", "ifDescr") if n in tree), None)
    lookup_ns = 0.0
    if probe:
        start = time.perf_counter()
        for _ in range(iterations):
            tree.lookup(probe)
        lookup_ns = (time.perf_counter() - start) / iterations * 1e9

    return {
        "modules": loaded,
        "nodes": len(tree),
        "parse": parse,
        "resolve": resolve,
        "total": mean(totals),
        "std": stdev(totals) if len(totals) > 1 else 0.0,
        "memory_mb": memory,
        "lookup_ns": lookup_ns,
        "runs": RUNS,
    }


def benchmark_pysmi(dirs: list[Path], names: list[str]) -> dict | None:
    """Compile exactly `names` with pysmi, given the same search path."""
    try:
        from pysmi.codegen import JsonCodeGen
        from pysmi.compiler import MibCompiler
        from pysmi.parser import SmiV1CompatParser
        from pysmi.reader import FileReader
        from pysmi.searcher import StubSearcher
        from pysmi.writer import CallbackWriter
    except ImportError:
        print("pysmi not installed, skipping comparison")
        return None

    def once() -> tuple[float, int]:
        out: dict[str, str] = {}
        compiler = MibCompiler(
            SmiV1CompatParser(),
            JsonCodeGen(),
            CallbackWriter(lambda name, data, ctx: out.__setitem__(name, data)),
        )
        compiler.add_sources(*[FileReader(str(d)) for d in dirs])
        compiler.add_searchers(StubSearcher(*JsonCodeGen.baseMibs))
        results = compiler.compile(*names)
        done = sum(1 for st in results.values() if st in ("compiled", "untouched"))
        start = time.perf_counter()
        return start, done

    # pysmi caches parsed modules on the compiler, so each run gets a fresh one.
    totals, done = [], 0
    once()
    gc.collect()
    before = _rss_mb()
    for _ in range(RUNS):
        start = time.perf_counter()
        _, done = once()
        totals.append(time.perf_counter() - start)
    memory = _rss_mb() - before

    return {
        "modules": done,
        "requested": len(names),
        "total": mean(totals),
        "std": stdev(totals) if len(totals) > 1 else 0.0,
        "memory_mb": memory,
        "runs": RUNS,
    }


def run_benchmarks() -> dict:
    """Compare MIB loading between snmpkit and pysmi."""
    print("=" * 70)
    print("  MIB parsing: snmpkit vs pysmi")
    print("=" * 70)
    print()

    dirs = [FIXTURES]
    modules = _module_set(dirs)
    names = sorted(modules)
    print(f"Module set  : {len(names)} dependency-closed modules, identical for both parsers")
    print(f"              {', '.join(names)}")
    print()

    snmpkit_result = benchmark_snmpkit(modules, names)
    print(
        f"{'snmpkit':<10} {snmpkit_result['modules']}/{len(names)} modules, "
        f"{snmpkit_result['nodes']} nodes"
    )
    print(
        f"{'':<10} parse {snmpkit_result['parse'] * 1000:.1f}ms + resolve "
        f"{snmpkit_result['resolve'] * 1000:.1f}ms = "
        f"{snmpkit_result['total'] * 1000:.1f}ms "
        f"+/- {snmpkit_result['std'] * 1000:.1f}ms  ({snmpkit_result['runs']} runs)"
    )
    print(
        f"{'':<10} {snmpkit_result['memory_mb']:.0f} MB, "
        f"lookup {snmpkit_result['lookup_ns']:.0f} ns"
    )
    print()

    pysmi_result = benchmark_pysmi(dirs, names)
    out = {"snmpkit": snmpkit_result, "sample": len(names)}
    if pysmi_result:
        print(f"{'pysmi':<10} {pysmi_result['modules']}/{pysmi_result['requested']} modules")
        print(
            f"{'':<10} {pysmi_result['total'] * 1000:.1f}ms "
            f"+/- {pysmi_result['std'] * 1000:.1f}ms  ({pysmi_result['runs']} runs), "
            f"{pysmi_result['memory_mb']:.0f} MB"
        )
        print()

        per_snmpkit = snmpkit_result["total"] / max(snmpkit_result["modules"], 1)
        per_pysmi = pysmi_result["total"] / max(pysmi_result["modules"], 1)
        print(
            f"{'':<10} per resolved module: snmpkit {per_snmpkit * 1000:.2f}ms, "
            f"pysmi {per_pysmi * 1000:.2f}ms"
        )
        print(f"Speedup: {per_pysmi / per_snmpkit:.1f}x faster per module")
        print()
        out["pysmi"] = pysmi_result
        out["speedup"] = per_pysmi / per_snmpkit

    # Scale: the whole Net-SNMP corpus, snmpkit only. pysmi at ~0.7s a module
    # would take the best part of an hour, so there is nothing to compare to.
    if CORPUS.is_dir():
        from snmpkit.mib import MibTree

        gc.collect()
        before = _rss_mb()
        start = time.perf_counter()
        tree = MibTree()
        loaded = tree.load_dir(str(CORPUS))
        tree.lookup("sysUpTime")
        elapsed = time.perf_counter() - start
        print("-" * 70)
        print(f"{'scale':<10} snmpkit alone over {CORPUS}")
        print(
            f"{'':<10} {loaded} modules, {len(tree)} nodes, "
            f"{elapsed:.3f}s, {_rss_mb() - before:.0f} MB"
        )
        print()
        out["corpus"] = {
            "modules": loaded,
            "nodes": len(tree),
            "total": elapsed,
            "memory_mb": _rss_mb() - before,
        }

    return out


if __name__ == "__main__":
    run_benchmarks()
