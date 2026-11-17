"""Measure the memory-mapped name index against the former in-memory dictionary.

Not part of ``npm run check``: ``scripts/measure-name-index.sh`` runs it after a
synthetic compile and prints one row per module.

Since:
    1.2.0
"""

from __future__ import annotations

import argparse
import json
import os
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any


def perf_name(position: int) -> str:
    """Return the invented name ``tests/perf-compile.php`` wrote at one position.

    Args:
        position: Name position.

    Returns:
        Name.

    Since:
        1.2.0
    """

    zone = position % 9973

    return f"host{position}.zone{zone}.example{zone % 17}.com"


def current_rss_bytes() -> int:
    """Return this process's resident set size.

    Returns:
        Resident bytes.

    Since:
        1.2.0
    """

    output = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    return int(output.strip()) * 1024


def load_module(module_path: Path, data_directory: Path) -> dict[str, Any]:
    """Execute one module source with stubbed Unbound globals.

    Args:
        module_path: Module source.
        data_directory: Generation directory.

    Returns:
        Module namespace.

    Since:
        1.2.0
    """

    namespace: dict[str, Any] = {}
    source = module_path.read_text(encoding="utf-8")
    exec(compile(source, str(module_path), "exec"), namespace)
    namespace["log_info"] = lambda message: None
    namespace["MAXIMUM_UNIQUE_NAMES"] = max(
        namespace["MAXIMUM_UNIQUE_NAMES"],
        10_000_000,
    )
    namespace["DATA_DIRECTORY"] = str(data_directory)
    namespace["MANIFEST_PATH"] = str(data_directory / "manifest.json")
    namespace["DOMAINS_PATH"] = str(data_directory / "domains.tsv")
    namespace["BYPASS_PATH"] = str(data_directory / "bypass.tsv")
    namespace["DOMAINS_INDEX_PATH"] = str(data_directory / "domains.index")
    namespace["BYPASS_INDEX_PATH"] = str(data_directory / "bypass.index")
    namespace["ALLOW_PATH"] = str(data_directory / "allow.txt")
    namespace["GENERATION_PATH"] = str(data_directory / "generation")

    return namespace


def queries(unique_names: int, count: int) -> list[str]:
    """Build a fixed mix of exact hits, subtree walks, and misses.

    Args:
        unique_names: Compiled name count.
        count: Query count.

    Returns:
        Query names.

    Since:
        1.2.0
    """

    generator = random.Random(20261116)
    names: list[str] = []

    for position in range(count):
        kind = position % 4

        if kind in (0, 1):
            names.append(perf_name(generator.randrange(unique_names)))
        elif kind == 2:
            subtree_position = generator.randrange(unique_names // 7) * 7
            names.append(f"cdn.edge.{perf_name(subtree_position)}")
        else:
            names.append(f"www.missing{generator.randrange(10**9)}.example.org")

    return names


def measure(module_path: Path, data_directory: Path, query_count: int) -> dict[str, Any]:
    """Load one generation, then time lookups through the module's policy object.

    Args:
        module_path: Module source.
        data_directory: Generation directory.
        query_count: Lookup count.

    Returns:
        Measurements.

    Since:
        1.2.0
    """

    namespace = load_module(module_path, data_directory)
    manifest = json.loads((data_directory / "manifest.json").read_text(encoding="utf-8"))
    names = queries(manifest["domain_count"], query_count)
    rss_before = current_rss_bytes()
    started_at = time.perf_counter()
    data = namespace["_load_data"](None)
    load_seconds = time.perf_counter() - started_at
    rss_after_load = current_rss_bytes()

    tracemalloc.start()

    traced_data = namespace["_load_data"](None)
    traced_current, traced_peak = tracemalloc.get_traced_memory()

    tracemalloc.stop()

    close = getattr(traced_data, "close", None)

    if close is not None:
        close()

    del traced_data
    listed = 0
    started_at = time.perf_counter()

    for name in names:
        if data.listed_mask(name) != 0:
            listed += 1

    listed_seconds = time.perf_counter() - started_at
    started_at = time.perf_counter()

    for name in names:
        data.is_listed(name)
        data.has_bypass_policy_name(name)
        decision, _mask = data.decision_details(name, None, None)

        if decision != "allow":
            data.bypass_blocks_name(name, "lan")

    query_seconds = time.perf_counter() - started_at
    rss_after_queries = current_rss_bytes()

    return {
        "module": module_path.name,
        "unique_names": manifest["domain_count"],
        "load_seconds": round(load_seconds, 2),
        "tracemalloc_current_bytes": traced_current,
        "tracemalloc_peak_bytes": traced_peak,
        "rss_load_delta_bytes": rss_after_load - rss_before,
        "rss_after_load_bytes": rss_after_load,
        "rss_after_queries_bytes": rss_after_queries,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        * (1 if sys.platform == "darwin" else 1024),
        "listed_fraction": round(listed / len(names), 3),
        "listed_mask_microseconds": round(listed_seconds / len(names) * 1e6, 2),
        "query_path_microseconds": round(query_seconds / len(names) * 1e6, 2),
    }


def baseline_directory(data_directory: Path, temporary_directory: Path) -> Path:
    """Expose the same generation to the former module under its schema-3 manifest.

    Args:
        data_directory: Generation directory.
        temporary_directory: Scratch directory.

    Returns:
        Baseline generation directory.

    Since:
        1.2.0
    """

    target = temporary_directory / "baseline"
    target.mkdir()

    for filename in ("domains.tsv", "bypass.tsv", "allow.txt", "generation"):
        os.symlink(data_directory.resolve() / filename, target / filename)

    manifest = json.loads((data_directory / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = 3
    manifest.pop("domain_index", None)
    manifest.pop("bypass_index", None)
    (target / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    return target


def main() -> int:
    """Run one measurement, or both modules in separate processes.

    Returns:
        Exit status.

    Since:
        1.2.0
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--baseline-module", type=Path)
    parser.add_argument("--queries", type=int, default=100_000)
    parser.add_argument("--single", action="store_true")
    arguments = parser.parse_args()

    if arguments.single:
        print(json.dumps(measure(arguments.module, arguments.data, arguments.queries)))

        return 0

    runs = [(arguments.module, arguments.data)]
    temporary_directory = Path(tempfile.mkdtemp(prefix="sinkhole-perf-"))

    try:
        if arguments.baseline_module is not None:
            runs.append(
                (
                    arguments.baseline_module,
                    baseline_directory(arguments.data, temporary_directory),
                )
            )

        for module_path, data_directory in runs:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    __file__,
                    "--single",
                    "--module",
                    str(module_path),
                    "--data",
                    str(data_directory),
                    "--queries",
                    str(arguments.queries),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            print(completed.stdout.strip())
    finally:
        shutil.rmtree(temporary_directory)

    return 0


if __name__ == "__main__":
    sys.exit(main())
