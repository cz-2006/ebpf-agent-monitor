#!/usr/bin/env python3
"""Summarize paired performance result files."""

import statistics
import sys
from pathlib import Path

PHASE_ORDER = (
    "total_ns",
    "active_ns",
    "wait_ns",
    "cpu_ns",
    "file_ns",
    "network_ns",
    "process_ns",
)


def read_results(path: Path) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = dict(field.split("=", 1) for field in line.split())
        phases = {name for name in fields if name.endswith("_ns")}
        if not values:
            values = {phase: [] for phase in PHASE_ORDER if phase in phases}
        if phases.intersection(PHASE_ORDER) != set(values):
            raise ValueError(f"inconsistent timing fields in {path}")
        for phase in values:
            values[phase].append(int(fields[phase]))
    if not values or not values.get("total_ns"):
        raise ValueError(f"no results in {path}")
    return values


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: performance_report.py BASELINE MONITORED")

    baseline = read_results(Path(sys.argv[1]))
    monitored = read_results(Path(sys.argv[2]))
    if len(baseline["total_ns"]) != len(monitored["total_ns"]):
        raise SystemExit("baseline and monitored run counts differ")

    print(f"runs={len(baseline['total_ns'])}")
    if set(baseline) != set(monitored):
        raise SystemExit("baseline and monitored timing fields differ")

    for phase in baseline:
        base_median = statistics.median(baseline[phase]) / 1_000_000
        monitored_median = statistics.median(monitored[phase]) / 1_000_000
        overhead = (monitored_median / base_median - 1.0) * 100.0
        paired = [
            (monitored_value / baseline_value - 1.0) * 100.0
            for baseline_value, monitored_value
            in zip(baseline[phase], monitored[phase])
        ]
        print(
            f"phase={phase.removesuffix('_ns')} "
            f"baseline_median_ms={base_median:.3f} "
            f"monitored_median_ms={monitored_median:.3f} "
            f"overhead_percent={overhead:.2f} "
            f"paired_overhead_median_percent={statistics.median(paired):.2f} "
            f"paired_overhead_p25_percent={percentile(paired, 0.25):.2f} "
            f"paired_overhead_p75_percent={percentile(paired, 0.75):.2f}"
        )


if __name__ == "__main__":
    main()
