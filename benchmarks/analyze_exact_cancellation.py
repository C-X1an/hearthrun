#!/usr/bin/env python3
"""Add exact userspace CLOCK_MONOTONIC receipt/write brackets to validated B-03 evidence.

Always validates the existing cleanup/population evidence first. The observer
never establishes cgroup emptiness, launcher reaping or descendant disappearance.
Instrumented and normal artifact measurements are distinct populations.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import analyze_cancellation as base
from analyze import lines, parse, read, require
from cancel_timing import FEATURE, load_trace, validate_trace


def compare_exact(work):
    original = base.compare_population(work)
    require(original["status"] == "PASS", "original B-03 cleanup/population validation failed")
    environment = parse(read(work / "environment.json"))
    schedule = parse(read(work / "schedule.json"))
    require(environment.get("exact_timing", {}).get("feature") == FEATURE
            and environment["build"].get("verification_features") == [FEATURE]
            and environment["clock"] == "clock_gettime(CLOCK_MONOTONIC)", "not a matching instrumented artifact")
    clock_identity = environment["exact_timing"]["clock_identity"]
    require(clock_identity["boot_id"] == environment["boot_id"], "harness boot identity differs")
    samples = lines(read(work / "samples.jsonl"))
    require(all(row["status"] == "PASS" for row in samples), "failed samples cannot supply complete exact evidence")
    planned = {row["job_id"]: row for row in samples}
    require(len(planned) == len(samples), "client job identity is ambiguous")
    teardowns = [row for row in lines(read(work / "events.jsonl")) if row["type"] == "shard_teardown"]
    observed, seen, hashes = [], set(), {}
    for teardown in teardowns:
        shard = f"shard-{teardown['shard']:04d}"
        path = work / shard / "cancel-timing.jsonl"
        records, trace_digest = load_trace(path)
        jobs = {row.get("job_id") for row in records[1:-1]}
        require(jobs <= planned.keys(), "trace contains unknown job identity")
        subset = [planned[job] for job in jobs]
        require(len(subset) == teardown["jobs"], "trace changed the per-shard denominator")
        rows = validate_trace(records, subset, run_id=schedule["run_id"], shard=shard, clock_identity=clock_identity)
        owner = teardown.get("exact_timing_supervisor_exit")
        require(isinstance(owner, dict) and type(owner.get("pid")) is int and owner["pid"] > 0
                and type(owner.get("exit_code")) is int and owner["exit_code"] == 0
                and records[0].get("pid") == owner["pid"],
                "missing or unsuccessful owned supervisor exit evidence")
        require(not seen.intersection(row["sample_index"] for row in rows), "sample appeared in multiple trace sessions")
        seen.update(row["sample_index"] for row in rows)
        observed.extend(rows)
        hashes[shard] = trace_digest
    require(seen == {row["sample_index"] for row in samples}, "exact trace population is incomplete")
    by_index = {row["sample_index"]: row for row in samples}
    groups = defaultdict(list)
    for row in observed:
        sample = by_index[row["sample_index"]]
        groups[(sample["workload"], sample["concurrency"])].append(row)
    return {"status": "PASS", "mode": original["mode"], "population": "explicitly instrumented test-feature artifact only",
        "original_cleanup_analysis": original, "trace_sha256": hashes,
        "semantics": "userspace observation after complete authenticated EOF; bracket of owned File::write request, not kernel syscall entry or kill completion",
        "raw_clocks": sorted(observed, key=lambda row: row["sample_index"]),
        "groups": [{"workload": workload, "concurrency": concurrency, "count": len(rows),
                    **{key: base.ranks([row[key] for row in rows]) for key in
                       ("receipt_to_write_begin_ns", "write_bracket_ns", "receipt_to_cleanup_ns")}}
                   for (workload, concurrency), rows in sorted(groups.items())]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    try:
        print(json.dumps(compare_exact(parser.parse_args().work), indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
