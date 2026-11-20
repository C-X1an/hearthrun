#!/usr/bin/env python3
"""Validate retained campaign identities/schedule and recompute all populations."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys
import tarfile


MAX_FILE = 128 * 1024 * 1024
MAX_LINE = 16 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
KEYS = ("workload", "phase", "backend", "batch", "seed", "bytes", "concurrency", "sample_index")


def compacted_shard(work: Path, rows: list[dict]) -> None:
    """Check a lossless aggregate without extracting or trusting archive paths."""
    raw_index = read(work / "transients-index.json")
    index = parse(raw_index)
    completion = parse(read(work / "compaction.json"))
    require(index["format"] == "hearthrun-shard-tar-gzip-v1" and index["status"] == "PASS"
            and completion["status"] == "PASS" and completion["originals_removed"] is True
            and completion["index_sha256"] == hashlib.sha256(raw_index).hexdigest(), "invalid shard compaction completion")
    archive_path = work / "transients.tar.gz"
    require(hashlib.sha256(read(archive_path)).hexdigest() == index["archive_sha256"], "shard archive digest differs")
    entries = index["entries"]
    require(isinstance(entries, list) and 0 < len(entries) <= 12_000
            and completion["entries"] == len(entries), "invalid compacted inventory count")
    identities = set()
    total = 0
    files = {}
    for entry in entries:
        path = entry["path"]
        require(isinstance(path, str) and path and "\\" not in path and not path.startswith("/")
                and all(part not in {"", ".", ".."} for part in path.split("/"))
                and path.split("/")[0] in {"state", "logs", "tmp", "data.ndjson"}, "invalid compacted path")
        require(path not in identities, "duplicate compacted path")
        identities.add(path)
        require(entry["type"] in {"file", "directory", "stale_socket"}, "invalid compacted entry type")
        require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o7777
                and not entry["mode"] & 0o022, "invalid compacted entry mode")
        require(type(entry["size"]) is int and 0 <= entry["size"] <= 64 * 1024 * 1024, "invalid compacted size")
        require(not (work / path).exists() and not (work / path).is_symlink(), "compacted original unexpectedly remains")
        if entry["type"] == "file":
            require(isinstance(entry["sha256"], str) and DIGEST.fullmatch(entry["sha256"]), "invalid content digest")
            total += entry["size"]
            files[path] = entry
        else:
            require(entry["size"] == 0, "nonfile compacted bytes")
            if entry["type"] == "stale_socket":
                require(path == "state/control.sock" and entry["mode"] == 0o600, "unexpected compacted special entry")
    require(total == index["content_bytes"] == completion["content_bytes"] and total <= 128 * 1024 * 1024,
            "compacted content bound/count differs")
    with tarfile.open(archive_path, "r|gz") as archive:
        for entry in entries:
            if entry["type"] == "stale_socket":
                continue
            item = archive.next()
            require(item is not None and item.name.rstrip("/") == entry["path"] and item.mode == entry["mode"],
                    "archive/index inventory differs")
            if entry["type"] == "directory":
                require(item.isdir() and item.size == 0, "invalid archive directory")
            else:
                require(item.isfile() and item.size == entry["size"], "invalid archive file")
                stream = archive.extractfile(item)
                require(stream is not None, "archive file content missing")
                with stream:
                    require(hashlib.sha256(stream.read(64 * 1024 * 1024 + 1)).hexdigest() == entry["sha256"],
                            "compacted content digest differs")
        require(archive.next() is None, "unindexed archive member")
    # Preserve independently checked bytes even when normal runtime retention
    # evicted older bundles before this shard stopped.
    native_rows = {row["run_id"]: row for row in rows if row["backend"] == "native"}
    verified = lines(read(work / "verified-results.jsonl")) if native_rows else []
    require(len({value["run_id"] for value in verified}) == len(verified)
            and {value["run_id"] for value in verified} == set(native_rows), "verified-result identities differ")
    reference = parse(read(work / "input.json"))["reference"] if rows else None
    for value in verified:
        row = native_rows[value["run_id"]]
        require(row["status"] == "PASS" and value["job_id"] == row["job_id"], "invalid verified native identity")
        raw = bytes.fromhex(value["metadata_hex"])
        stdout, stderr = bytes.fromhex(value["stdout_hex"]), bytes.fromhex(value["stderr_hex"])
        require(len(raw) <= 64 * 1024 and not stdout and not stderr, "invalid verified native metadata/streams")
        metadata, record = parse(raw), value["record"]
        bundle = hashlib.sha256(b"HearthRun result bundle v1\0" + len(raw).to_bytes(8, "big") + raw
            + len(stdout).to_bytes(8, "big") + hashlib.sha256(stdout).hexdigest().encode("ascii")
            + len(stderr).to_bytes(8, "big") + hashlib.sha256(stderr).hexdigest().encode("ascii")).hexdigest()
        require(bundle == value["result_digest"] == row["output_digest"] == record["result_digest"]
                and metadata["job_id"] == record["job_id"] == row["job_id"]
                and metadata["status"] == record["state"] == "SUCCEEDED"
                and metadata["cleanup_confirmed"] is record["cleanup_confirmed"] is True
                and record["policy_digest"] == row["policy_digest"], "verified bundle/record differs from observation")
        retained = files.get(f"state/results/{row['job_id']}/result.json")
        eviction = files.get(f"state/evicted/{row['job_id']}")
        require((retained is not None and retained["sha256"] == hashlib.sha256(raw).hexdigest())
                or (eviction is not None and eviction["sha256"] == hashlib.sha256(bundle.encode()).hexdigest()),
                "verified bundle lacks matching retained metadata or eviction marker")
        artifacts = value["artifacts"]
        if row["workload"] == "B-02":
            require(len(artifacts) == 1 and artifacts[0]["path"] == "summary.json", "verified transform artifact set differs")
            content = bytes.fromhex(artifacts[0]["content_hex"])
            artifact_digest = hashlib.sha256(content).hexdigest()
            require(len(content) <= 1024 and artifact_digest == artifacts[0]["sha256"] == row["artifact_sha256"]
                    and parse(content) == row["verified_output"] == {key: reference[key] for key in ("count", "sum")}
                    and metadata["artifacts"] == [{"path": "summary.json", "sha256": artifact_digest, "size_bytes": len(content)}],
                    "verified transform differs from observed output/oracle")
            retained_artifact = files.get(f"state/results/{row['job_id']}/artifacts/summary.json")
            require(retained_artifact is not None and retained_artifact["sha256"] == artifact_digest or eviction is not None,
                    "transform artifact lacks retained bytes or eviction marker")
        else:
            require(not artifacts and metadata["artifacts"] == [], "empty result contains artifacts")


def storage_evidence(work: Path, schedule: dict, samples: list[dict], teardown_paths: list[Path]) -> None:
    policy = schedule["storage_policy"]
    require(policy["format"] == "hearthrun-shard-tar-gzip-v1" and policy["headroom_bytes"] == 256 * 1024 * 1024
            and policy["headroom_inodes"] == 16_384 and policy["retained_bytes_bound"] == 2_000_000_000,
            "storage policy differs")
    observations = lines(read(work / "storage.jsonl"))
    contexts = {row["context"] for row in observations}
    require(len(contexts) == len(observations), "duplicate storage checkpoint")
    for value in observations:
        require(value["required_bytes"] == policy["headroom_bytes"]
                and value["required_inodes"] == policy["headroom_inodes"]
                and value["available_bytes"] >= value["required_bytes"]
                and value["available_inodes"] >= value["required_inodes"]
                and value["retained_accounted_bytes"] <= policy["retained_bytes_bound"], "insufficient recorded storage headroom")
    for path in teardown_paths:
        number = int(path.parent.name.split("-")[1])
        require(f"before-shard-{number:04d}" in contexts, "shard lacks storage preflight")
        rows = [row for row in samples if row["shard"] == number]
        summary = parse(read(path.parent / "shard-summary.json"))
        encoded = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode() for row in rows)
        require(summary["shard"] == number and summary["samples"] == len(rows)
                and summary["run_ids"] == [row["run_id"] for row in rows]
                and summary["rows_sha256"] == hashlib.sha256(encoded).hexdigest(), "shard summary differs from raw samples")
        if summary["status"] == "PASS":
            require(all(row["status"] == "PASS" for row in rows), "failed samples in compacted successful shard")
            compacted_shard(path.parent, rows)
        else:
            require(summary["status"] == "FAIL" and not (path.parent / "compaction.json").exists(),
                    "failed shard diagnostics were compacted")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(raw: bytes) -> dict:
    value = json.loads(raw, object_pairs_hook=unique_keys,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    require(isinstance(value, dict), "expected JSON object")
    return value


def read(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), "expected regular evidence file")
    require(path.stat().st_size <= MAX_FILE, "evidence file exceeds analysis bound")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    require(len(data) <= MAX_FILE, "evidence file grew beyond analysis bound")
    return data


def lines(raw: bytes) -> list[dict]:
    require(raw.endswith(b"\n"), "incomplete JSONL final record")
    result = []
    for line in raw.splitlines():
        require(0 < len(line) <= MAX_LINE, "empty/oversized JSONL record")
        result.append(parse(line))
    require(len(result) <= 40_000, "evidence row count exceeds bound")
    return result


def distribution(values: list[float]) -> dict:
    values = sorted(values)
    return {"count": len(values), "min_ms": min(values) if values else None,
            "max_ms": max(values) if values else None,
            **{f"p{q}_ms": values[max(0, math.ceil(q / 100 * len(values)) - 1)] if values else None for q in (50, 95, 99)}}


def analyze(work: Path) -> dict:
    schedule = parse(read(work / "schedule.json"))
    environment = parse(read(work / "environment.json"))
    fingerprinted = {key: value for key, value in environment.items() if key != "environment_id"}
    encoded_environment = (json.dumps(fingerprinted, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(hashlib.sha256(encoded_environment).hexdigest() == environment["environment_id"], "environment fingerprint differs")
    require(schedule["mode"] in {"full", "smoke"}, "invalid campaign mode")
    raw_samples, raw_attempts = read(work / "samples.jsonl"), read(work / "attempts.jsonl")
    samples, attempts = lines(raw_samples), lines(raw_attempts)
    identities = {row["run_id"] for row in samples}
    require(len(identities) == len(samples), "duplicate sample identity")
    require(len({row["run_id"] for row in attempts}) == len(attempts), "duplicate attempt identity")
    require(identities == {row["run_id"] for row in attempts}, "dropped sample or interrupted intent")
    planned = {row["run_id"]: row["planned"] for row in attempts}
    groups = collections.defaultdict(list)
    observed_schedule = set()
    failures = 0
    for row in samples:
        require(row["campaign_id"] == schedule["run_id"], "campaign identity differs")
        require(row["environment_id"] == environment["environment_id"], "environment identity differs")
        require(all(row[key] == planned[row["run_id"]][key] for key in KEYS), "sample differs from planned workload")
        require(row["status"] in {"PASS", "FAIL", "BLOCKED"}, "unknown sample status")
        key = tuple(row[field] for field in KEYS)
        require(key not in observed_schedule, "duplicate scheduled sample")
        observed_schedule.add(key)
        duration = row["duration_ms"]
        if duration is not None:
            require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0, "invalid duration")
            require(type(row["submit_ns"]) is int and type(row["finish_ns"]) is int
                    and row["finish_ns"] >= row["submit_ns"], "invalid observed interval")
            require(math.isclose(duration, (row["finish_ns"] - row["submit_ns"]) / 1e6, rel_tol=1e-12, abs_tol=1e-9),
                    "duration differs from raw observed endpoints")
        if row["status"] == "PASS":
            require(duration is not None and row["exit_code"] == 0, "successful sample lacks duration or successful exit")
            if row["backend"] == "native":
                require(isinstance(row["policy_digest"], str) and DIGEST.fullmatch(row["policy_digest"])
                        and row["cleanup_confirmed"] is True and DIGEST.fullmatch(row["output_digest"]),
                        "successful native sample lacks policy/cleanup/result identity")
                if row["workload"] == "B-02":
                    require(set(row["verified_output"]) == {"count", "sum"}
                            and DIGEST.fullmatch(row["artifact_sha256"]), "transform lacks checked output")
            else:
                require(row["backend"] == "direct" and row["policy_digest"] == "DIRECT_NO_SANDBOX", "invalid direct baseline")
        else:
            failures += 1
        groups[tuple(row[field] for field in ("workload", "phase", "backend", "bytes", "concurrency", "policy_digest"))].append(row)
    expected = set()
    warmups = 2 if schedule["mode"] == "smoke" else 30
    for workload in ("B-01", "B-02"):
        repetitions = 4 if schedule["mode"] == "smoke" else 1000 if workload == "B-01" else 100
        for batch in range(1 if schedule["mode"] == "smoke" else 5):
            seed = schedule["seed"] + batch if workload == "B-01" else batch
            for size in ((0,) if workload == "B-01" else (16384, 1048576, 8388608)):
                for concurrency in (1, 2, 4):
                    for backend in (("native", "direct") if workload == "B-01" else ("native",)):
                        for index in range(warmups + repetitions):
                            expected.add((workload, "warmup" if index < warmups else "measured", backend,
                                          batch, seed, size, concurrency, index))
    require(observed_schedule == expected, f"incomplete/changed schedule: expected {len(expected)} actual {len(observed_schedule)}")
    results = []
    for identity, rows in groups.items():
        success = [row["duration_ms"] for row in rows if row["status"] == "PASS"]
        timed = [row["duration_ms"] for row in rows if row["duration_ms"] is not None]
        medians = {str(batch): statistics.median(values) for batch in sorted({row["batch"] for row in rows})
                   if (values := [row["duration_ms"] for row in rows if row["batch"] == batch and row["status"] == "PASS"])}
        results.append({"workload_phase_backend_bytes_concurrency_policy": identity, "samples_total": len(rows),
                        "samples_failed": len(rows) - len(success), "success_fraction": len(success) / len(rows),
                        "successful_latency": distribution(success), "all_attempt_observed_duration": distribution(timed),
                        "untimed_attempts": len(rows) - len(timed), "batch_success_median_ms": medians,
                        "cross_batch_median_range_ms": max(medians.values()) - min(medians.values()) if medians else None,
                        "p99_warning": "exploratory below 1000 successful samples" if len(success) < 1000 else None})
    teardown_paths = sorted(work.glob("shard-*/teardown.json"))
    teardowns = [parse(read(path)) for path in teardown_paths]
    require(teardowns and all(value["status"] == "PASS" and not value["errors"] for value in teardowns), "missing or failed shard teardown")
    require({row["shard"] for row in samples}.issubset({int(path.parent.name.split("-")[1]) for path in teardown_paths}),
            "timed shard lacks teardown evidence")
    if "storage_policy" in schedule:
        storage_evidence(work, schedule, samples, teardown_paths)
    hold = parse(read(work / "shard-0001/hold-control.json"))
    require(hold["status"] == "PASS" and hold["launcher_reaped"] is True and hold["cgroup_removed"] is True,
            "separate held-job control is missing/failed")
    campaign_summary = parse(read(work / "summary.json"))
    require(campaign_summary["completed_samples"] == len(samples) and campaign_summary["interrupted"] is None,
            "campaign incomplete/interrupted")
    return {"status": "FAIL" if failures else "PASS", "scope": schedule["mode"], "samples_total": len(samples),
            "samples_failed": failures, "quantile_method": "nearest rank", "groups": results,
            "samples_sha256": hashlib.sha256(raw_samples).hexdigest(),
            "attempts_sha256": hashlib.sha256(raw_attempts).hexdigest(),
            "acceptance_status": "NOT ESTABLISHED; scope shortfalls and independent review remain",
            "scope_shortfalls": schedule["scope_shortfalls"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.work)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, tarfile.TarError, EOFError) as error:
        print(json.dumps({"status": "FAIL", "reason": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
