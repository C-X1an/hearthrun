"""Strict pure validator for opt-in instrumented B-03 sidecars.

No sidecar proves cleanup: callers must first run analyze_cancellation.compare_population.
These raw values are userspace CLOCK_MONOTONIC observations, not kernel entry times.
"""
import hashlib
import json
import os
import stat
import re
from pathlib import Path

MAX_TRACE_BYTES = 256 * 1024
MAX_EVENTS = 128
FEATURE = "cancellation-timing-verification"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON trace key")
        result[key] = value
    return result


def parse_trace(raw):
    require(0 < len(raw) <= MAX_TRACE_BYTES and raw.endswith(b"\n"), "oversize or incomplete trace")
    records = []
    for line in raw.splitlines():
        require(0 < len(line) <= 2048 and len(records) < MAX_EVENTS + 2, "oversize trace record count or length")
        records.append(json.loads(line, object_pairs_hook=unique_object,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON"))))
    return records


def load_trace(path):
    path = Path(path)
    require(not path.is_symlink(), "trace is a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_TRACE_BYTES,
                "trace is not a bounded singly linked regular file")
        raw = stream.read(MAX_TRACE_BYTES + 1)
    return parse_trace(raw), hashlib.sha256(raw).hexdigest()


def read_trace(path):
    return load_trace(path)[0]


def validate_trace(records, samples, *, run_id, shard, clock_identity):
    require(re.fullmatch(r"[0-9a-f]{32}", run_id) is not None, "invalid run identity")
    require(re.fullmatch(r"shard-[0-9]{4}", shard) is not None, "invalid shard identity")
    require(2 <= len(records) <= MAX_EVENTS + 2 and all(type(row) is dict for row in records), "invalid trace size")
    header, *events, footer = records
    require(header.get("kind") == "header" and type(header.get("version")) is int and header["version"] == 1
            and header.get("run_id") == run_id and header.get("shard") == shard
            and integer(header.get("pid")) and header["pid"] > 0, "wrong trace session")
    require(clock_identity.get("clock") == "CLOCK_MONOTONIC"
            and all(isinstance(clock_identity.get(key), str) and clock_identity[key]
                    and header.get(key) == clock_identity[key]
                    for key in ("clock", "boot_id", "time_namespace")), "different monotonic clock identity")
    require(footer.get("kind") == "footer" and footer.get("complete") is True
            and type(footer.get("lost")) is int and footer["lost"] == 0
            and integer(footer.get("events")) and footer["events"] == len(events)
            and integer(footer.get("received")), "lost or incomplete trace")
    require(not any(row.get("kind") == "deadline_write" for row in events),
            "independent deadline write prevents owner cancellation attribution")
    require(all(row.get("kind") == "owner_write" for row in events), "missing actual owner write")
    require(footer["received"] == len(events) == len(samples) <= MAX_EVENTS, "missing or extra cancellation event")
    by_job, ordinals = {}, set()
    for row in events:
        job, ordinal = row.get("job_id"), row.get("ordinal")
        require(isinstance(job, str) and re.fullmatch(r"[0-9a-f]{32}", job) is not None
                and job not in by_job and integer(ordinal) and ordinal > 0 and ordinal not in ordinals,
                "ambiguous cancellation identity")
        require(all(integer(row.get(key)) for key in ("receipt_ns", "begin_ns", "end_ns"))
                and row.get("ok") is True, "failed or absent kill write bracket")
        by_job[job] = row
        ordinals.add(ordinal)
    require(ordinals == set(range(1, len(events) + 1)), "missing receipt ordinal")
    result, seen, sample_indices = [], set(), set()
    for sample in samples:
        job, index = sample.get("job_id"), sample.get("sample_index")
        require(sample.get("run_id") == run_id and sample.get("status") == "PASS"
                and job in by_job and job not in seen and integer(index) and index not in sample_indices,
                "wrong or ambiguous client cancellation identity")
        require(all(integer(sample.get(key)) for key in ("cancel_request_ns", "cancel_ack_ns", "cleanup_ns", "finish_ns")),
                "missing client clock or cleanup witness")
        row = by_job[job]
        require(sample["cancel_request_ns"] <= row["receipt_ns"] <= row["begin_ns"] <= row["end_ns"]
                <= sample["cancel_ack_ns"] <= sample["finish_ns"]
                and row["end_ns"] <= sample["cleanup_ns"] <= sample["finish_ns"], "wrong clock order or cleanup")
        result.append({"sample_index": index, "job_id": job, "ordinal": row["ordinal"],
                       "receipt_ns": row["receipt_ns"], "begin_ns": row["begin_ns"], "end_ns": row["end_ns"],
                       "receipt_to_write_begin_ns": row["begin_ns"] - row["receipt_ns"],
                       "write_bracket_ns": row["end_ns"] - row["begin_ns"],
                       "receipt_to_cleanup_ns": sample["cleanup_ns"] - row["receipt_ns"]})
        seen.add(job)
        sample_indices.add(index)
    return result
