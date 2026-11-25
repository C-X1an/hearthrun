#!/usr/bin/env python3
"""Independently validate B-04 schedule/accounting and scoped raw observations.

No native execution or output files: --work reads an existing campaign only.
Passing synthetic unit checks of this analyzer are not native evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
from typing import Any

sys.dont_write_bytecode = True
PROFILES = ("memory", "pids", "cpu", "admission")
EXPECTED_CONTROLS = {"memory.max": "268435456", "memory.swap.max": "0", "memory.oom.group": "1",
                     "pids.max": "32", "cpu.max": "100000 100000"}


def digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def identity(value: dict[str, Any]) -> tuple[int, int]:
    require(type(value["pid"]) is int and value["pid"] > 0 and type(value["start_ticks"]) is int
            and value["start_ticks"] > 0, "invalid process identity")
    return value["pid"], value["start_ticks"]


def checked_cleanup(value: dict[str, Any], members: list[dict[str, Any]], launchers: list[dict[str, Any]]) -> None:
    require(value["owned_leaf_removed"] is True and value["direct_populated_zero"] is None,
            "missing truthful owned leaf removal")
    require(value["members"] and value["launchers"] and len({identity(item["original"]) for item in value["members"]}) == len(value["members"]),
            "missing/duplicate original cleanup members")
    require([item["original"] for item in value["members"]] == members
            and [item["original"] for item in value["launchers"]] == launchers, "cleanup identities differ from live membership")
    for item in value["members"]:
        current = item["current"]
        require(current is None or identity(current) != identity(item["original"]) or current["state"] == "Z", "member remained live")
    for item in value["launchers"]:
        require(item["current"] is None or identity(item["current"]) != identity(item["original"]), "launcher was not reaped")


def rpc_pairs(events: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    intents, results = {}, {}
    for value in events:
        if value["type"] not in {"rpc_intent", "rpc_result"}:
            continue
        key = value["rpc_id"]
        require(type(key) is int and key > 0, "RPC lacks stable operation identity")
        target = intents if value["type"] == "rpc_intent" else results
        require(key not in target, "duplicate RPC operation identity")
        target[key] = value
    require(intents.keys() == results.keys(), "unpaired RPC intent/result")
    pairs = []
    for key in sorted(intents):
        intent, result = intents[key], results[key]
        require(intent["operation"] == result["operation"] and intent["expected_ok"] == result["expected_ok"]
                and intent["monotonic_ns"] <= result["monotonic_ns"], "RPC result differs from operation intent")
        pairs.append((intent, result))
    return pairs


def checked_host(events: list[dict[str, Any]], row: dict[str, Any]) -> None:
    reserve = [value for value in events if value["type"] == "host_reserve"]
    require(len(reserve) == 1 and reserve[0]["monotonic_ns"] < row["started_ns"], "missing pre-attempt host reserve")
    controls = reserve[0]["service_controls"]
    require(0 < int(controls["memory.max"]) <= 8_000_000_000 and controls["memory.swap.max"] == "0"
            and 128 <= int(controls["pids.max"]) <= 256 and controls["cpu.max"] == "max 100000"
            and int(controls["memory.max"]) - int(controls["memory.current"]) >= 768 * 1024 * 1024
            and int(controls["pids.max"]) - int(controls["pids.current"]) >= 128
            and {"cpu", "memory", "pids"} <= set(reserve[0]["delegated_controllers"].split()), "invalid local service reserve/controllers")
    available = reserve[0]["host_mem_available_line"].split()
    require(len(available) == 3 and available[0] == "MemAvailable:" and available[2] == "kB"
            and int(available[1]) * 1024 >= 1024 * 1024 * 1024, "host RAM reserve absent")
    storage = [value for value in events if value["type"] == "storage"]
    require({value["context"] for value in storage} == {"before-trial", "after-compaction"} and len(storage) == 2,
            "missing pre/post storage evidence")
    for value in storage:
        require(0 <= value["retained_bytes"] <= 512 * 1024 * 1024 and 0 <= value["entries"] <= 50_000
                and value["available_bytes"] >= 256 * 1024 * 1024 and value["available_inodes"] >= 16_384, "insufficient storage reserve")
    before = next(value for value in storage if value["context"] == "before-trial")
    after = next(value for value in storage if value["context"] == "after-compaction")
    require(reserve[0]["monotonic_ns"] <= before["monotonic_ns"] < row["started_ns"] < after["monotonic_ns"] <= row["finish_ns"],
            "storage checks do not bracket actual trial")


def checked_build(work: Path, environment: dict[str, Any]) -> None:
    for name, key in (("build-record.json", "build"), ("host-record.json", "host_record")):
        raw = read(work / name)
        field = "host_record_sha256" if key == "host_record" else "build_record_sha256"
        require(hashlib.sha256(raw).hexdigest() == environment[field], "provenance record file digest differs")
        require(parse(raw) == environment[key], "embedded provenance differs from retained original")
    build = environment["build"]
    require(build["profile"] == "release" and build["rustc_verbose"].startswith("rustc 1.99.1 ")
            and isinstance(build["optimization_flags"], list) and build["optimization_flags"]
            and isinstance(build["target"], str) and build["target"] and isinstance(build["build_command"], list)
            and build["build_command"] and digest(build["capture_manifest_sha256"]), "release build provenance absent")
    require(digest(build["source_sha256"]) and build["source_sha256"] == environment["observed_source_sha256"]
            and build["binary_sha256"] == environment["observed_binary_sha256"]
            and set(build["binary_sha256"]) == {"hearthrun", "hearthrun-supervisor", "hearthrun-launcher"}
            and all(digest(value) for value in build["binary_sha256"].values()), "native build/observed identity mismatch")
    for key in ("resources", "task"):
        entry = build[key]
        require(digest(entry["fixture_sha256"]) and entry["fixture_sha256"] == environment["observed_fixture_sha256"][key]
                and digest(entry["source_sha256"]) and entry["source_sha256"] == environment["observed_fixture_source_sha256"][key]
                and digest(entry["capture_manifest_sha256"]) and isinstance(entry["build_command"], list) and entry["build_command"],
                "fixture captured build/observed identity mismatch")
    require(digest(environment["doctor_sha256"]) and environment["runtime"] == "actual local Linux native supervisor/launcher"
            and all(key in environment["host_record"] for key in
                    ("power_policy", "background_load_control", "filesystem_mount_options", "landlock_abi", "seccomp_mode"))
            and environment["mount"]["filesystem"] == "tmpfs" and "noswap" in environment["mount"]["options"]
            and all(environment[key] for key in ("kernel", "machine", "cpu_count", "cpuinfo", "meminfo", "boot_id", "cgroup_controllers")),
            "native host/build observation fields absent")


def checked_compaction(work: Path, row: dict[str, Any], events: list[dict[str, Any]]) -> None:
    reports = [value for value in events if value["type"] == "compaction"]
    require(len(reports) == 1, "missing actual compaction event")
    report = reports[0]
    require(report["shard"] == f"shard-{row['sample_index']:03d}", "compaction shard identity differs")
    shard = work / report["shard"]
    payloads = {name: read(shard / name) for name in ("transients.tar.gz", "transients-index.json", "compaction.json")}
    for name, field in (("transients.tar.gz", "archive_sha256"), ("transients-index.json", "index_sha256"), ("compaction.json", "compaction_sha256")):
        require(hashlib.sha256(payloads[name]).hexdigest() == report[field], "retained compaction file digest differs")
    index, compact = parse(payloads["transients-index.json"]), parse(payloads["compaction.json"])
    require(index["format"] == "hearthrun-shard-tar-gzip-v1" and index["status"] == compact["status"] == "PASS"
            and index["archive_sha256"] == report["archive_sha256"] and compact["index_sha256"] == report["index_sha256"]
            and compact["originals_removed"] is True and compact["entries"] == len(index["entries"])
            and 0 <= compact["content_bytes"] == index["content_bytes"] <= 128 * 1024 * 1024
            and len(index["entries"]) <= 12_000, "invalid compaction/index agreement")
    entries = index["entries"]
    paths = [value["path"] for value in entries]
    require(len(set(paths)) == len(paths) and all(path and not path.startswith("/") and "\\" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")) for path in paths), "invalid archive paths")
    expected = [value for value in entries if value["type"] != "stale_socket"]
    require({"state", "logs", "tmp", "data.ndjson"} <= set(paths)
            and all(value["type"] != "stale_socket" or (value["path"] == "state/control.sock" and value["mode"] == 0o600
                    and value["size"] == 0) for value in entries), "missing compaction roots or invalid stale socket")
    archived_records, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(payloads["transients.tar.gz"]), mode="r|gz") as archive:
        for entry in expected:
            member = archive.next()
            require(member is not None and member.name.rstrip("/") == entry["path"] and member.mode == entry["mode"], "archive index metadata differs")
            if entry["type"] == "directory":
                require(member.isdir(), "archive expected directory")
            else:
                require(entry["type"] == "file" and member.isfile() and 0 <= member.size == entry["size"] <= 64 * 1024 * 1024,
                        "archive type/size invalid")
                stream = archive.extractfile(member)
                require(stream is not None, "archive missing file bytes")
                raw = stream.read(member.size + 1)
                require(len(raw) == member.size and hashlib.sha256(raw).hexdigest() == entry["sha256"], "archive content digest differs")
                total += len(raw)
                require(total <= 128 * 1024 * 1024, "archive uncompressed byte bound exceeded")
                if entry["path"].startswith("state/records/") and entry["path"].endswith(".json") and entry["path"] != "state/records/catalog.json":
                    archived_records[entry["path"].split("/")[-1][:-5]] = parse(raw)
        require(archive.next() is None, "unindexed archive entry")
    require(total == index["content_bytes"], "archive total content byte count differs")
    records = {value["job_id"]: value["record"] for value in events if value["type"] == "job_record"}
    require(archived_records == records, "archived final job records differ from raw observed records")
    for name in ("state", "logs", "tmp", "data.ndjson"):
        require(not os.path.lexists(shard / name), "compacted original transient remains")


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError(message)


def duplicate_checked(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def parse(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"nonfinite JSON number: {value}")
    return json.loads(raw, object_pairs_hook=duplicate_checked, parse_constant=reject_constant)


def read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 64 * 1024 * 1024, "evidence is not a bounded regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(64 * 1024 * 1024 + 1)
        after = os.fstat(descriptor)
        require(len(raw) == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns,
                "evidence changed during read")
        return raw
    finally:
        os.close(descriptor)


def counters(raw: str) -> dict[str, int]:
    values = {}
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in values and re.fullmatch(r"[0-9]+", fields[1]), "invalid raw kernel counters")
        values[fields[0]] = int(fields[1])
    return values


def checked_proc(event: dict[str, Any]) -> tuple[int, int]:
    identity, after = event["identity"], event["identity_after"]
    require(identity["pid"] == after["pid"] and identity["start_ticks"] == after["start_ticks"]
            and identity["state"] != "Z" and after["state"] != "Z", "changed/dead supervisor identity")
    rss = event["vmrss_line"].split()
    require(len(rss) == 3 and rss[0] == "VmRSS:" and rss[1].isdigit() and rss[2] == "kB"
            and event["rss_bytes"] == int(rss[1]) * 1024, "RSS does not match exact /proc VmRSS units")
    fds = event["fd_numbers"]
    require(fds == sorted(set(fds)) and all(type(value) is int and value >= 0 for value in fds)
            and event["fd_count"] == len(fds) <= 1024, "FD count differs from exact owned PID inventory")
    return identity["pid"], identity["start_ticks"]


def checked_measurement(row: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    workload, cases = row["workload"], row["measurements"]
    require(type(row["started_ns"]) is int and row["started_ns"] < row["finish_ns"], "invalid attempt clocks")
    checked_host(events, row)
    pairs = rpc_pairs(events)
    require(row["teardown"] == {"status": "PASS", "owned_children_reaped": True, "owned_cgroups_remaining": 0},
            "passing measurement lacks clean teardown")
    teardown = [value for value in events if value["type"] == "shard_teardown"]
    require(len(teardown) == 1 and teardown[0]["status"] == "PASS"
            and teardown[0]["owned_children_reaped"] is True and teardown[0]["owned_cgroups_remaining"] == 0,
            "missing or duplicate raw teardown")
    observations = [value for value in events if value["type"] == "supervisor_proc"]
    spawns = [value for value in events if value["type"] == "supervisor_spawn"]
    require(len(spawns) == 1 and spawns[0]["popen_pid"] == spawns[0]["identity"]["pid"], "missing owned Popen spawn anchor")
    anchor = identity(spawns[0]["identity"])
    require(len(observations) >= 2 and len({checked_proc(value) for value in observations}) == 1
            and all(checked_proc(value) == anchor and spawns[0]["monotonic_ns"] <= value["monotonic_ns"] for value in observations)
            and {"before-profile", "after-profile"} <= {value["context"] for value in observations},
            "missing scoped supervisor baseline/end observations")
    records = [value for value in events if value["type"] == "job_record"]
    jobs = {value["job_id"] for value in records}
    require(len(records) == len(jobs) == teardown[0]["jobs"] == (21 if workload == "admission" else 1),
            "raw native job count differs from declared profile")
    for value in records:
        record = value["record"]
        require(record["job_id"] == value["job_id"] and record["state"] in {"SUCCEEDED", "FAILED", "CANCELLED"}
                and record["cleanup_confirmed"] is True and re.fullmatch(r"[a-f0-9]{64}", record["result_digest"]),
                "final native record is unconfirmed or lacks result identity")
        pages = [entry for entry in events if entry["type"] == "native_phase_page" and entry["job_id"] == value["job_id"]]
        require(pages and pages[0]["after_seq"] == 0, "missing native phase origin")
        after, names = 0, []
        for page in pages:
            require(page["after_seq"] == after and page["page"]["truncated"] is False, "lost native phase history")
            phases = page["page"]["events"]
            require(isinstance(phases, list) and len(phases) <= 100, "unbounded phase page")
            sequences = [entry["sequence"] for entry in phases]
            require(sequences == sorted(set(sequences)) and all(sequence > after for sequence in sequences), "nonmonotonic native phases")
            after = sequences[-1] if sequences else after
            names.extend(entry["event"] for entry in phases)
        require("RUNNING" in names, "native job has no actual RUNNING phase")
    raw_counters = [value for value in events if value["type"] == "kernel_raw"]
    for value in raw_counters:
        require(value["job_id"] in jobs and value["filename"] in {"memory.events", "pids.events", "cpu.stat"}
                and counters(value["raw"]) == value["counters"], "kernel counter differs from scoped raw bytes")
    group_controls = [value for value in events if value["type"] == "cgroup_controls"]
    require(len({value["job_id"] for value in group_controls}) == len(group_controls), "duplicate cgroup control identity")
    by_job = {value["job_id"]: value for value in group_controls}
    for value in group_controls:
        record = next(item["record"] for item in records if item["job_id"] == value["job_id"])
        require({key: raw.strip() for key, raw in value["raw"].items()} == EXPECTED_CONTROLS
                and value["group_name"] == f"hr-{record['instance_id']}-{value['job_id']}"
                and type(value["cgroup_inode"]) is int and value["cgroup_inode"] > 0, "contradictory live cgroup controls/identity")
    require(all(value["job_id"] in by_job and value["cgroup_inode"] == by_job[value["job_id"]]["cgroup_inode"]
                for value in raw_counters), "raw counter belongs to a different cgroup inode")
    if workload in {"memory", "pids", "cpu"}:
        case = cases[workload]
        job = case["job_id"]
        require(jobs == {job} and case["status"] == "PASS" and case["controls"] == EXPECTED_CONTROLS,
                "resource job/controls do not match exact profile")
        record = records[0]["record"]
        require(record["state"] == ("SUCCEEDED" if workload == "cpu" else "FAILED")
                and (workload == "cpu" or record["cancel_reason"] == "RESOURCE_LIMIT"), "resource final state/cause differs")
        live = [value for value in events if value["type"] == "live_membership" and value["job_id"] == job]
        require(len(live) == 1 and job in by_job and live[0]["controls"] == case["controls"]
                and live[0]["cgroup_inode"] == by_job[job]["cgroup_inode"]
                and live[0]["launchers"] and all(value["ppid"] == anchor[0] for value in live[0]["launchers"]),
                "live membership disagrees with exact controls/owned launcher")
        require({"memory.events", "pids.events", "cpu.stat"} <=
                {value["filename"] for value in raw_counters if value["job_id"] == job and value["context"] == "live_initial"},
                "missing initial exact cgroup counters")
        cleanup = [value for value in events if value["type"] == "cleanup_witness" and value["job_id"] == job]
        require(len(cleanup) == 1 and cleanup[0]["owned_leaf_removed"] is True and cleanup[0]["direct_populated_zero"] is None,
                "missing truthful leaf removal cleanup witness")
        checked_cleanup(cleanup[0], live[0]["members"], live[0]["launchers"])
        if workload == "cpu":
            before, after = case["before"], case["after"]
            elapsed = case["steady_wall_seconds"]
            require(elapsed >= 10, "CPU trial shorter than ten seconds")
            ratio = (after["usage_usec"] - before["usage_usec"]) / (elapsed * 1_000_000)
            require(.85 <= ratio <= 1.15 and ratio == case["used_cores"]
                    and after["nr_throttled"] > before["nr_throttled"]
                    and after["throttled_usec"] > before["throttled_usec"], "no measured one-core quota/throttling")
            expected, filename = [before, after], "cpu.stat"
        else:
            filename, key = ("memory.events", "oom_kill") if workload == "memory" else ("pids.events", "max")
            require(case["counter_file"] == filename and case["baseline"][key] == 0
                    and case["event_before_teardown"][key] > 0, "kernel limit was not independently observed")
            expected = [case["baseline"], case["event_before_teardown"]]
        for expected_value in expected:
            require(any(value["filename"] == filename and value["context"] == "retained_counter_read"
                        and value["job_id"] == job and value["counters"] == expected_value for value in raw_counters),
                    "reported kernel measurement has no raw retained-descriptor witness")
        if workload == "cpu":
            witnesses = [next(value for value in raw_counters if value["filename"] == "cpu.stat"
                              and value["context"] == "retained_counter_read" and value["counters"] == item) for item in expected]
            for witness in witnesses:
                require(type(witness["read_started_ns"]) is int and type(witness["read_finished_ns"]) is int
                        and row["started_ns"] <= witness["read_started_ns"] <= witness["read_finished_ns"]
                        <= witness["monotonic_ns"] <= row["finish_ns"]
                        and witness["monotonic_ns"] - witness["read_finished_ns"] <= 250_000_000,
                        "CPU raw read clock bounds invalid")
            require(witnesses[1]["read_started_ns"] - witnesses[0]["read_finished_ns"] >= 10_000_000_000,
                    "raw CPU read witnesses do not establish a ten-second window")
            measured = (witnesses[1]["read_finished_ns"] - witnesses[0]["read_finished_ns"]) / 1_000_000_000
            actual_ratio = (after["usage_usec"] - before["usage_usec"]) / (measured * 1_000_000)
            require(abs(measured - elapsed) <= .25 and .85 <= actual_ratio <= 1.15, "CPU duration/usage differs from raw host clock interval")
    else:
        require(workload == "admission", "unknown profile")
        case = cases["capacity_fifo"]
        require(len(case["holders"]) == 4 and len(case["waiting_admission_order"]) == 16
                and case["rejection"]["code"] == "QUEUE_FULL"
                and all(case[key]["active"] == 4 and case[key]["queued"] == 16 and case[key]["retained_requests"] == 20
                        for key in ("full_metrics", "after_rejection_metrics")), "missing 4+16 and 21st refusal")
        rejected = case["rejected_request_id"]
        refusals = [value for value in events if value["type"] == "rpc_intent" and value["operation"] == "submit"
                    and value["arguments"][0] == rejected and value["expected_ok"] is False]
        require(len(refusals) == 1 and refusals[0]["expected_error"] == "QUEUE_FULL", "missing exact refused submit attempt")
        rejected_results = [value for value in events if value["type"] == "rpc_result" and value["operation"] == "submit"
                            and value["expected_ok"] is False and value["value"].get("code") == "QUEUE_FULL"]
        require(len(rejected_results) == 1, "missing actual QUEUE_FULL response")
        holders = {value["job_id"] for value in case["holders"]}
        waiting = {value["job_id"] for value in case["waiting_admission_order"]}
        require(len(holders) == 4 and len(waiting) == 16 and not holders & waiting and holders | waiting <= jobs
                and jobs - (holders | waiting) == {case["explicit_post_capacity_retry_job_id"]}, "admission job sets duplicated/unrelated")
        final = {value["job_id"]: value["record"] for value in records}
        rejected_pairs = [(intent, result) for intent, result in pairs if intent["operation"] == "submit"
                          and intent["arguments"][0] == rejected and intent["expected_ok"] is False]
        require(len(rejected_pairs) == 1 and rejected_pairs[0][1]["value"] == case["rejection"], "refusal response is linked to a different submit")
        refused_intent, refused_result = rejected_pairs[0]
        boundaries = [value for value in events if value["type"] == "admission_boundary" and value["rpc_id"] == refused_intent["rpc_id"]]
        require(len(boundaries) == 2 and {value["context"] for value in boundaries} == {"before_refusal", "after_refusal"}, "missing linked refusal boundaries")
        inventories = []
        for boundary in boundaries:
            inventory = {value["job_id"]: value for value in boundary["records"]}
            require(len(inventory) == len(boundary["records"]) == 20 and inventory.keys() == holders | waiting
                    and all(inventory[job]["state"] == "RUNNING" for job in holders)
                    and all(inventory[job]["state"] == "QUEUED" and inventory[job]["launch_stage"] == "INTENT"
                            and inventory[job]["started_monotonic_ns"] is None for job in waiting)
                    and all(value["request_id"] != rejected and value["request_id"] == final[job]["request_id"]
                            and value["instance_id"] == final[job]["instance_id"] and value["executable_digest"] == final[job]["executable_digest"]
                            for job, value in inventory.items()), "raw refusal inventory differs from 4+16")
            require(boundary["monotonic_ns"] <= refused_intent["monotonic_ns"] if boundary["context"] == "before_refusal"
                    else boundary["monotonic_ns"] >= refused_result["monotonic_ns"], "refusal boundary clocks do not bracket RPC")
            require(set(boundary["groups"]) == {by_job[job]["group_name"] for job in holders}, "raw admission group inventory differs")
            inventories.append(inventory)
        require(inventories[0] == inventories[1], "refused request changed durable inventory")
        retry = case["explicit_post_capacity_retry_job_id"]
        require(final[retry]["request_id"] == rejected and final[retry]["state"] == "SUCCEEDED"
                and all(final[job]["state"] == "CANCELLED" for job in holders)
                and all(final[job]["state"] == "SUCCEEDED" for job in waiting)
                and any(intent["operation"] == "submit" and intent["expected_ok"] is True and intent["arguments"][0] == rejected
                        and result["value"]["job_id"] == retry and intent["monotonic_ns"] > refused_result["monotonic_ns"]
                        for intent, result in pairs), "explicit post-refusal retry or final admission states differ")
        for context, expected_value in (("full_metrics", case["full_metrics"]), ("after_rejection_metrics", case["after_rejection_metrics"])):
            metrics = [(intent, result) for intent, result in pairs if intent["operation"] == "metrics" and result["value"] == expected_value
                       and (result["monotonic_ns"] < refused_intent["monotonic_ns"] if context == "full_metrics"
                            else intent["monotonic_ns"] > refused_result["monotonic_ns"])]
            require(metrics, "reported exact admission metrics have no linked raw RPC observation")
        for item in [*case["holders"], *case["waiting_admission_order"]]:
            job, request = item["job_id"], item["request_id"]
            require(final[job]["request_id"] == request and any(intent["operation"] == "submit" and intent["expected_ok"] is True
                    and intent["arguments"][0] == request and intent["arguments"][-1] == ("hold" if job in holders else "empty")
                    and result["value"]["job_id"] == job for intent, result in pairs), "admission request/job identity is unrelated to raw submit")
        cleanup = [value for value in events if value["type"] == "cleanup_witness" and value["job_id"] in holders]
        require(len(cleanup) == len(holders) == 4 and {value["job_id"] for value in cleanup} == holders
                and all(value["owned_leaf_removed"] is True and value["launchers"] for value in cleanup),
                "missing actual holder cleanup witnesses")
        for value in cleanup:
            holder = next(item for item in case["holders"] if item["job_id"] == value["job_id"])
            require(all(item["ppid"] == anchor[0] for item in holder["launchers"]), "holder launcher does not belong to owned supervisor")
            checked_cleanup(value, holder["members"], holder["launchers"])
    return {"supervisor_sample_count": len(observations),
            "sampled_supervisor_rss_bytes": {"min": min(value["rss_bytes"] for value in observations),
                                             "max": max(value["rss_bytes"] for value in observations)},
            "sampled_supervisor_fd_count": {"min": min(value["fd_count"] for value in observations),
                                            "max": max(value["fd_count"] for value in observations)}}


def compare_population(work: Path) -> dict[str, Any]:
    schedule, summary, environment = [parse(read(work / name)) for name in ("schedule.json", "summary.json", "environment.json")]
    encoded = (json.dumps({key: value for key, value in environment.items() if key != "environment_id"},
                          sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(hashlib.sha256(encoded).hexdigest() == environment["environment_id"], "environment fingerprint differs")
    require(schedule["mode"] in {"smoke", "full"} and schedule["benchmark"] == summary["benchmark"] == environment["benchmark"] == "B-04"
            and summary["mode"] == schedule["mode"] and summary["run_id"] == schedule["run_id"], "invalid campaign identities")
    expected = [(workload, repetition) for workload in PROFILES for repetition in range(30 if schedule["mode"] == "full" else 1)]
    samples_raw, attempts_raw = read(work / "samples.jsonl"), read(work / "attempts.jsonl")
    samples, attempts, events = [[parse(line) for line in raw.splitlines()] for raw in
                                 (samples_raw, attempts_raw, read(work / "events.jsonl"))]
    expected_indices = set(range(len(expected)))
    require(len(samples) == len(expected) == summary["planned"] == len(schedule["rows"])
            and {value["sample_index"] for value in samples} == expected_indices, "missing/duplicate sample population")
    for batch in (samples, attempts, schedule["rows"]):
        require(len({value["sample_index"] for value in batch}) == len(batch), "duplicate planned/attempt/sample index")
        for value in batch:
            index = value["sample_index"]
            require(index in expected_indices and (value["workload"], value["repetition"]) == expected[index]
                    and value["run_id"] == schedule["run_id"] and value["benchmark"] == "B-04", "row differs from independently derived schedule")
    attempted = {value["sample_index"] for value in attempts}
    require(len(attempted) == len(attempts) and attempted == {value["sample_index"] for value in samples if value["status"] != "NOT RUN"},
            "attempts and outcomes do not reconcile")
    counts = Counter(value["status"] for value in samples)
    require(counts.keys() <= {"PASS", "FAIL", "NOT RUN", "INCOMPLETE"} and summary["counts"] == counts,
            "summary altered denominator/status")
    groups, measurements = [], []
    for workload in PROFILES:
        members = [value for value in samples if value["workload"] == workload]
        groups.append({"workload": workload, "planned": len(members), "counts": dict(Counter(value["status"] for value in members))})
    require(summary["groups"] == groups, "summary groups differ from raw denominator")
    if any(row["status"] == "PASS" for row in samples):
        checked_build(work, environment)
    for row in samples:
        if row["status"] == "PASS":
            scoped = [event for event in events if event.get("sample_index") == row["sample_index"]]
            checked_compaction(work, row, scoped)
            fixture_key = "task" if row["workload"] == "admission" else "resources"
            require(all(value["record"]["executable_digest"] == environment["observed_fixture_sha256"][fixture_key]
                        for value in scoped if value["type"] == "job_record"), "archived job executable differs from captured fixture build")
            measurements.append({"sample_index": row["sample_index"], "workload": row["workload"],
                                 **checked_measurement(row, scoped)})
    clean = counts == {"PASS": len(expected)}
    require((summary["status"] == "PASS") == clean, "summary PASS does not equal complete passing matrix")
    return {"benchmark": "B-04", "status": "PASS" if clean else "FAIL", "mode": schedule["mode"],
            "counts": dict(counts), "groups": groups, "measurements": measurements,
            "samples_sha256": hashlib.sha256(samples_raw).hexdigest(), "attempts_sha256": hashlib.sha256(attempts_raw).hexdigest(),
            "supervisor_scope": "sampled point-in-time values for each owned PID; maximum sampled RSS is not a peak RSS measurement"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    try:
        report = compare_population(parser.parse_args().work)
        print(json.dumps(report, sort_keys=True, indent=2))
        raise SystemExit(0 if report["status"] == "PASS" else 1)
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError, EOFError, tarfile.TarError) as error:
        print(json.dumps({"status": "FAIL", "reason": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        raise SystemExit(1)
