#!/usr/bin/env python3
"""Bounded Cargo inventory, declared-license inventory and offline RustSec audit.

Run from public/, using the existing quota-backed Cargo cache/toolchain:
  python3 scripts/dependency_inventory.py --mode inventory
  python3 scripts/dependency_inventory.py --mode sbom
  python3 scripts/dependency_inventory.py --mode licenses
  python3 scripts/dependency_inventory.py --mode audit --audit-tool ABS_CARGO_AUDIT --audit-db ABS_EXISTING_DB

Writes JSON only to stdout. No installations, builds, database fetches or output
files. cargo metadata uses --locked --offline and may use Cargo's existing cache
locks; the caller must already confine Cargo/toolchain/cache destinations. The
SBOM follows the CycloneDX 1.6 JSON shape; schema validation is a separate gate.
Declared license expressions are inventory, not a legal compatibility verdict.
Advisory status never follows from metadata. Audit needs a real cargo-audit and
an existing clean database/cache; cargo-audit enforces its own staleness policy.
Exit 0: requested inventory/audit completed, 1: failed check/findings, 78: missing
capability or incomplete declarations. Capture this command with capture.py.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

try:
    import tomllib
except ImportError:
    tomllib = None

MAX_FILE = 2 * 1024 * 1024
MAX_CAPTURE = 16 * 1024 * 1024
MAX_PACKAGES = 2048
MAX_EDGES = 32768
HASH = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


class CheckError(ValueError):
    pass


class Blocked(CheckError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_executable(path: Path) -> str:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= 256 * 1024 * 1024, "audit executable exceeds bounded regular-file limit")
    value = hashlib.sha256()
    seen = 0
    with path.open("rb") as stream:
        while data := stream.read(65536):
            seen += len(data)
            require(seen <= 256 * 1024 * 1024, "audit executable grew beyond hashing bound")
            value.update(data)
    require(seen == info.st_size, "audit executable changed size during hashing")
    return value.hexdigest()


def read_file(path: Path, limit: int = MAX_FILE) -> bytes:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= limit, "input must be a bounded regular file without a symlink")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "input grew beyond its read bound")
    return value


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def parse_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(CheckError("nonfinite JSON")))


def command(argv: list[str], root: Path, timeout: float = 45) -> tuple[int, bytes, bytes]:
    """Bound both pipe buffers and elapsed time, including an unhelpful tool."""
    environment = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", NO_COLOR="1", GIT_OPTIONAL_LOCKS="0")
    try:
        child = subprocess.Popen(argv, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, start_new_session=os.name == "posix")
    except FileNotFoundError as error:
        raise Blocked("required external command is unavailable") from error
    output = [bytearray(), bytearray()]
    overflow = threading.Event()
    errors: list[str] = []
    def collect(pipe: Any, index: int) -> None:
        try:
            while True:
                data = pipe.read(65536)
                if not data:
                    return
                if len(output[index]) + len(data) > MAX_CAPTURE:
                    overflow.set()
                    return
                output[index].extend(data)
        except OSError:
            errors.append("tool pipe capture failed")
        finally:
            pipe.close()
    readers = [threading.Thread(target=collect, args=(pipe, index), daemon=True)
               for index, pipe in enumerate((child.stdout, child.stderr))]
    for reader in readers:
        reader.start()
    end = time.monotonic() + timeout
    failed = False
    while child.poll() is None:
        if overflow.is_set() or time.monotonic() >= end:
            failed = True
            if os.name == "posix":
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                child.kill()
            break
        time.sleep(0.02)
    child.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=2)
    require(not failed and not overflow.is_set() and not errors and not any(reader.is_alive() for reader in readers), "external tool exceeded time/output bounds or failed pipe capture")
    return child.returncode, bytes(output[0]), bytes(output[1])


def source_identity(source: Any) -> str | None:
    if source is None:
        return None
    require(isinstance(source, str) and len(source) <= 2048 and source.startswith(("registry+", "sparse+", "git+")), "unsupported dependency source")
    url = urlsplit(source.split("+", 1)[1])
    require(url.scheme in {"https", "http", "ssh"} and bool(url.hostname) and url.username is None and url.password is None, "dependency source contains local paths or embedded credentials")
    return source


def lock_key(package: dict[str, Any]) -> tuple[str, str, str | None]:
    name, version = package.get("name"), package.get("version")
    require(isinstance(name, str) and NAME.fullmatch(name) is not None and isinstance(version, str) and 0 < len(version) <= 128, "invalid package identity")
    return name, version, source_identity(package.get("source"))


def inventory(root: Path) -> dict[str, Any]:
    if tomllib is None:
        raise Blocked("Python 3.11+ tomllib is required")
    lock_path = root / "Cargo.lock"
    raw = read_file(lock_path)
    lock = tomllib.loads(raw.decode("utf-8"))
    require(lock.get("version") in {3, 4}, "unsupported Cargo.lock format")
    entries = lock.get("package")
    require(isinstance(entries, list) and 0 < len(entries) <= MAX_PACKAGES, "lock package inventory exceeds bounds or is empty")
    locked: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for package in entries:
        key = lock_key(package)
        require(key not in locked, "duplicate locked package identity")
        if key[2] and key[2].startswith(("registry+", "sparse+")):
            require(isinstance(package.get("checksum"), str) and HASH.fullmatch(package["checksum"]) is not None, "registry package lacks a locked SHA-256 checksum")
        locked[key] = package
    cargo = shutil.which("cargo")
    if cargo is None:
        raise Blocked("cargo is unavailable; no metadata inventory was measured")
    code, version, _ = command([cargo, "--version"], root, timeout=15)
    require(code == 0 and version.startswith(b"cargo "), "cargo version capability check failed")
    code, stdout, stderr = command([cargo, "metadata", "--locked", "--offline", "--format-version", "1"], root)
    require(read_file(lock_path) == raw, "Cargo.lock changed during --locked offline metadata")
    if code:
        raise Blocked(f"actual cargo metadata --locked --offline failed (exit {code}; stderr_sha256={digest(stderr)}); capture that direct command separately to inspect its stderr")
    metadata = parse_json(stdout)
    packages = metadata.get("packages")
    require(isinstance(packages, list) and 0 < len(packages) <= MAX_PACKAGES, "actual metadata packages missing or beyond bounds")
    nodes = metadata.get("resolve", {}).get("nodes")
    require(isinstance(nodes, list) and len(nodes) <= MAX_PACKAGES, "actual resolved dependency graph missing")
    components = []
    identifiers: dict[str, str] = {}
    matched = set()
    workspace_ids = set(metadata.get("workspace_members", []))
    for package in packages:
        key = lock_key(package)
        require(key in locked and key not in matched, "metadata package differs from exact locked package set")
        matched.add(key)
        name, version_string, source = key
        package_id = package.get("id")
        require(isinstance(package_id, str) and package_id not in identifiers, "metadata package ID missing/duplicate")
        if source is None:
            manifest = Path(package["manifest_path"]).resolve(strict=True)
            require(manifest.is_relative_to(root), "external local path dependency would cross the public source boundary")
            origin = "path:" + manifest.parent.relative_to(root).as_posix()
        else:
            origin = source
        reference = "cargo-" + digest(f"{name}\0{version_string}\0{origin}".encode())
        identifiers[package_id] = reference
        purl = f"pkg:cargo/{quote(name, safe='')}@{quote(version_string, safe='')}"
        if source and source != "registry+https://github.com/rust-lang/crates.io-index":
            qualifier = "vcs_url" if source.startswith("git+") else "repository_url"
            purl += f"?{qualifier}={quote(source.split('+', 1)[1], safe='')}"
        # Local unpublished packages carry an explicit source property; their
        # PURL identifies ecosystem/name/version without asserting publication.
        license_value = package.get("license")
        require(license_value is None or isinstance(license_value, str) and len(license_value) <= 2048, "invalid declared license expression")
        license_file = package.get("license_file")
        license_file_hash = None
        if license_file:
            base = Path(package["manifest_path"]).parent.resolve(strict=True)
            target = (base / license_file).resolve(strict=True)
            require(target.is_relative_to(base), "declared license file escapes the package root")
            license_file_hash = digest(read_file(target))
        components.append({"ref": reference, "name": name, "version": version_string, "source": origin,
                           "workspace_member": package_id in workspace_ids, "purl": purl,
                           "archive_sha256": locked[key].get("checksum"),
                           "declared_license_expression": license_value, "license_file_sha256": license_file_hash})
    require(matched == set(locked), "offline metadata omitted locked packages; inventory is incomplete")
    dependencies = []
    for node in nodes:
        require(node.get("id") in identifiers, "resolved graph contains an unknown source package")
        refs = node.get("dependencies")
        require(isinstance(refs, list) and all(item in identifiers for item in refs), "resolved graph dependency is unknown")
        dependencies.append({"ref": identifiers[node["id"]], "dependsOn": sorted({identifiers[item] for item in refs})})
    require(len(dependencies) == len(components) and len({node["ref"] for node in dependencies}) == len(components), "resolved graph omitted/duplicated package nodes")
    require(sum(len(node["dependsOn"]) for node in dependencies) <= MAX_EDGES, "resolved dependency edges exceed bounds")
    missing = sorted(item["ref"] for item in components if not item["declared_license_expression"] and not item["license_file_sha256"])
    return {"schema_version": 1, "inventory_status": "PASS", "cargo_version": version.decode().strip(),
            "metadata_command": "cargo metadata --locked --offline --format-version 1", "cargo_lock_sha256": digest(raw),
            "metadata_stdout_sha256": digest(stdout), "metadata_stderr_sha256": digest(stderr),
            "components": sorted(components, key=lambda item: (item["name"], item["version"], item["ref"])),
            "dependencies": sorted(dependencies, key=lambda item: item["ref"]),
            "licensing": {"status": "COMPLETE_DECLARATIONS" if not missing else "PARTIAL", "missing_declarations": missing,
                          "compatibility_review": "NOT RUN; declarations/file hashes are not legal compatibility findings"},
            "advisory_audit": {"status": "NOT RUN", "reason": "inventory metadata is not an advisory audit"},
            "hash_scope": "registry checksum is the locked source archive hash; local package source trees are not hashed"}


def sbom(value: dict[str, Any]) -> dict[str, Any]:
    components = []
    for item in value["components"]:
        component = {"type": "library", "bom-ref": item["ref"], "name": item["name"], "version": item["version"],
                     "purl": item["purl"], "properties": [{"name": "hearthrun:source", "value": item["source"]}]}
        if item["archive_sha256"]:
            component["hashes"] = [{"alg": "SHA-256", "content": item["archive_sha256"]}]
        if item["declared_license_expression"]:
            # Preserve the Cargo declaration without pretending this script is
            # an SPDX-expression validator. CycloneDX permits named licenses.
            component["licenses"] = [{"license": {"name": item["declared_license_expression"]}}]
        if item["license_file_sha256"]:
            component["properties"].append({"name": "hearthrun:license-file-sha256", "value": item["license_file_sha256"]})
        components.append(component)
    return {"$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": components, "dependencies": value["dependencies"], "properties": [
                {"name": "hearthrun:cargo-lock-sha256", "value": value["cargo_lock_sha256"]},
                {"name": "hearthrun:advisory-audit", "value": "NOT RUN"},
                {"name": "hearthrun:license-compatibility-review", "value": "NOT RUN"},
                {"name": "hearthrun:schema-validation", "value": "NOT RUN; independently validate against CycloneDX 1.6 schema"},
                {"name": "hearthrun:hash-scope", "value": value["hash_scope"]}]}


def audit(root: Path, tool_value: str | None, db_value: str | None) -> tuple[dict[str, Any], int]:
    if not tool_value or not db_value:
        raise Blocked("advisory audit requires --audit-tool and --audit-db; no tool installation or database fetch is performed")
    tool, database = Path(tool_value), Path(db_value)
    require(tool.is_absolute() and database.is_absolute() and tool.resolve(strict=True) == tool and database.resolve(strict=True) == database,
            "audit tool/database must be existing absolute paths without symlinks")
    tool_hash = hash_executable(tool)
    require(os.access(tool, os.X_OK) and database.is_dir(), "audit capability is not an executable and existing database directory")
    # Refuse silent ignore/target/stale settings from cargo-audit defaults.
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    if (root / ".cargo" / "audit.toml").exists() or (cargo_home / "audit.toml").exists():
        raise Blocked("cargo-audit configuration exists; independently review/remove ignore/filter/stale settings before this strict default-policy command")
    git = shutil.which("git")
    if not git:
        raise Blocked("git is needed to establish actual advisory database identity/freshness")
    code, head, _ = command([git, "-C", str(database), "log", "-1", "--format=%H %ct"], root, 15)
    require(code == 0, "advisory database Git identity unavailable")
    fields = head.decode("ascii").strip().split()
    require(len(fields) == 2 and re.fullmatch(r"[0-9a-f]{40,64}", fields[0]) is not None and fields[1].isdigit(), "advisory database commit metadata malformed")
    age = datetime.now(timezone.utc).timestamp() - int(fields[1])
    code, dirty, _ = command([git, "-C", str(database), "status", "--porcelain", "--untracked-files=normal"], root, 15)
    require(code == 0 and not dirty.strip(), "advisory database has uncommitted/untracked changes")
    code, version, _ = command([str(tool), "--version"], root, 15)
    require(code == 0 and version.startswith(b"cargo-audit "), "external tool did not identify itself as cargo-audit")
    code, help_text, _ = command([str(tool), "audit", "--help"], root, 15)
    required = (b"--format", b"--no-fetch", b"--db", b"--file", b"--deny")
    if code or not all(flag in help_text for flag in required):
        raise Blocked("installed cargo-audit lacks the required checked offline/JSON/strict-warning capabilities")
    before_lock = read_file(root / "Cargo.lock")
    code, stdout, stderr = command([str(tool), "audit", "--no-fetch", "--format", "json", "--db", str(database), "--file", str(root / "Cargo.lock"), "--deny", "warnings"], root)
    require(read_file(root / "Cargo.lock") == before_lock, "Cargo.lock changed during actual cargo-audit")
    try:
        report = parse_json(stdout)
    except (ValueError, UnicodeError) as error:
        raise Blocked(f"actual cargo-audit produced no usable JSON verdict (exit {code}; stderr_sha256={digest(stderr)})") from error
    require(isinstance(report, dict) and isinstance(report.get("vulnerabilities"), dict), "unexpected actual cargo-audit report schema")
    vulnerabilities = report["vulnerabilities"]
    require(type(vulnerabilities.get("found")) is bool and isinstance(vulnerabilities.get("list"), list), "cargo-audit vulnerability verdict missing")
    if code not in {0, 1}:
        raise Blocked(f"cargo-audit operational failure (exit {code}; stderr_sha256={digest(stderr)})")
    warnings = report.get("warnings", {})
    require(isinstance(warnings, dict), "cargo-audit warnings are malformed")
    findings = vulnerabilities["found"] or bool(vulnerabilities["list"]) or any(bool(items) for items in warnings.values())
    require(code != 0 or not findings, "cargo-audit exit status contradicts findings")
    diagnostics = stderr.decode("utf-8", errors="replace")
    for private_path, replacement in ((root, "<workspace>"), (database, "<advisory-db>"), (cargo_home, "<cargo-home>"), (Path.home(), "<home>")):
        diagnostics = diagnostics.replace(str(private_path), replacement)
    result = {"status": "FAIL" if code or findings else "PASS", "tool_version": version.decode().strip(), "tool_sha256": tool_hash,
              "database_commit": fields[0], "database_age_seconds": round(age), "offline": True,
              "staleness_policy": "cargo-audit built-in; --stale is not supplied",
              "yanked_package_check": "enabled by cargo-audit defaults against existing registry cache; no --no-yanked; inspect actual diagnostics/report for coverage errors",
              "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), "stderr_redacted": diagnostics,
              "exit_code": code, "report": report}
    return result, 1 if code or findings else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("inventory", "sbom", "licenses", "audit"), default="inventory")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--audit-tool")
    parser.add_argument("--audit-db")
    args = parser.parse_args()
    output: dict[str, Any] = {"schema_version": 1, "mode": args.mode}
    code = 1
    try:
        root = args.root.resolve(strict=True)
        require(root.is_dir() and (root / "Cargo.toml").is_file(), "--root is not a Cargo workspace")
        value = inventory(root)
        output = value
        code = 0
        if args.mode == "sbom":
            output = sbom(value)
        elif args.mode == "licenses":
            output = {"schema_version": 1, "cargo_lock_sha256": value["cargo_lock_sha256"], "licensing": value["licensing"],
                      "components": value["components"], "advisory_audit": value["advisory_audit"]}
            if value["licensing"]["missing_declarations"]:
                code = 78
        elif args.mode == "audit":
            try:
                output["advisory_audit"], code = audit(root, args.audit_tool, args.audit_db)
            except Blocked as error:
                output["advisory_audit"] = {"status": "BLOCKED", "reason": str(error)}
                code = 78
    except Blocked as error:
        output = {"schema_version": 1, "mode": args.mode, "status": "BLOCKED", "reason": str(error)}
        code = 78
    except (CheckError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not copy private absolute paths or raw Cargo metadata into public
        # inventory diagnostics. capture.py preserves the invocation separately.
        reason = str(error) if isinstance(error, CheckError) else type(error).__name__
        output = {"schema_version": 1, "mode": args.mode, "status": "FAIL", "reason": reason}
        code = 1
    encoded = json.dumps(output, sort_keys=True, indent=2).encode("utf-8")
    if len(encoded) > MAX_CAPTURE:
        print(json.dumps({"status": "FAIL", "reason": "inventory exceeds output bound"}))
        return 1
    print(encoded.decode("utf-8"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
