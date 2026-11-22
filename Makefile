PYTHON ?= python3
CC ?= cc
NATIVE_CC ?= musl-gcc
CARGO_ENV = CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
NATIVE_BIN_DIR = $(abspath $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/debug)
NATIVE_FIXTURE = $(abspath $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/hearthrun-native-task)
POLICY_FIXTURE = $(abspath $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/hearthrun-policy-probe)
RESOURCE_FIXTURE = $(abspath $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/hearthrun-resources)
NATIVE_DOCTOR = $(abspath .work/hearthrun-probe)
BENCH_BIN_DIR = $(abspath $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)/release)
.PHONY: native-prerequisites integration-run demo-run policy-fixture resource-fixture security-smoke resource-run
.PHONY: help bootstrap build fmt lint typecheck unit tooling-test doctor integration acceptance security property fuzz mutation clean-verify dependency-audit sbom license-audit public-audit benchmark-smoke bench demo demo-offline verify teardown
help:
	@printf '%s\n' 'Portable: make tooling-test; make demo-offline' 'Rust: make build fmt lint typecheck unit' 'Native: make doctor; make integration with HEARTHRUN_JOBS and HEARTHRUN_DEV_ROOT set. See OPERATIONS.md.'
bootstrap:
	$(PYTHON) scripts/check_source.py
	$(PYTHON) scripts/check_acceptance.py
	$(PYTHON) -c 'import sys; assert sys.version_info >= (3,11), "Python >=3.11 required"'
build:
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo build --workspace --locked
fmt:
	$(PYTHON) scripts/require_tool.py cargo fmt --all -- --check
lint:
	$(PYTHON) scripts/check_source.py
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo clippy --workspace --all-targets --locked -- -D warnings
typecheck:
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo check --workspace --all-targets --locked
unit:
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo test --workspace --locked
tooling-test: bootstrap
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests/tooling -v
.work/hearthrun-probe: tools/doctor.c
	mkdir -p .work
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror $< -o $@
doctor: .work/hearthrun-probe
	./.work/hearthrun-probe
native-prerequisites:
	mkdir -p '$(dir $(NATIVE_FIXTURE))'
	$(NATIVE_CC) -std=c11 -static -O2 -Wall -Wextra -Werror fixtures/native/task.c -o '$(NATIVE_FIXTURE)'
policy-fixture:
	mkdir -p '$(dir $(POLICY_FIXTURE))'
	$(NATIVE_CC) -std=c11 -static -O2 -Wall -Wextra -Werror fixtures/native/policy_probe.c -o '$(POLICY_FIXTURE)'
resource-fixture:
	mkdir -p '$(dir $(RESOURCE_FIXTURE))'
	$(NATIVE_CC) -std=c11 -static -O2 -Wall -Wextra -Werror fixtures/native/resources.c -o '$(RESOURCE_FIXTURE)'
integration: build .work/hearthrun-probe native-prerequisites
	$(MAKE) integration-run
integration-run:
	$(PYTHON) tests/e2e/native.py --bin-dir '$(NATIVE_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(NATIVE_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/integration-native-$$(date -u +%Y%m%dT%H%M%S)-$$$$"
	$(PYTHON) tests/integration/scheduler.py --bin-dir '$(NATIVE_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(NATIVE_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/integration-scheduler-$$(date -u +%Y%m%dT%H%M%S)-$$$$"
demo: build .work/hearthrun-probe native-prerequisites
	$(MAKE) demo-run
demo-run:
	$(PYTHON) tests/e2e/demo.py --bin-dir '$(NATIVE_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(NATIVE_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/demo-$$(date -u +%Y%m%dT%H%M%S)-$$$$"
resource-run:
	$(PYTHON) tests/integration/resources.py --bin-dir '$(NATIVE_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(RESOURCE_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/resources-$$(date -u +%Y%m%dT%H%M%S)-$$$$"
security-smoke:
	$(PYTHON) tests/security/policy.py --bin-dir '$(NATIVE_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(POLICY_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/policy-$$(date -u +%Y%m%dT%H%M%S)-$$$$"
property:
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo test --locked -p hearthrun-domain --test lifecycle_properties -- --nocapture
fuzz:
	$(CARGO_ENV) $(PYTHON) scripts/require_tool.py cargo test --locked -p hearthrun-domain --test protocol_corpus -- --nocapture
dependency-audit:
	$(PYTHON) scripts/dependency_inventory.py --mode audit --audit-tool "$${HEARTHRUN_CARGO_AUDIT:?set HEARTHRUN_CARGO_AUDIT}" --audit-db "$${HEARTHRUN_ADVISORY_DB:?set HEARTHRUN_ADVISORY_DB}"
sbom:
	$(PYTHON) scripts/dependency_inventory.py --mode sbom
license-audit:
	$(PYTHON) scripts/dependency_inventory.py --mode licenses
public-audit:
	$(PYTHON) scripts/public_audit.py
clean-verify:
	$(PYTHON) tests/acceptance_locked/reproduce.py --source '$(CURDIR)' --jobs "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --toolchain-bin "$${HEARTHRUN_RUST_TOOLCHAIN_BIN:?set HEARTHRUN_RUST_TOOLCHAIN_BIN}" --host-cc '$(CC)' --native-cc '$(NATIVE_CC)' --work "$${HEARTHRUN_DEV_ROOT:?set HEARTHRUN_DEV_ROOT}/r-$$$$"
benchmark-smoke: BENCH_MODE=smoke
bench: BENCH_MODE=full
benchmark-smoke bench:
	$(PYTHON) -B benchmarks/campaign.py --mode $(BENCH_MODE) --bin-dir '$(BENCH_BIN_DIR)' --doctor '$(NATIVE_DOCTOR)' --fixture '$(NATIVE_FIXTURE)' --cgroup-root "$${HEARTHRUN_JOBS:?set HEARTHRUN_JOBS}" --build-record "$${HEARTHRUN_BENCH_BUILD:?set HEARTHRUN_BENCH_BUILD}" --host-record "$${HEARTHRUN_BENCH_HOST:?set HEARTHRUN_BENCH_HOST}" --work "$${HEARTHRUN_BENCH_WORK:?set a new HEARTHRUN_BENCH_WORK}"
	$(PYTHON) -B benchmarks/analyze.py --work "$${HEARTHRUN_BENCH_WORK:?set HEARTHRUN_BENCH_WORK}"
acceptance security mutation:
	$(PYTHON) scripts/not_implemented.py $@
demo-offline:
	mkdir -p .work
	$(PYTHON) scripts/report.py fixtures/report-example.json .work/report.html --illustrative
	@printf '%s\n' 'ILLUSTRATIVE ONLY: open .work/report.html; no guest was executed.'
verify: tooling-test fmt lint typecheck unit integration acceptance security property fuzz mutation
teardown:
	$(PYTHON) -c 'from pathlib import Path; import shutil; p=Path(".work"); assert not p.is_symlink(); shutil.rmtree(p) if p.exists() else None'
