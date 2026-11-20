# HearthRun repository contract

Purpose: bounded native-tool lifecycle, containment and artifact publication on one trusted Linux host. Read README.md and VERIFICATION_REPORT.md for the current implementation and test scope.

Order: spec/acceptance.json and ACCEPTANCE_SPEC.md; PRD.md; ARCHITECTURE.md; THREAT_MODEL.md and SECURITY.md; API.md; TEST_MATRIX.md; other docs. Do not weaken/delete locked acceptance behavior. Run `python3 scripts/check_acceptance.py` before substantial changes. A real specification error needs a preserved TEST_SPEC_EXCEPTION record and independent assessment.

One writer per module; reviewers initially read-only. Keep Rust unsafe code narrow and justified, errors explicit, resources bounded and all guest output untrusted. A child exit is not terminal completion. Missing mandatory host controls must refuse execution; never substitute a weaker backend and report equivalent protection.

Setup `make bootstrap`; build `make build`; format `make fmt`; lint `make lint`; type/static check `make typecheck`; Rust unit `make unit`; portable tests `make tooling-test`; integration `make integration`; locked acceptance `make acceptance`; security `make security`; benchmark `make bench`; live demo `make demo`; illustrative report `make demo-offline`; combined gate `make verify`; safe local teardown `make teardown`. Unimplemented targets must fail explicitly until real implementations replace them.

Use scripts/capture.py for actual command provenance. No invented terminal output, test runs, performance, deployment or screenshots. Do not suppress failing tests, silently skip, alter fixtures to fit code or replace integration with mocks. Test critical tests using controlled pass/fail/pass mutants. Follow VERIFICATION.md for independent review and clean reproduction. Update VERIFICATION_REPORT.md and CLAIMS_EVIDENCE.md after meaningful results, distinguishing PASS/FAIL/BLOCKED/NOT RUN/NOT YET MEASURED.

A human prerequisite blocks only its dependent task. Use a clear placeholder, document exact steps and continue unblocked work; never treat a mock as a real integration. Do not buy services, expose a public executor, modify unrelated user files or publish secrets. Publish only source/tests/fixtures/docs and reviewed evidence required for reproduction. Keep private research and account/session state outside this repository.

Completion requires applicable acceptance evidence, real native negative controls, independent findings followed by repairs, clean-environment build/demo/teardown and release privacy/license/security review. A green portable CI check is not completion.
