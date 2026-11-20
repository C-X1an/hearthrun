# Security policy and boundary

HearthRun is an experimental single-host native execution workbench. Its boundary assumes a trusted Linux kernel, host owner, launcher and approved configuration. Guest executables and guest-controlled data are untrusted. [Release readiness](RELEASE_READINESS.md)

Run adversarial fixtures only on an owned disposable Linux test host. Do not expose the Unix socket through an unauthenticated network proxy. Do not pass real credentials, mount your home directory or Docker socket, or lower host protections to make the demo work. Missing mandatory features cause refusal. Native execution tests are not satisfied by mocks or by unit tests of policy structures.

See THREAT_MODEL.md, ARCHITECTURE.md and ACCEPTANCE_SPEC.md for controls, residual risks and required verification. Kernel exploits and side channels are outside the claim. A successful named test demonstrates only its declared behavior/environment.

## Reporting
Use GitHub's private vulnerability reporting for this repository once enabled. Do not post secrets or a working host-escape exploit in public issues. No response-time guarantee is offered. Until publication/maintainer configuration is completed, this package contains no live reporting endpoint.

## Supported versions
No released version is supported yet. A release must state exact source commit, dependency lock, kernel features, policy hash and acceptance evidence. Security fixes require affected tests and negative controls to rerun. CI credentials remain read-only for public pull requests; native privileged checks run only on trusted commits on disposable infrastructure.
