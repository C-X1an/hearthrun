# Operational host doctor

`doctor.c` runs fixed trusted operations on Linux x86-64, kernel 6.6 or later.
It executes no guest. A successful result establishes the listed host
capabilities at that instant; it does not establish the full launcher,
pre-exec barrier, combined policy, artifact exporter, crash recovery or native
acceptance. `full_launch_policy_exercised` remains `false` on success.

Build from the public repository root:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror tools/doctor.c -o /bounded/work/hearthrun-probe
```

Set an absolute `TMPDIR` inside the operator's bounded development filesystem.
Supply an existing delegated **jobs parent**, either through
`--cgroup-root /operator/delegation/jobs` or `HEARTHRUN_CGROUP_ROOT`. These are
trusted host configuration, never API/client/guest-supplied paths. The jobs
parent must be a cgroup-v2 domain, contain no processes, and have `cpu`,
`memory` and `pids` available and enabled in `cgroup.subtree_control`. Put the
supervisor/operator process in a sibling host leaf before distributing
controllers. The caller must also have cgroup migration authority at the
common ancestor of its current cgroup and the jobs parent. Owning only the
jobs directory is insufficient. The doctor never changes the parent topology
or enables controllers.

```sh
TMPDIR=/bounded/work/tmp /bounded/work/hearthrun-probe \
  --cgroup-root /operator/delegation/jobs
```

When an existing user systemd delegation owns the common ancestor, an operator
can run the doctor in a transient user scope with appropriate aggregate
memory/swap/process limits. Do not globally relax user-namespace, LSM, cgroup
or seccomp policy to obtain a positive result. A build wrapper that prohibits
nested user namespaces or hides cgroupfs is intentionally unsuitable for these
operational probes; run them on the owned compatible host with its bounded
scratch directory and resource scope.

The JSON response has `schema_version: 2`, one named feature object per check
(`passed`, numeric `errno`, bounded `detail`), `compatible` and `status`. Exit
0 / `PASS` / `compatible: true` requires every feature and cleanup check to
pass. A missing feature, operational error, unsupported reviewed ABI, invalid
operator configuration or interrupted probe produces exit 78 / `BLOCKED` /
`compatible: false`. There is no best-effort backend or successful skip.

| Check | Actual operation and observation |
|---|---|
|Platform|Linux x86-64 and parsed kernel version at least 6.6|
|Namespaces/root|Create distinct user, mount, PID, network, IPC and UTS namespaces; map one host UID/GID; deny supplementary-group changes; private propagation; set private hostname; mount a 1 MiB / 32-inode tmpfs; fork PID1; pivot into an empty root with no proc/home/dev/sys; reap its child; unmount|
|Landlock|Require ABI 3–7; handle all applicable filesystem rights through ABI7 (including REFER, TRUNCATE and, from ABI5, IOCTL_DEV); apply actual rules with no_new_privs; read allowed file; deny outside read and readonly truncate; permit same-directory hard link, then require cross-directory link to fail EXDEV with creation otherwise permitted|
|Seccomp|Install architecture-first, explicit x32-refusing tiny allowlist; permit getpid; require default-denied getppid, x32 getpid and i386 int80 getpid to return distinct expected errors|
|pidfd|Open a child pidfd, signal through it, observe exit readiness and reap the child with SIGKILL status|
|close_range|Close an owned duplicated descriptor and verify EBADF|
|openat2|Open a regular file using BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV; require ELOOP for a symlink and EXDEV for parent traversal. This does not independently exercise every flag against every possible mount/magic-link topology|
|cgroup|Create only a unique child leaf; write and read back exact limits; gate each worker until placement and membership readback; enforce pids.max=2 by real fork denial and pids.events; enforce cpu.max=50000/100000 by positive throttling counters; enforce memory.max=32 MiB, swap.max=0 and oom.group=1 by a real 64 MiB touch worker killed with positive memory max/oom_kill events; raise pids.max to 32 for a real setsid/double-fork descendant; kill via cgroup.kill; require populated=0; reap both remaining descendants; remove the leaf|
|Cleanup|Remove fixed owned fixtures, reap adopted disposable descendants and remove the exact owned cgroup. No success is emitted for uncertain cleanup|

The doctor uses smaller test limits to bound the probes. It does not certify
that the launcher's production limits, seccomp allowlist, Landlock policy or
UID/capability/descriptor drop are implemented correctly. Network and IPC
namespace creation/identity are checked; this is not an end-to-end guest
network/IPC attack suite. The seccomp alternate-architecture operation
requires the host's i386 compatibility entry; an unavailable entry is a named
probe failure. ABI newer than 7 is deliberately refused pending rights review.

Scratch files are owner-only and contain only synthetic bytes. Child policies
and mount namespaces end with the probe processes. Workers carry independent
alarms; probes have bounded waits and process-group cleanup. Cgroup ownership
is tracked across the disposable probe so a failed mkdir/EEXIST cannot cause
cleanup to kill an existing unrelated leaf. Catchable interruption is handled
through owned cgroup cleanup and adopted-child reaping. SIGKILL, host/kernel
failure and uninterruptible kernel tasks cannot be converted into cleanup
proof; an external operator must reconcile interrupted state.

`test_doctor.py` is an actual native regression harness for an already compiled
binary. It requires the same compatible host and delegated parent:

```sh
TMPDIR=/bounded/work/tmp PYTHONDONTWRITEBYTECODE=1 \
python3 scripts/capture.py --cwd . --out /bounded/work/evidence/doctor \
  --category doctor-regression --requirement SEC-001 -- \
  python3 tools/test_doctor.py --doctor /bounded/work/hearthrun-probe \
  --cgroup-root /operator/delegation/jobs
```

It exercises compatible operation, missing/relative/non-cgroup/nonexistent
roots, unknown CLI options, missing TMPDIR, environment configuration, actual
fresh-process seccomp faults denying each mandatory syscall family and
SIGTERM during a real cgroup probe. It checks structured refusal and absence
of scratch/cgroup leaks after each case. It does not mock cgroups, execute
untrusted fixtures, replace the locked acceptance suite, perform the required
six launch-policy pass/fail/pass mutants, or constitute independent review.
Capture the full operational JSON separately when retaining named-feature
evidence; the harness prints a concise case summary.
