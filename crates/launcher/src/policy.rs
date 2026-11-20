//! Irreversible guest policy for the fresh, single-threaded Linux x86-64 launcher.
//!
//! The caller first completes cgroup placement, namespaces, private mounts,
//! credential/capability drop and descriptor closure. Only the private gate
//! pipes and guest stdio may remain when these functions run. Landlock does not
//! revoke authority already held by inherited descriptors. After enforcement the
//! authenticated gate uses read/write/close, then execve of /bin/task. No setup,
//! networking, descriptor-transfer, tracing or policy-installation call is in
//! the guest allowlist. An error denies release of that gate; never retry with a
//! weaker policy. This source is a policy definition, not native test evidence.

#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;

const POLICY_VERSION: &[u8] = b"hearthrun-guest-policy-v1\0linux-x86_64\0";
const DEPENDENCY_POLICY: &[u8] = b"landlock=0.4.7;seccompiler=0.5.0;libc=0.2.191;rustix=1.1.6\0";
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const MAX_BPF_INSTRUCTIONS: usize = 4096;

// Explicit clone equality, never a mask accepting unreviewed flags. glibc's
// fork uses CHILD_SETTID|CHILD_CLEARTID|SIGCHLD. Raw fork/clone without those TID
// stores is also supported. The vfork variant shares the calling address space
// only while the caller is suspended until exec/exit; it remains in the same
// namespaces, cgroup, credentials and inherited Landlock/seccomp domain.
const CLONE_FLAGS: [u64; 3] = [
    libc::SIGCHLD as u64,
    (libc::SIGCHLD | libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID) as u64,
    (libc::SIGCHLD | libc::CLONE_VM | libc::CLONE_VFORK) as u64,
];

/// Query the actual kernel ABI. Unknown newer ABIs require a policy review,
/// even when the installed crate knows how to represent them.
pub fn landlock_abi() -> io::Result<u32> {
    // SAFETY: the VERSION query takes a null attributes pointer and size zero;
    // it reads/writes no pointed-to memory and returns an ABI integer, not an FD.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let abi = u32::try_from(result).map_err(|_| unsupported("invalid Landlock ABI response"))?;
    selected_abi(abi)?;
    Ok(abi)
}

fn selected_abi(abi: u32) -> io::Result<ABI> {
    match abi {
        3 => Ok(ABI::V3),
        4 => Ok(ABI::V4),
        5 => Ok(ABI::V5),
        6 => Ok(ABI::V6),
        7 => Ok(ABI::V7),
        _ => Err(unsupported(
            "Landlock ABI must be within reviewed range 3..=7",
        )),
    }
}

fn output_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
        | AccessFs::Truncate
}

/// Enforce all filesystem rights applicable to the exact queried ABI, with no
/// best-effort compatibility. No execute, device, FIFO, socket or symlink-create
/// right is granted under /out. /in is read-only and only /bin/task can execute.
/// The caller must have constructed these fixed paths in its private root.
pub fn apply_landlock(abi: u32) -> io::Result<()> {
    let selected = selected_abi(abi)?;
    if landlock_abi()? != abi {
        return Err(unsupported(
            "Landlock ABI differs from the probed configuration",
        ));
    }
    let task = open_policy_path("/bin/task", FileType::RegularFile)?;
    let input = open_policy_path("/in", FileType::Directory)?;
    let output = open_policy_path("/out", FileType::Directory)?;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(selected))
        .map_err(policy_error)?;
    if abi >= 4 {
        // Handle all TCP bind/connect rights, with no port exceptions. Seccomp
        // separately denies every socket syscall, including non-TCP protocols.
        ruleset = ruleset
            .handle_access(AccessNet::from_all(selected))
            .map_err(policy_error)?;
    }
    if abi >= 6 {
        // Signals to processes outside this domain and external abstract UNIX
        // sockets are forbidden. Descendants inherit this domain and may still
        // signal one another within their private PID namespace.
        ruleset = ruleset
            .scope(Scope::from_all(selected))
            .map_err(policy_error)?;
    }
    let status = ruleset
        .create()
        .map_err(policy_error)?
        .no_new_privs(true)
        .add_rule(PathBeneath::new(
            task,
            AccessFs::ReadFile | AccessFs::Execute,
        ))
        .map_err(policy_error)?
        .add_rule(PathBeneath::new(
            input,
            AccessFs::ReadFile | AccessFs::ReadDir,
        ))
        .map_err(policy_error)?
        .add_rule(PathBeneath::new(output, output_access()))
        .map_err(policy_error)?
        .restrict_self()
        .map_err(policy_error)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(unsupported(
            "Landlock did not fully enforce the required policy and NNP",
        ));
    }
    Ok(())
}

fn open_policy_path(path: &str, expected: FileType) -> io::Result<OwnedFd> {
    // These are fixed trusted paths in the freshly constructed root. Bind
    // mounts are intentional, so NO_XDEV/BENEATH are not appropriate here;
    // symlinks and proc-style magic links are rejected at every component.
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    if FileType::from_raw_mode(fs::fstat(&fd)?.st_mode) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Landlock policy path type mismatch",
        ));
    }
    Ok(fd)
}

/// Compile the reviewed guest syscall policy before installing restrictions.
/// Unlisted calls return EPERM. clone3 returns ENOSYS for libc's audited fork
/// fallback. Architecture mismatch and the x32 syscall bit kill the process.
pub fn prepare_seccomp() -> io::Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Native static-runtime memory management, TLS bookkeeping and signals.
    // These operate only on this process's address space. No executable file
    // authority is obtained here: mounts and Landlock constrain file mappings.
    let runtime = [
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    // Bounded stdio/gate pipes, private-root input/output and artifact creation.
    // The caller closes all host/control FDs first; Landlock then limits new
    // opens and mutations. No ioctl, sendmsg/recvmsg, or special-node creation.
    let io_calls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_lseek,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_getdents64,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat2,
        libc::SYS_readlinkat,
    ];
    // Local clocks/identities/randomness and ordinary POSIX child management.
    // PID namespace placement is mandatory before this policy is installed;
    // descendants additionally remain bounded/accounted by the job cgroup.
    let process_calls = [
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_execve,
    ];
    for syscall in runtime.into_iter().chain(io_calls).chain(process_calls) {
        if rules.insert(syscall, Vec::new()).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate policy syscall",
            ));
        }
    }

    let clone_rules = CLONE_FLAGS
        .into_iter()
        .map(|flags| exact_rule(&[(0, flags)]))
        .collect::<io::Result<Vec<_>>>()?;
    rules.insert(libc::SYS_clone, clone_rules);

    // TLS setup/query only; no arbitrary arch_prctl extension or mapping calls.
    rules.insert(
        libc::SYS_arch_prctl,
        vec![
            exact_rule(&[(0, 0x1002)])?, // ARCH_SET_FS
            exact_rule(&[(0, 0x1003)])?, // ARCH_GET_FS
        ],
    );
    // Static glibc queries its own stack limit at startup. Reading is permitted;
    // changing a limit or querying another process is not.
    rules.insert(libc::SYS_prlimit64, vec![exact_rule(&[(0, 0), (2, 0)])?]);

    let mut fcntl = Vec::new();
    for command in [
        libc::F_DUPFD,
        libc::F_DUPFD_CLOEXEC,
        libc::F_GETFD,
        libc::F_GETFL,
        libc::F_SETFL,
    ] {
        fcntl.push(exact_rule(&[(1, command as u64)])?);
    }
    for flags in [0, libc::FD_CLOEXEC] {
        fcntl.push(exact_rule(&[(1, libc::F_SETFD as u64), (2, flags as u64)])?);
    }
    rules.insert(libc::SYS_fcntl, fcntl);

    let compiled: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(policy_error)?
    .try_into()
    .map_err(policy_error)?;

    // This tiny fixed prefix only handles decisions not expressible with the
    // compiler's single on-match action. It precedes every generated decision.
    // All jumps are relative, so prepending preserves the compiled program.
    let mut program = vec![
        instruction(0x20, 0, 0, 4),                 // LD W ABS seccomp_data.arch
        instruction(0x15, 1, 0, AUDIT_ARCH_X86_64), // JEQ expected -> skip KILL
        instruction(0x06, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        instruction(0x20, 0, 0, 0), // LD W ABS seccomp_data.nr
        instruction(0x45, 0, 1, X32_SYSCALL_BIT), // JSET x32 -> KILL
        instruction(0x06, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        instruction(0x15, 0, 1, libc::SYS_clone3 as u32), // JEQ clone3 -> ENOSYS
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
    ];
    program.extend(compiled);
    if program.len() > MAX_BPF_INSTRUCTIONS {
        return Err(unsupported(
            "compiled seccomp policy exceeds kernel instruction bound",
        ));
    }
    Ok(program)
}

fn exact_rule(arguments: &[(u8, u64)]) -> io::Result<SeccompRule> {
    let conditions = arguments
        .iter()
        .map(|(index, value)| {
            // Full-width equality also rejects unreviewed high argument bits.
            SeccompCondition::new(*index, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, *value)
                .map_err(policy_error)
        })
        .collect::<io::Result<Vec<_>>>()?;
    SeccompRule::new(conditions).map_err(policy_error)
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Install only the exact program produced by this policy version. This avoids
/// accepting an empty, truncated or caller-modified program as equivalent policy.
/// The calling launcher must remain single-threaded; children inherit the filter.
pub fn apply_seccomp(program: &[sock_filter]) -> io::Result<()> {
    let expected = prepare_seccomp()?;
    if program.len() != expected.len()
        || program.iter().zip(&expected).any(|(actual, expected)| {
            actual.code != expected.code
                || actual.jt != expected.jt
                || actual.jf != expected.jf
                || actual.k != expected.k
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "seccomp program differs from reviewed policy",
        ));
    }
    // seccompiler sets NNP and checks both prctl and seccomp syscall results.
    seccompiler::apply_filter(program).map_err(policy_error)
}

/// Stable policy identity, not proof of enforcement. Source bytes include every
/// rule and prefix; the selected ABI and reviewed dependency versions are bound
/// separately. Compute/store this before guest execution. An unsupported ABI
/// digest never authorizes execution; landlock_abi/apply_landlock still refuse it.
pub fn policy_digest(abi: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_VERSION);
    hasher.update(DEPENDENCY_POLICY);
    hasher.update(abi.to_be_bytes());
    hasher.update(include_bytes!("policy.rs"));
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in hasher.finalize() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    encoded
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn policy_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("guest policy failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small, non-kernel cBPF evaluator exercises generated decisions against
    // synthetic seccomp_data. It installs nothing and makes no guest syscalls;
    // these checks do not establish native policy enforcement.
    fn decision(program: &[sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        for _ in 0..=program.len() {
            let insn = program.get(pc).expect("BPF ran outside program");
            pc += 1;
            match insn.code {
                0x20 => {
                    accumulator = match insn.k {
                        0 => nr,
                        4 => arch,
                        offset if (16..64).contains(&offset) && offset % 4 == 0 => {
                            let value = args[((offset - 16) / 8) as usize];
                            if offset % 8 == 0 {
                                value as u32
                            } else {
                                (value >> 32) as u32
                            }
                        }
                        _ => panic!("unsupported seccomp_data load"),
                    };
                }
                0x05 => pc += insn.k as usize,
                0x15 | 0x25 | 0x35 | 0x45 => {
                    let yes = match insn.code {
                        0x15 => accumulator == insn.k,
                        0x25 => accumulator > insn.k,
                        0x35 => accumulator >= insn.k,
                        0x45 => accumulator & insn.k != 0,
                        _ => unreachable!(),
                    };
                    pc += if yes { insn.jt } else { insn.jf } as usize;
                }
                0x54 => accumulator &= insn.k,
                0x06 => return insn.k,
                _ => panic!("unreviewed generated BPF opcode"),
            }
        }
        panic!("BPF failed to terminate within forward-program bound")
    }

    #[test]
    fn architecture_and_clone3_decisions_precede_syscall_allowances() {
        let program = prepare_seccomp().unwrap();
        assert_eq!(
            decision(&program, AUDIT_ARCH_X86_64, libc::SYS_read as u32, [0; 6]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            decision(&program, 0x4000_0003, libc::SYS_read as u32, [0; 6]),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            decision(
                &program,
                AUDIT_ARCH_X86_64,
                X32_SYSCALL_BIT | libc::SYS_read as u32,
                [0; 6]
            ),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            decision(&program, AUDIT_ARCH_X86_64, libc::SYS_clone3 as u32, [0; 6]),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        for syscall in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_mount,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_ioctl,
            libc::SYS_memfd_create,
            libc::SYS_seccomp,
            libc::SYS_landlock_create_ruleset,
            libc::SYS_execveat,
            999_999,
        ] {
            assert_eq!(
                decision(&program, AUDIT_ARCH_X86_64, syscall as u32, [0; 6]),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
    }

    #[test]
    fn clone_is_exact_and_limit_changes_are_denied() {
        let program = prepare_seccomp().unwrap();
        for flags in CLONE_FLAGS {
            assert_eq!(
                decision(
                    &program,
                    AUDIT_ARCH_X86_64,
                    libc::SYS_clone as u32,
                    [flags, 0, 0, 0, 0, 0]
                ),
                libc::SECCOMP_RET_ALLOW
            );
        }
        for flag in [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_PARENT,
            libc::CLONE_PTRACE,
            libc::CLONE_THREAD,
        ] {
            let flags = CLONE_FLAGS[1] | flag as u64;
            assert_eq!(
                decision(
                    &program,
                    AUDIT_ARCH_X86_64,
                    libc::SYS_clone as u32,
                    [flags, 0, 0, 0, 0, 0]
                ),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
        assert_eq!(
            decision(
                &program,
                AUDIT_ARCH_X86_64,
                libc::SYS_clone as u32,
                [CLONE_FLAGS[1] | (1 << 63), 0, 0, 0, 0, 0]
            ),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            decision(
                &program,
                AUDIT_ARCH_X86_64,
                libc::SYS_prlimit64 as u32,
                [0; 6]
            ),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            decision(
                &program,
                AUDIT_ARCH_X86_64,
                libc::SYS_prlimit64 as u32,
                [0, 0, 1, 0, 0, 0]
            ),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            decision(
                &program,
                AUDIT_ARCH_X86_64,
                libc::SYS_fcntl as u32,
                [0, libc::F_SETOWN as u64, 0, 0, 0, 0]
            ),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
    }

    #[test]
    fn landlock_rights_and_policy_identity_are_bounded() {
        for abi in 3..=7 {
            let selected = selected_abi(abi).unwrap();
            assert!(AccessFs::from_all(selected).contains(output_access()));
            assert!(!output_access().intersects(
                AccessFs::Execute
                    | AccessFs::MakeChar
                    | AccessFs::MakeBlock
                    | AccessFs::MakeFifo
                    | AccessFs::MakeSock
                    | AccessFs::MakeSym
            ));
        }
        for abi in [0, 1, 2, 8, 9, u32::MAX] {
            assert!(selected_abi(abi).is_err());
        }
        let digest = policy_digest(3);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(digest, policy_digest(3));
        assert_ne!(digest, policy_digest(4));
    }
}
