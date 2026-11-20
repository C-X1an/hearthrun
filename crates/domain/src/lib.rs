//! Pure contract primitives. This crate does not isolate or execute a process.
//!
//! Proof structs represent observations supplied by the future trusted supervisor;
//! constructing one here does not prove a kernel control was applied.
#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

pub mod protocol;

pub const MAX_RUNNING: usize = 4;
pub const MAX_QUEUED: usize = 16;
pub const MAX_HEADER_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPath,
    InvalidId,
    InvalidFrame,
    InvalidTransition,
    MissingProof,
    QueueFull,
    Duplicate,
    NotFound,
}

pub fn validate_logical_path(path: &str) -> Result<(), Error> {
    if path.is_empty() || path.len() > 240 || !path.is_ascii() {
        return Err(Error::InvalidPath);
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() > 8 {
        return Err(Error::InvalidPath);
    }
    for part in parts {
        if part.is_empty() || part == "." || part == ".." || part.len() > 64 {
            return Err(Error::InvalidPath);
        }
        if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(Error::InvalidPath);
        }
    }
    Ok(())
}

/// A normal non-staging header frame. JSON semantic validation is a separate layer.
pub fn decode_header(frame: &[u8]) -> Result<&str, Error> {
    let header: [u8; 4] = frame
        .get(..4)
        .ok_or(Error::InvalidFrame)?
        .try_into()
        .map_err(|_| Error::InvalidFrame)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_HEADER_BYTES || frame.len() != length + 4 {
        return Err(Error::InvalidFrame);
    }
    std::str::from_utf8(&frame[4..]).map_err(|_| Error::InvalidFrame)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId([u8; 16]);

impl JobId {
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidId);
        }
        let mut bytes = [0_u8; 16];
        for (i, item) in bytes.iter_mut().enumerate() {
            *item =
                u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::InvalidId)?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Running,
    Queued,
}

#[derive(Debug, Default)]
pub struct AdmissionQueue {
    running: HashSet<JobId>,
    queued: VecDeque<JobId>,
}

impl AdmissionQueue {
    pub fn admit(&mut self, id: JobId) -> Result<Admission, Error> {
        if self.running.contains(&id) || self.queued.contains(&id) {
            return Err(Error::Duplicate);
        }
        if self.running.len() < MAX_RUNNING && self.queued.is_empty() {
            self.running.insert(id);
            return Ok(Admission::Running);
        }
        if self.queued.len() >= MAX_QUEUED {
            return Err(Error::QueueFull);
        }
        self.queued.push_back(id);
        Ok(Admission::Queued)
    }

    /// Caller must supply a true, verified cleanup observation before slot reuse.
    pub fn release(&mut self, id: JobId, cleanup_confirmed: bool) -> Result<Option<JobId>, Error> {
        if !cleanup_confirmed {
            return Err(Error::MissingProof);
        }
        if !self.running.remove(&id) {
            return Err(Error::NotFound);
        }
        let next = self.queued.pop_front();
        if let Some(id) = next {
            self.running.insert(id);
        }
        Ok(next)
    }

    pub fn cancel_queued(&mut self, id: JobId) -> Result<(), Error> {
        let index = self
            .queued
            .iter()
            .position(|item| *item == id)
            .ok_or(Error::NotFound)?;
        self.queued.remove(index);
        Ok(())
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.running.len(), self.queued.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Queued,
    Starting,
    Running,
    Cancelling,
    CleanupPending,
    Exporting,
    Terminal(Outcome),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Interrupted,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BarrierProof {
    pub cgroup_and_limits: bool,
    pub namespaces_and_root: bool,
    pub privileges_dropped: bool,
    pub landlock_applied: bool,
    pub seccomp_applied: bool,
    pub descriptors_closed: bool,
    pub output_descriptor_validated: bool,
}
impl BarrierProof {
    fn complete(self) -> bool {
        self.cgroup_and_limits
            && self.namespaces_and_root
            && self.privileges_dropped
            && self.landlock_applied
            && self.seccomp_applied
            && self.descriptors_closed
            && self.output_descriptor_validated
    }
}

#[derive(Debug)]
pub struct Lifecycle {
    state: State,
    requested: Option<Outcome>,
    exit_code: Option<i32>,
}
impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: State::Queued,
            requested: None,
            exit_code: None,
        }
    }
}
impl Lifecycle {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn begin(&mut self) -> Result<(), Error> {
        if self.state != State::Queued {
            return Err(Error::InvalidTransition);
        }
        self.state = State::Starting;
        Ok(())
    }
    pub fn release_barrier(&mut self, proof: BarrierProof) -> Result<(), Error> {
        if self.state != State::Starting {
            return Err(Error::InvalidTransition);
        }
        if !proof.complete() {
            return Err(Error::MissingProof);
        }
        self.state = State::Running;
        Ok(())
    }
    /// Queued cancellation is terminal only after a no-launch decision is durable.
    pub fn cancel_unlaunched(&mut self, decision_durable: bool) -> Result<(), Error> {
        if self.state != State::Queued {
            return Err(Error::InvalidTransition);
        }
        if !decision_durable {
            return Err(Error::MissingProof);
        }
        self.state = State::Terminal(Outcome::Cancelled);
        Ok(())
    }
    pub fn request_stop(&mut self, reason: Outcome) -> Result<(), Error> {
        if !matches!(
            reason,
            Outcome::Cancelled | Outcome::TimedOut | Outcome::Interrupted | Outcome::Failed
        ) {
            return Err(Error::InvalidTransition);
        }
        if matches!(self.state, State::Terminal(_)) {
            return Ok(());
        }
        if !matches!(
            self.state,
            State::Starting
                | State::Running
                | State::Cancelling
                | State::CleanupPending
                | State::Exporting
        ) {
            return Err(Error::InvalidTransition);
        }
        // First reason wins; cancellation cannot turn an already committed result into failure.
        if self.requested.is_none() {
            self.requested = Some(reason);
        }
        if matches!(self.state, State::Starting | State::Running) {
            self.state = State::Cancelling;
        }
        Ok(())
    }
    pub fn observe_exit(&mut self, exit_code: Option<i32>) -> Result<(), Error> {
        if !matches!(
            self.state,
            State::Starting | State::Running | State::Cancelling
        ) {
            return Err(Error::InvalidTransition);
        }
        self.exit_code = exit_code;
        self.state = State::CleanupPending;
        Ok(())
    }
    pub fn confirm_cleanup(
        &mut self,
        launcher_reaped: bool,
        cgroup_empty: bool,
    ) -> Result<(), Error> {
        if self.state != State::CleanupPending {
            return Err(Error::InvalidTransition);
        }
        if !launcher_reaped || !cgroup_empty {
            return Err(Error::MissingProof);
        }
        self.state = State::Exporting;
        Ok(())
    }
    /// Plan the record without releasing capacity or advertising a terminal state.
    pub fn candidate_outcome(&self, artifacts_valid: bool) -> Result<Outcome, Error> {
        if self.state != State::Exporting {
            return Err(Error::InvalidTransition);
        }
        Ok(if !artifacts_valid {
            Outcome::Failed
        } else if let Some(reason) = self.requested {
            reason
        } else if self.exit_code == Some(0) {
            Outcome::Succeeded
        } else {
            Outcome::Failed
        })
    }

    /// Publication failure must itself be recorded durably before a terminal record is exposed.
    pub fn commit_result(
        &mut self,
        record_durable: bool,
        artifacts_valid: bool,
    ) -> Result<Outcome, Error> {
        let outcome = self.candidate_outcome(artifacts_valid)?;
        if !record_durable {
            return Err(Error::MissingProof);
        }
        self.state = State::Terminal(outcome);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(i: u8) -> JobId {
        JobId([i; 16])
    }
    fn proof() -> BarrierProof {
        BarrierProof {
            cgroup_and_limits: true,
            namespaces_and_root: true,
            privileges_dropped: true,
            landlock_applied: true,
            seccomp_applied: true,
            descriptors_closed: true,
            output_descriptor_validated: true,
        }
    }
    fn running() -> Lifecycle {
        let mut x = Lifecycle::default();
        x.begin().unwrap();
        x.release_barrier(proof()).unwrap();
        x
    }
    #[test]
    fn valid_paths() {
        for p in ["data.ndjson", "a/b-c_1.txt", ".hidden"] {
            assert_eq!(validate_logical_path(p), Ok(()));
        }
    }
    #[test]
    fn invalid_paths() {
        for p in ["", "/etc/passwd", "a/../b", "a//b", "a\\b", "a/./b", "a\0b"] {
            assert_eq!(validate_logical_path(p), Err(Error::InvalidPath));
        }
    }
    #[test]
    fn path_boundaries() {
        assert!(validate_logical_path(&"a".repeat(65)).is_err());
        assert!(validate_logical_path("a/b/c/d/e/f/g/h/i").is_err());
        assert!(validate_logical_path(&"a".repeat(64)).is_ok());
    }
    #[test]
    fn ids_are_bounded_and_lowercase() {
        assert!(JobId::parse(&"ab".repeat(16)).is_ok());
        for p in ["A".repeat(32), "g".repeat(32), "a".repeat(31)] {
            assert!(JobId::parse(&p).is_err());
        }
    }
    #[test]
    fn frame_rejects_trailing_and_bad_utf8() {
        assert_eq!(decode_header(b"\0\0\0\x02{}"), Ok("{}"));
        assert!(decode_header(b"\0\0\0\x02{}x").is_err());
        assert!(decode_header(&[0, 0, 0, 1, 255]).is_err());
    }
    #[test]
    fn oversized_frame() {
        assert!(decode_header(&[0, 1, 0, 1]).is_err());
        assert!(decode_header(&[]).is_err());
    }
    #[test]
    fn queue_bound_and_fifo() {
        let mut q = AdmissionQueue::default();
        for i in 0..20 {
            assert!(q.admit(id(i)).is_ok());
        }
        assert_eq!(q.admit(id(20)), Err(Error::QueueFull));
        assert_eq!(q.counts(), (4, 16));
        assert_eq!(q.release(id(0), true), Ok(Some(id(4))));
    }
    #[test]
    fn queue_duplicate() {
        let mut q = AdmissionQueue::default();
        q.admit(id(0)).unwrap();
        assert_eq!(q.admit(id(0)), Err(Error::Duplicate));
    }
    #[test]
    fn cleanup_blocks_slot_reuse() {
        let mut q = AdmissionQueue::default();
        q.admit(id(0)).unwrap();
        assert_eq!(q.release(id(0), false), Err(Error::MissingProof));
        assert_eq!(q.counts(), (1, 0));
    }
    #[test]
    fn queued_cancel_preserves_others() {
        let mut q = AdmissionQueue::default();
        for i in 0..6 {
            q.admit(id(i)).unwrap();
        }
        q.cancel_queued(id(4)).unwrap();
        assert_eq!(q.release(id(0), true), Ok(Some(id(5))));
    }
    #[test]
    fn barrier_fail_closed() {
        let mut x = Lifecycle::default();
        x.begin().unwrap();
        let mut p = proof();
        p.landlock_applied = false;
        assert_eq!(x.release_barrier(p), Err(Error::MissingProof));
        assert_eq!(x.state(), State::Starting);
    }
    #[test]
    fn leader_exit_is_not_completion() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        assert_eq!(x.state(), State::CleanupPending);
        assert_eq!(x.confirm_cleanup(true, false), Err(Error::MissingProof));
        assert_eq!(x.commit_result(true, true), Err(Error::InvalidTransition));
    }
    #[test]
    fn reaping_is_required() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        assert_eq!(x.confirm_cleanup(false, true), Err(Error::MissingProof));
    }
    #[test]
    fn publication_must_be_durable() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        x.confirm_cleanup(true, true).unwrap();
        assert_eq!(x.commit_result(false, true), Err(Error::MissingProof));
        assert_eq!(x.commit_result(true, true), Ok(Outcome::Succeeded));
    }
    #[test]
    fn invalid_artifacts_never_succeed() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        x.confirm_cleanup(true, true).unwrap();
        assert_eq!(x.commit_result(true, false), Ok(Outcome::Failed));
    }
    #[test]
    fn timeout_survives_zero_exit() {
        let mut x = running();
        x.request_stop(Outcome::TimedOut).unwrap();
        x.observe_exit(Some(0)).unwrap();
        x.confirm_cleanup(true, true).unwrap();
        assert_eq!(x.commit_result(true, true), Ok(Outcome::TimedOut));
    }
    #[test]
    fn cancel_during_export_precedes_commit() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        x.confirm_cleanup(true, true).unwrap();
        x.request_stop(Outcome::Cancelled).unwrap();
        assert_eq!(x.commit_result(true, true), Ok(Outcome::Cancelled));
    }
    #[test]
    fn committed_result_wins_late_cancel() {
        let mut x = running();
        x.observe_exit(Some(0)).unwrap();
        x.confirm_cleanup(true, true).unwrap();
        x.commit_result(true, true).unwrap();
        x.request_stop(Outcome::Cancelled).unwrap();
        assert_eq!(x.state(), State::Terminal(Outcome::Succeeded));
    }
    #[test]
    fn queued_cancel_requires_durable_decision() {
        let mut x = Lifecycle::default();
        assert_eq!(x.cancel_unlaunched(false), Err(Error::MissingProof));
        x.cancel_unlaunched(true).unwrap();
        assert_eq!(x.state(), State::Terminal(Outcome::Cancelled));
    }
}
