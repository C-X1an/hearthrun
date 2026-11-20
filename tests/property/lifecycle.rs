use hearthrun_domain::{BarrierProof, Lifecycle, Outcome, State};

fn events(seed: u64) -> impl Iterator<Item = u64> {
    let mut state = seed;
    std::iter::repeat_with(move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    })
}

#[test]
fn arbitrary_event_histories_require_independent_witnesses_for_completion() {
    let mut terminal_histories = 0;
    for seed in 1..=4096 {
        let mut lifecycle = Lifecycle::default();
        let mut saw_full_barrier = false;
        let mut saw_verified_cleanup = false;
        for bits in events(seed).take(96) {
            let before = lifecycle.state();
            let flag = |offset: u32| bits & (1 << offset) != 0;
            let mut took_durable_step = false;
            let operation = match bits % 11 {
                0 => lifecycle.begin(),
                1 | 2 => {
                    let missing = (bits >> 16) as usize % 13;
                    let proof = BarrierProof {
                        cgroup_and_limits: missing != 0,
                        namespaces_and_root: missing != 1,
                        privileges_dropped: missing != 2,
                        landlock_applied: missing != 3,
                        seccomp_applied: missing != 4,
                        descriptors_closed: missing != 5,
                        output_descriptor_validated: missing != 6,
                    };
                    let result = lifecycle.release_barrier(proof);
                    if result.is_ok() {
                        assert!(missing >= 7, "seed {seed} authorized an omitted witness");
                        saw_full_barrier = true;
                    }
                    result
                }
                3 => {
                    let result = lifecycle.cancel_unlaunched(flag(8));
                    if result.is_ok() {
                        assert_eq!(before, State::Queued);
                        assert!(flag(8));
                        took_durable_step = true;
                    }
                    result
                }
                4 => lifecycle.request_stop(Outcome::Cancelled),
                5 => lifecycle.request_stop(Outcome::TimedOut),
                6 => lifecycle.observe_exit(flag(8).then_some(0)),
                7 | 8 => {
                    let result = lifecycle.confirm_cleanup(flag(8), flag(9));
                    if result.is_ok() {
                        assert!(flag(8) && flag(9), "seed {seed} used incomplete cleanup");
                        saw_verified_cleanup = true;
                    }
                    result
                }
                _ => {
                    let result = lifecycle.commit_result(flag(8), flag(9));
                    if result.is_ok() {
                        assert!(flag(8) && saw_verified_cleanup);
                        took_durable_step = true;
                    }
                    result.map(|_| ())
                }
            };
            let after = lifecycle.state();
            if operation.is_err() || matches!(before, State::Terminal(_)) {
                assert_eq!(
                    after, before,
                    "seed {seed} changed a rejected or terminal state"
                );
            }
            if after == State::Running {
                assert!(saw_full_barrier);
            }
            if after == State::Exporting {
                assert!(saw_verified_cleanup);
            }
            if matches!(after, State::Terminal(_)) && before != after {
                assert!(took_durable_step);
                terminal_histories += 1;
            }
        }
    }
    assert!(
        terminal_histories >= 3000,
        "generator did not exercise enough terminal histories"
    );
    println!("4096 deterministic domain histories, {terminal_histories} terminal observations");
}
