"""Synthetic evidence-contract fixtures; never native measurement evidence."""
import copy
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benchmarks"))
from analyze_exact_cancellation import compare_exact
from cancel_timing import FEATURE

RUN="1"*32
CLOCK={"clock":"CLOCK_MONOTONIC","boot_id":"test-boot","time_namespace":"time:[123]"}

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()+b"\n"

def fixture(work):
    seed=random.Random(21083).sample(range(1<<32),1)[0]
    environment={"benchmark":"B-03","boot_id":"test-boot","build":{"verification_features":[FEATURE]},
                 "clock":"clock_gettime(CLOCK_MONOTONIC)","exact_timing":{"feature":FEATURE,"clock_identity":CLOCK}}
    environment["environment_id"]=hashlib.sha256(encoded(environment)).hexdigest()
    rows=[];groups=[];teardowns=[]
    for workload in ("spin","detached","output"):
        for lanes in (1,4):
            shard=len(groups)+1;name=f"shard-{shard:04d}"
            trace=[{"kind":"header","version":1,"run_id":RUN,"shard":name,"pid":shard,**CLOCK}]
            for repetition in range(8):
                index=len(rows);job=f"{index+1:032x}"
                row={"run_id":RUN,"seed":seed,"workload":workload,"concurrency":lanes,"repetition":repetition,
                     "sample_index":index,"job_id":job,"request_id":f"req-{index}","planned_cancel_delay_ms":5,
                     "status":"PASS","state":"CANCELLED","cancel_ack":{"cancel_requested":True},
                     "submit_ns":10,"start_ns":20,"cancel_request_ns":100,"cancel_ack_ns":150,"finish_ns":190,
                     "launcher_reap_ns":160,"cleanup_ns":180,"empty_confirmed_ns":170,"empty_observed_ns":170,
                     "cancel_receipt_ns":None,"kill_request_ns":None,"empty_confirmation":"empty",
                     "launcher_reap_witness":[{"original":{"start_ticks":1},"current":None}],"output_digest":"f"*64,
                     "output_ready_bytes_per_stream":131072,"stdout_bytes":140000,"stderr_bytes":140000,
                     "cleanup_pending_observations":0}
                rows.append(row)
                trace.append({"kind":"owner_write","ordinal":repetition+1,"job_id":job,"receipt_ns":110,
                              "begin_ns":120,"end_ns":130,"ok":True})
            trace.append({"kind":"footer","complete":True,"lost":0,"received":8,"events":8})
            directory=work/name;directory.mkdir()
            (directory/"cancel-timing.jsonl").write_bytes(b"".join(encoded(row) for row in trace))
            groups.append({"workload":workload,"concurrency":lanes,"counts":{"PASS":8},"cleanup_pending_jobs":0,
                           "cancel_request_to_cleanup":{"min_ns":80,"max_ns":80,"p50_ns":80,"p95_ns":80,"p99_ns":80}})
            teardowns.append({"type":"shard_teardown","shard":shard,"jobs":8,"status":"PASS",
                              "owned_cgroups_remaining":0,"owned_children_reaped":True,
                              "exact_timing_supervisor_exit":{"pid":shard,"exit_code":0}})
    for name,value in [("environment.json",environment),("schedule.json",{"benchmark":"B-03","mode":"smoke",
        "run_id":RUN,"master_seed":21083,"seeds":[seed],"planned_jobs":48,"rows":copy.deepcopy(rows)}),
        ("summary.json",{"status":"PASS","planned":48,"counts":{"PASS":48},"groups":groups})]:
        (work/name).write_bytes(encoded(value))
    for name,batch in [("samples.jsonl",rows),("attempts.jsonl",rows),("events.jsonl",teardowns)]:
        (work/name).write_bytes(b"".join(encoded(row) for row in batch))
    return rows

class AdditiveAnalyzer(unittest.TestCase):
    def setUp(self):
        self.scratch=Path(__file__).resolve().parents[1]/"test-tmp"
        self.scratch.mkdir(exist_ok=True)
        self.context=tempfile.TemporaryDirectory(prefix="pure-",dir=self.scratch)
        self.work=Path(self.context.name)
        self.assertTrue(self.work.resolve().is_relative_to(self.scratch.resolve()))
        self.addCleanup(self.context.cleanup)
        self.rows=fixture(self.work)
    def test_uses_original_population_and_retains_every_raw_endpoint(self):
        report=compare_exact(self.work)
        self.assertEqual(report["status"],"PASS")
        self.assertEqual(len(report["raw_clocks"]),48)
        self.assertEqual(len(report["groups"]),6)
        self.assertTrue(all(row["receipt_to_cleanup_ns"]==70 for row in report["raw_clocks"]))
        self.assertEqual(report["original_cleanup_analysis"]["counts"],{"PASS":48})
    def test_valid_trace_cannot_bypass_original_reaping_witness(self):
        self.rows[0]["launcher_reap_witness"][0]["current"]={"start_ticks":1}
        (self.work/"samples.jsonl").write_bytes(b"".join(encoded(row) for row in self.rows))
        with self.assertRaisesRegex(ValueError,"still present"):
            compare_exact(self.work)
    def test_valid_trace_cannot_bypass_original_population(self):
        (self.work/"attempts.jsonl").write_bytes(b"".join(encoded(row) for row in self.rows[:-1]))
        with self.assertRaisesRegex(ValueError,"sets differ"):
            compare_exact(self.work)
    def test_wrong_session_cannot_reuse_another_shards_trace(self):
        first=self.work/"shard-0001/cancel-timing.jsonl"
        first.write_bytes((self.work/"shard-0002/cancel-timing.jsonl").read_bytes())
        with self.assertRaisesRegex(ValueError,"session"):
            compare_exact(self.work)
    def rewrite_teardown(self, mutate):
        path=self.work/"events.jsonl"
        rows=[json.loads(line) for line in path.read_bytes().splitlines()]
        mutate(rows[0])
        path.write_bytes(b"".join(encoded(row) for row in rows))
    def test_exact_analyzer_rejects_missing_owned_supervisor_exit(self):
        self.rewrite_teardown(lambda row:row.pop("exact_timing_supervisor_exit"))
        with self.assertRaisesRegex(ValueError,"supervisor"):
            compare_exact(self.work)
    def test_exact_analyzer_rejects_nonzero_collector_owner_exit(self):
        self.rewrite_teardown(lambda row:row["exact_timing_supervisor_exit"].update(exit_code=1))
        with self.assertRaisesRegex(ValueError,"supervisor"):
            compare_exact(self.work)
    def test_exact_analyzer_rejects_another_successful_child_pid(self):
        self.rewrite_teardown(lambda row:row["exact_timing_supervisor_exit"].update(pid=9999))
        with self.assertRaisesRegex(ValueError,"supervisor"):
            compare_exact(self.work)
    def test_client_analyzer_retains_historical_teardown_contract(self):
        import analyze_cancellation
        self.rewrite_teardown(lambda row:row.pop("exact_timing_supervisor_exit"))
        self.assertEqual(analyze_cancellation.compare_population(self.work)["status"],"PASS")

if __name__=="__main__":unittest.main()
