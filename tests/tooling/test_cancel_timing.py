"""Pure evidence-contract tests; these are not native execution evidence."""
import copy
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benchmarks"))
from cancel_timing import validate_trace

RUN="1"*32
JOB="2"*32
CLOCK={"clock":"CLOCK_MONOTONIC", "boot_id":"test-boot", "time_namespace":"time:[123]"}

class ExactTiming(unittest.TestCase):
    def setUp(self):
        self.samples=[{"run_id":RUN,"job_id":JOB,"sample_index":0,"status":"PASS",
                       "cancel_request_ns":100,"cancel_ack_ns":150,"cleanup_ns":170,"finish_ns":180}]
        self.records=[{"kind":"header","version":1,"run_id":RUN,"shard":"shard-0001","pid":12,**CLOCK},
                      {"kind":"owner_write","ordinal":1,"job_id":JOB,"receipt_ns":110,
                       "begin_ns":120,"end_ns":130,"ok":True},
                      {"kind":"footer","complete":True,"lost":0,"received":1,"events":1}]
    def check(self):
        return validate_trace(self.records,self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_preserves_raw_clock_endpoints_and_cleanup_latency(self):
        rows=self.check()
        self.assertEqual(len(rows),1)
        row=rows[0]
        self.assertEqual((row["receipt_ns"],row["begin_ns"],row["end_ns"]),(110,120,130))
        self.assertEqual((row["receipt_to_write_begin_ns"],row["write_bracket_ns"],row["receipt_to_cleanup_ns"]),(10,10,60))
    def test_missing_duplicate_wrong_job_and_ambiguous_client_fail(self):
        variants=[]
        records=copy.deepcopy(self.records);records.pop(1);variants.append((records,self.samples))
        records=copy.deepcopy(self.records);records.insert(1,copy.deepcopy(records[1]));variants.append((records,self.samples))
        records=copy.deepcopy(self.records);records[1]["job_id"]="3"*32;variants.append((records,self.samples))
        records=copy.deepcopy(self.records);records.insert(1,{**records[1],"ordinal":2});records[-1].update(events=2,received=2);variants.append((records,self.samples))
        variants.append((self.records,self.samples+self.samples))
        for records,samples in variants:
            with self.subTest(records=records,samples=samples),self.assertRaises(ValueError):
                validate_trace(records,samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_wrong_clock_session_and_loss_fail_closed(self):
        for index,key,value in [(0,"run_id","3"*32),(0,"shard","shard-0002"),(0,"clock","CLOCK_MONOTONIC_RAW"),
                                (0,"boot_id","other"),(0,"time_namespace","time:[999]"),
                                (-1,"lost",1),(-1,"complete",False),(-1,"events",2),(-1,"received",2)]:
            records=copy.deepcopy(self.records);records[index][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                validate_trace(records,self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
        with self.assertRaises(ValueError):
            validate_trace(self.records[:-1],self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_bracket_wrong_order_and_failed_write_fail(self):
        for key,value in [("receipt_ns",99),("receipt_ns",121),("begin_ns",131),("end_ns",151),
                          ("begin_ns",True),("ok",False),("begin_ns",None),("ordinal",0)]:
            records=copy.deepcopy(self.records);records[1][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                validate_trace(records,self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_deadline_worker_write_is_not_owner_attribution(self):
        event={"kind":"deadline_write","job_id":JOB,"begin_ns":125,"end_ns":135,"ok":True}
        records=copy.deepcopy(self.records);records.insert(2,event);records[-1]["events"]=2
        with self.assertRaisesRegex(ValueError,"deadline"):
            validate_trace(records,self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_no_write_event_cannot_satisfy_required_owner_clock(self):
        records=copy.deepcopy(self.records);records[1].update(kind="owner_no_write",begin_ns=None,end_ns=None,ok=False)
        with self.assertRaises(ValueError):
            validate_trace(records,self.samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_cleanup_must_follow_write_and_sample_must_be_pass(self):
        for key,value in [("cleanup_ns",115),("status","FAIL"),("finish_ns",160)]:
            samples=copy.deepcopy(self.samples);samples[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate_trace(self.records,samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
    def test_events_join_by_identity_not_concurrent_emission_order(self):
        samples=copy.deepcopy(self.samples);samples.append({**samples[0],"job_id":"3"*32,"sample_index":1})
        records=copy.deepcopy(self.records);records.insert(1,{**records[1],"job_id":"3"*32,"ordinal":2});records[-1].update(events=2,received=2)
        rows=validate_trace(records,samples,run_id=RUN,shard="shard-0001",clock_identity=CLOCK)
        self.assertEqual({r["sample_index"] for r in rows},{0,1})

if __name__=="__main__": unittest.main()
