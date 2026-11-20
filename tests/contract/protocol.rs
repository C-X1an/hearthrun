//! Pure v1 contracts. Full AC-001 additionally requires live socket/UID tests.
use hearthrun_domain::protocol::{parse_request, read_request, strict_json, Code, Request};
use serde_json::{json, Value};
use std::io::Cursor;

fn submit() -> Value {
    json!({"v":1,"op":"submit","request_id":"11".repeat(16),"profile_id":"summarize-v1",
           "stage_id":"22".repeat(16),"argv":[],"wall_ms":10000})
}
fn parse(value: &Value) -> Result<Request, Code> {
    parse_request(&serde_json::to_vec(value).unwrap()).map_err(|e| e.code)
}

#[test]
fn decoded_duplicate_keys_are_rejected_at_every_depth() {
    for bytes in [
        br#"{"v":1,"v":1,"op":"doctor"}"#.as_slice(),
        br#"{"v":1,"op":"stage","files":[{"path":"a","size":0,"sha256":"x","size":0}]}"#,
        br#"{"v":1,"op":"doctor","\u0076":1}"#,
    ] {
        assert_eq!(parse_request(bytes).unwrap_err().code, Code::DuplicateKey);
    }
}

#[test]
fn numbers_trailing_data_unicode_and_depth_fail_closed() {
    for bytes in [
        br#"{"v":1.0,"op":"doctor"}"#.as_slice(),
        br#"{"v":1e0,"op":"doctor"}"#,
        br#"{"v":1,"op":"doctor"}{}"#,
        br#"{"v":NaN,"op":"doctor"}"#,
        br#"{"v":18446744073709551616,"op":"doctor"}"#,
        br#"{"v":1,"op":"doctor","x":"\ud800"}"#,
    ] {
        assert_eq!(parse_request(bytes).unwrap_err().code, Code::BadJson);
    }
    assert_eq!(strict_json(&[255]).unwrap_err().code, Code::BadJson);
    let okay = format!("{}0{}", "[".repeat(16), "]".repeat(16));
    let deep = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    assert!(strict_json(okay.as_bytes()).is_ok());
    assert_eq!(
        strict_json(deep.as_bytes()).unwrap_err().code,
        Code::BadJson
    );
}

#[test]
fn unknown_fields_versions_and_injected_authority_are_rejected() {
    for field in ["mounts", "env", "uid", "command", "host_path"] {
        let mut value = submit();
        value[field] = json!("untrusted");
        assert_eq!(parse(&value), Err(Code::UnknownField));
    }
    assert_eq!(
        parse(&json!({"v":2,"op":"doctor"})),
        Err(Code::UnsupportedVersion)
    );
    assert_eq!(
        parse(&json!({"v":1,"op":"doctor","extra":0})),
        Err(Code::UnknownField)
    );
    assert_eq!(
        parse(
            &json!({"v":1,"op":"stage","files":[{"path":"a","size":0,"sha256":"00".repeat(32),"extra":0}]})
        ),
        Err(Code::UnknownField)
    );
}

#[test]
fn argv_counts_utf8_bytes_and_boundaries() {
    let mut value = submit();
    value["argv"] = json!(["é".repeat(2048)]);
    assert!(parse(&value).is_ok());
    value["argv"] = json!(["é".repeat(2049)]);
    assert_eq!(parse(&value), Err(Code::InvalidLimit));
    value["argv"] = json!(["a\0b"]);
    assert_eq!(parse(&value), Err(Code::InvalidLimit));
    value["argv"] = json!(vec![""; 33]);
    assert_eq!(parse(&value), Err(Code::InvalidLimit));
    value["argv"] = json!(vec![""; 32]);
    assert!(parse(&value).is_ok());
}

#[test]
fn ids_profiles_and_wall_boundaries_follow_contract() {
    let mut value = submit();
    for ms in [100, 60000] {
        value["wall_ms"] = json!(ms);
        assert!(parse(&value).is_ok());
    }
    for ms in [-1, 99, 60001] {
        value["wall_ms"] = json!(ms);
        assert_eq!(parse(&value), Err(Code::InvalidLimit));
    }
    value = submit();
    value["request_id"] = json!("AB".repeat(16));
    assert_eq!(parse(&value), Err(Code::BadJson));
    value = submit();
    value["profile_id"] = json!("../bin/sh");
    assert_eq!(parse(&value), Err(Code::BadJson));
}

#[test]
fn stage_limits_names_and_prefix_conflicts_are_checked() {
    let file = |path: &str, size: u64| json!({"path":path,"size":size,"sha256":"00".repeat(32)});
    assert!(parse(&json!({"v":1,"op":"stage","files":[file("data.ndjson",16777216)]})).is_ok());
    assert_eq!(
        parse(&json!({"v":1,"op":"stage","files":[file("data.ndjson",16777217)]})),
        Err(Code::InvalidLimit)
    );
    for files in [
        vec![file("../x", 0)],
        vec![file("a", 0), file("a", 0)],
        vec![file("a", 0), file("a/b", 0)],
        vec![file("a/b", 0), file("a", 0)],
    ] {
        assert_eq!(
            parse(&json!({"v":1,"op":"stage","files":files})),
            Err(Code::InvalidPath)
        );
    }
    let files: Vec<_> = (0..128).map(|i| file(&format!("f{i}"), 0)).collect();
    assert!(parse(&json!({"v":1,"op":"stage","files":files})).is_ok());
    let files: Vec<_> = (0..129).map(|i| file(&format!("f{i}"), 0)).collect();
    assert_eq!(
        parse(&json!({"v":1,"op":"stage","files":files})),
        Err(Code::InvalidLimit)
    );
}

#[test]
fn stage_payload_is_never_consumed_as_header() {
    let header = br#"{"v":1,"op":"stage","files":[]}"#;
    let mut frame = (header.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(header);
    frame.extend_from_slice(b"payload");
    let mut reader = Cursor::new(frame);
    assert_eq!(read_request(&mut reader).unwrap(), Request::Stage(vec![]));
    assert_eq!(reader.position(), header.len() as u64 + 4);
    for frame in [
        vec![],
        vec![0, 0, 0, 0],
        vec![0, 1, 0, 1],
        vec![0, 0, 0, 3, b'{', b'}'],
    ] {
        assert_eq!(
            read_request(&mut Cursor::new(frame)).unwrap_err().code,
            Code::BadFrame
        );
    }
}

#[test]
fn canonical_identity_ignores_json_field_order_and_whitespace() {
    let first = parse(&submit()).unwrap();
    let second=parse_request(format!(" {{ \"wall_ms\":10000, \"argv\":[], \"stage_id\":\"{}\", \"profile_id\":\"summarize-v1\",\"request_id\":\"{}\",\"op\":\"submit\",\"v\":1 }} ","22".repeat(16),"11".repeat(16)).as_bytes()).unwrap();
    let (Request::Submit(first), Request::Submit(second)) = (first, second) else {
        panic!("submission expected")
    };
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    let expected = format!("{{\"argv\":[],\"op\":\"submit\",\"profile_id\":\"summarize-v1\",\"request_id\":\"{}\",\"stage_id\":\"{}\",\"v\":1,\"wall_ms\":10000}}", "11".repeat(16), "22".repeat(16));
    assert_eq!(first.canonical_bytes(), expected.as_bytes());
    for (field, value) in [
        ("request_id", json!("33".repeat(16))),
        ("profile_id", json!("summarize-v2")),
        ("stage_id", json!("44".repeat(16))),
        ("argv", json!(["changed"])),
        ("wall_ms", json!(11000)),
    ] {
        let mut changed = submit();
        changed[field] = value;
        let Request::Submit(changed) = parse(&changed).unwrap() else {
            panic!("submission expected")
        };
        assert_ne!(
            first.canonical_bytes(),
            changed.canonical_bytes(),
            "field {field}"
        );
    }
}

#[test]
fn event_defaults_and_page_bounds_are_explicit() {
    let id = "11".repeat(16);
    assert_eq!(
        parse(&json!({"v":1,"op":"events","job_id":id})).unwrap(),
        Request::Events {
            job_id: id.clone(),
            after_seq: 0,
            limit: 100
        }
    );
    assert_eq!(
        parse(&json!({"v":1,"op":"events","job_id":id,"limit":101})),
        Err(Code::InvalidLimit)
    );
}
