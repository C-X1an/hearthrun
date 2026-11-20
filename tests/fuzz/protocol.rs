use hearthrun_domain::{protocol, MAX_HEADER_BYTES};

const SEEDS: &[&[u8]] = &[
    br#"{"v":1,"op":"doctor"}"#,
    br#"{"op":"metrics","v":1}"#,
    br#"{"v":1,"op":"submit","request_id":"00000000000000000000000000000001","stage_id":"00000000000000000000000000000002","profile_id":"fixture","argv":["one","two"],"wall_ms":10000}"#,
    br#"{"v":1,"op":"stage","files":[{"path":"inputs/data","size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}"#,
];

fn framed(body: &[u8]) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}

fn observe(body: &[u8]) -> bool {
    let raw = protocol::parse_request(body);
    if !body.is_empty() && body.len() <= MAX_HEADER_BYTES {
        assert_eq!(raw, protocol::read_request(&mut framed(body).as_slice()));
    }
    match raw {
        Ok(request) => {
            let independently_parsed: serde_json::Value =
                serde_json::from_slice(body).expect("accepted bytes must be valid JSON");
            assert_eq!(independently_parsed["v"].as_u64(), Some(1));
            assert!(independently_parsed["op"].is_string());
            if let protocol::Request::Submit(submission) = request {
                let body = submission.canonical_bytes();
                assert_eq!(
                    protocol::parse_request(&body),
                    Ok(protocol::Request::Submit(submission))
                );
            }
            true
        }
        Err(_) => false,
    }
}

#[test]
fn bounded_deterministic_corpus_preserves_framing_and_canonicalization() {
    let mut examined = 0;
    let mut accepted = 0;
    for seed in SEEDS {
        assert!(
            observe(seed),
            "invalid base corpus: {:?}",
            protocol::parse_request(seed)
        );
        for index in 0..seed.len() {
            let mut truncated = framed(&seed[..index]);
            truncated[..4].copy_from_slice(&(seed.len() as u32).to_be_bytes());
            assert!(protocol::read_request(&mut truncated.as_slice()).is_err());
            let mut body = seed.to_vec();
            for byte in [0, b'"', b'{', b']', b'\\', b' ', b'9', 0x80, 0xff] {
                body[index] = byte;
                examined += 1;
                accepted += usize::from(observe(&body));
            }
        }
    }
    for length in [
        0,
        1,
        MAX_HEADER_BYTES,
        MAX_HEADER_BYTES + 1,
        u32::MAX as usize,
    ] {
        let header = (length as u32).to_be_bytes();
        assert!(protocol::read_request(&mut header.as_slice()).is_err());
    }
    assert!(examined >= 2000 && accepted > 0 && accepted < examined);
    println!("{examined} deterministic header mutations, {accepted} valid requests");
}
