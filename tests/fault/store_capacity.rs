//! Filesystem-backed coverage for the local v1 retry catalog bounds.
use super::*;
use std::os::unix::fs::DirBuilderExt;

fn submission(index: usize) -> Submission {
    Submission {
        request_id: format!("{:032x}", 65536 + index),
        profile_id: "example".into(),
        stage_id: "b".repeat(32),
        argv: vec!["empty".into()],
        wall_ms: 1000,
    }
}

fn record(store: &Store, index: usize) -> JobRecord {
    JobRecord::intent(
        store.instance_id().into(),
        format!("{:032x}", index + 1),
        &submission(index),
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "2026-01-01T00:00:00Z".into(),
    )
    .unwrap()
}

fn test_work() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("HEARTHRUN_LEDGER_TEST_WORK").expect("set HEARTHRUN_LEDGER_TEST_WORK"),
    );
    assert!(root.is_absolute());
    let parent = root.parent().unwrap();
    assert_eq!(parent, parent.canonicalize().unwrap());
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0);
    assert!(rustix::process::getgroups().unwrap().is_empty());
    let scope = open_root(parent, uid).unwrap();
    assert_eq!(fs::fstatfs(&scope).unwrap().f_type as u64, 0x0102_1994);
    let space = fs::fstatvfs(&scope).unwrap();
    assert!((64_000_000..=12_000_000_000).contains(&(space.f_blocks * space.f_frsize)));
    assert!(space.f_bavail * space.f_frsize >= 64_000_000);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    root
}

// Construct exact v1 disk fixtures under the real Store lock. The resize
// regression exercises public admission and reopen after fixture creation.
fn seed(path: &Path, count: usize, retained_bytes: Option<u64>) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    let store = Store::open(path).unwrap();
    let mut catalog = Catalog {
        v: 1,
        instance_id: store.instance_id().into(),
        entries: Vec::with_capacity(count),
    };
    let mut records = Vec::with_capacity(count);
    for index in 0..count {
        let item = record(&store, index);
        catalog.entries.push(CatalogEntry {
            job_id: item.job_id.clone(),
            request_id: item.request_id.clone(),
            canonical_request_sha256: item.canonical_request_sha256.clone(),
        });
        records.push((
            format!("{}.json", item.job_id),
            encode_record(&item).unwrap(),
        ));
    }
    let catalog_bytes = encode_bounded(&catalog, MAX_CATALOG_BYTES).unwrap();
    let initial: u64 =
        records.iter().map(|(_, raw)| raw.len() as u64).sum::<u64>() + catalog_bytes.len() as u64;
    let mut padding = retained_bytes.map_or(0, |target| target.checked_sub(initial).unwrap());
    for (name, raw) in &mut records {
        let added = padding.min((MAX_RECORD_BYTES - raw.len()) as u64);
        raw.resize(raw.len() + usize::try_from(added).unwrap(), b' ');
        padding -= added;
        atomic_write(&store.records_directory, name, raw, None, store.owner_uid).unwrap();
    }
    assert_eq!(
        padding, 0,
        "seeded record count cannot hold requested byte fixture"
    );
    let old = fs::statat(
        &store.records_directory,
        CATALOG_NAME,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    atomic_write(
        &store.records_directory,
        CATALOG_NAME,
        &catalog_bytes,
        Some(Identity::of(&old)),
        store.owner_uid,
    )
    .unwrap();
}

fn refuse_without_write(store: &mut Store, next: usize) {
    let before = store.inventory().unwrap();
    let candidate = record(store, next);
    assert_eq!(
        store.write(&candidate).unwrap_err().kind,
        ErrorKind::StorageFull
    );
    assert!(!store.frozen.get());
    let after = store.inventory().unwrap();
    assert_eq!(before.bytes, after.bytes);
    assert_eq!(before.records.len(), after.records.len());
    assert!(before.catalog_identity == after.catalog_identity);
    assert!(store.lookup_request(&submission(next)).unwrap().is_none());
}

#[test]
fn bounded_catalog_grows_without_forgetting_old_retries() {
    let root = test_work();
    let dense = root.join("large-catalog");
    seed(&dense, 1023, None);
    let mut store = Store::open(&dense).unwrap();
    let added = record(&store, 1023);
    store.write(&added).unwrap();
    let mut catalog = std::fs::read(dense.join("records/catalog.json")).unwrap();
    assert!(
        catalog.len() > hearthrun_domain::MAX_HEADER_BYTES && catalog.len() <= MAX_CATALOG_BYTES
    );
    assert_eq!(
        protocol::strict_json(&catalog).unwrap_err().code,
        protocol::Code::BadFrame
    );
    assert!(protocol::strict_json_with_limit(&catalog, MAX_CATALOG_BYTES).is_ok());
    let mut duplicate = catalog[..catalog.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"v\":1}");
    assert_eq!(
        protocol::strict_json_with_limit(&duplicate, MAX_CATALOG_BYTES)
            .unwrap_err()
            .code,
        protocol::Code::DuplicateKey
    );
    let mut wire = vec![b' '; hearthrun_domain::MAX_HEADER_BYTES];
    wire[..2].copy_from_slice(b"{}");
    assert!(protocol::strict_json(&wire).is_ok());
    wire.push(b' ');
    assert_eq!(
        protocol::strict_json(&wire).unwrap_err().code,
        protocol::Code::BadFrame
    );

    catalog.resize(MAX_CATALOG_BYTES, b' ');
    let previous = fs::statat(
        &store.records_directory,
        CATALOG_NAME,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();
    atomic_write(
        &store.records_directory,
        CATALOG_NAME,
        &catalog,
        Some(Identity::of(&previous)),
        store.owner_uid,
    )
    .unwrap();
    assert_eq!(
        store.inventory().unwrap().catalog_bytes,
        MAX_CATALOG_BYTES as u64
    );
    catalog.push(b' ');
    assert_eq!(
        protocol::strict_json_with_limit(&catalog, MAX_CATALOG_BYTES)
            .unwrap_err()
            .code,
        protocol::Code::BadFrame
    );
    refuse_without_write(&mut store, 1024);
    drop(store);
    let store = Store::open(&dense).unwrap();
    assert_eq!(store.records().unwrap().len(), 1024);
    assert_eq!(
        store.lookup_request(&submission(1023)).unwrap(),
        Some(added)
    );
    assert_eq!(
        store.lookup_request(&submission(0)).unwrap(),
        Some(record(&store, 0))
    );
    let mut changed = submission(0);
    changed.wall_ms += 1;
    assert_eq!(
        store.lookup_request(&changed).unwrap_err().kind,
        ErrorKind::Conflict
    );

    let legacy = root.join("legacy-read-ceiling");
    seed(&legacy, 256, Some(MAX_RETAINED_BYTES));
    let mut legacy_store = Store::open(&legacy).unwrap();
    assert_eq!(legacy_store.inventory().unwrap().bytes, MAX_RETAINED_BYTES);
    assert_eq!(legacy_store.records().unwrap().len(), 256);
    refuse_without_write(&mut legacy_store, 256);

    let replacement = root.join("catalog-displacement");
    seed(&replacement, 1000, Some(MAX_RETAINED_BYTES - 4096));
    let mut crowded = Store::open(&replacement).unwrap();
    let before = crowded.inventory().unwrap();
    let candidate = record(&crowded, 1000);
    let record_bytes = encode_record(&candidate).unwrap().len() as u64;
    let mut next = before.catalog;
    next.entries.push(CatalogEntry {
        job_id: candidate.job_id,
        request_id: candidate.request_id,
        canonical_request_sha256: candidate.canonical_request_sha256,
    });
    let new_catalog_bytes = encode_bounded(&next, MAX_CATALOG_BYTES).unwrap().len() as u64;
    assert!(
        before.bytes - before.catalog_bytes + record_bytes + new_catalog_bytes
            <= MAX_RETAINED_BYTES
    );
    assert!(
        before.bytes + record_bytes + new_catalog_bytes + MAX_INSTANCE_BYTES as u64
            > MAX_METADATA_BYTES
    );
    refuse_without_write(&mut crowded, 1000);
    println!("{{\"case\":\"bounded_catalog\",\"status\":\"PASS\",\"verified_new_count\":1024,\"legacy_count\":256,\"unchanged_ipc_limit\":65536,\"peak_displacement_refused\":true}}");
}
