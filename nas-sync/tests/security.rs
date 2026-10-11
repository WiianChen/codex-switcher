use codex_nas_sync::{atomic_json, same_identity, Connection};
use serde_json::json;
#[test]
fn insecure_url_and_wrong_identity_are_rejected() {
    let mut c = Connection {
        origin: "http://nas.local".into(),
        certificate_sha256: "a".repeat(64),
    };
    assert!(c.validate().is_err());
    c.origin = "https://nas.local".into();
    assert!(c.validate().is_ok());
    c.origin = "https://user:password@nas.local".into();
    assert!(c.validate().is_err());
    assert!(same_identity(
        &json!({"tokens":{"account_id":"a"}}),
        &json!({"tokens":{"account_id":"b"}})
    )
    .is_err());
}
#[test]
fn atomic_replacement_leaves_only_complete_auth() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.json");
    atomic_json(&path, &json!({"tokens":{"account_id":"a"}})).unwrap();
    atomic_json(&path, &json!({"tokens":{"account_id":"b"}})).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(v["tokens"]["account_id"], "b");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
