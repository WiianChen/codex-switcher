use codex_nas_sync::recovery_index;
use serde_json::json;

#[test]
fn crash_recovery_uses_actual_auth_instead_of_old_active_metadata() {
    let a = json!({"tokens":{"account_id":"a"}});
    let b = json!({"tokens":{"account_id":"b"}});
    assert_eq!(recovery_index(&[a.clone(), b.clone()], &a).unwrap(), 0);
    assert_eq!(recovery_index(&[a.clone(), b.clone()], &b).unwrap(), 1);
    assert!(recovery_index(&[a.clone(), a.clone()], &a).is_err());
    assert!(recovery_index(&[a.clone()], &b).is_err());
}
