//! Optional NAS ownership. Credentials remain in Credential Manager, never the frontend settings.
use crate::auth::{
    get_codex_auth_file, get_config_dir, load_accounts, read_current_auth, save_accounts,
    set_active_account, touch_account, AUTH_OPERATION_LOCK,
};
use crate::types::{AuthData, StoredAccount, UsageInfo};
use anyhow::{bail, Context, Result};
use codex_nas_sync::{atomic_json, load_token, same_identity, save_token, Connection, NasClient};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf, sync::Mutex};

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
#[derive(Clone, Serialize, Deserialize)]
struct Ownership {
    local_id: String,
    hub_id: String,
    lease_id: String,
    revision: i64,
    digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Config {
    connection: Connection,
    mapping: BTreeMap<String, String>,
    current: Option<Ownership>,
    #[serde(default)]
    pending: Vec<Ownership>,
}
fn path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("nas-sync.json"))
}
fn load() -> Result<Option<Config>> {
    let p = path()?;
    if !p.exists() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_slice(&std::fs::read(p)?)
            .context("NAS 設定檔無法讀取，已停止同步帳號操作")?,
    ))
}
fn save(c: &Config) -> Result<()> {
    atomic_json(&path()?, c)
}
fn client(c: &Config) -> Result<NasClient> {
    NasClient::new(c.connection.clone(), load_token(&c.connection.origin)?)
}
fn hash(v: &Value) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(v).expect("JSON")))
}
fn saved_auth(a: &StoredAccount) -> Result<Value> {
    Ok(serde_json::to_value(
        crate::auth::switcher::create_auth_json(a)?,
    )?)
}
pub fn managed(id: &str) -> Result<bool> {
    Ok(load()?.is_some_and(|c| c.mapping.contains_key(id)))
}
pub fn require_local_refresh(id: &str) -> Result<()> {
    if managed(id)? {
        bail!("此帳號由 NAS 管理憑證；Switcher 不執行本機 Token 刷新");
    }
    Ok(())
}

#[tauri::command]
pub fn nas_status() -> Result<Value, String> {
    let config = load().map_err(|e| e.to_string())?;
    Ok(match config {
        None => json!({"configured":false}),
        Some(c) => {
            json!({"configured":true,"origin":c.connection.origin,"mapping":c.mapping,"active_id":c.current.map(|o|o.local_id),"pending":c.pending.len(),"error":LAST_ERROR.lock().ok().and_then(|e|e.clone())})
        }
    })
}
#[tauri::command]
pub async fn nas_pair(
    origin: String,
    certificate_sha256: String,
    code: String,
) -> Result<(), String> {
    async fn perform(origin: String, pin: String, code: String) -> Result<()> {
        let _guard = AUTH_OPERATION_LOCK.lock().await;
        if load()?.is_some() {
            bail!("已有 NAS 配對，請先完成既有租約同步");
        }
        let connection = Connection {
            origin: origin.trim_end_matches('/').into(),
            certificate_sha256: pin.replace(':', "").to_lowercase(),
        };
        let token = NasClient::new(connection.clone(), String::new())?
            .pair(&code)
            .await?;
        save_token(&connection.origin, &token)?;
        save(&Config {
            connection,
            mapping: BTreeMap::new(),
            current: None,
            pending: vec![],
        })
    }
    perform(origin, certificate_sha256, code)
        .await
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn nas_import(account_ids: Vec<String>, admin_password: String) -> Result<(), String> {
    async fn perform(ids: Vec<String>, password: String) -> Result<()> {
        let _guard = AUTH_OPERATION_LOCK.lock().await;
        crate::commands::process::ensure_codex_not_running().map_err(anyhow::Error::msg)?;
        let mut c = load()?.context("請先配對 NAS")?;
        let admin = NasClient::new(c.connection.clone(), password)?;
        let device = client(&c)?;
        let store = load_accounts()?;
        for (index, id) in ids.iter().enumerate() {
            if c.mapping.contains_key(id) {
                continue;
            }
            let account = store
                .accounts
                .iter()
                .find(|a| &a.id == id)
                .context("找不到帳號")?;
            let saved = saved_auth(account)?;
            let auth = if store.active_account_id.as_deref() == Some(id) {
                let live =
                    serde_json::to_value(read_current_auth()?.context("目前登入憑證不存在")?)?;
                same_identity(&saved, &live)?;
                live
            } else {
                saved
            };
            let alias = if account.name.contains('@') {
                format!("帳號 {}", index + 1)
            } else {
                account.name.clone()
            };
            let imported = admin
                .request(
                    reqwest::Method::POST,
                    "/accounts",
                    Some(json!({"alias":alias,"auth":auth})),
                )
                .await?;
            let hub = imported["id"]
                .as_str()
                .context("NAS 回應缺少帳號 ID")?
                .to_owned();
            c.mapping.insert(id.clone(), hub.clone());
            save(&c)?;
            if store.active_account_id.as_deref() == Some(id) {
                let lease = device.acquire(&hub).await?;
                same_identity(&auth, &lease.auth)?;
                c.current = Some(Ownership {
                    local_id: id.clone(),
                    hub_id: hub,
                    lease_id: lease.lease_id,
                    revision: lease.revision,
                    digest: hash(&auth),
                });
                save(&c)?;
            }
        }
        Ok(())
    }
    perform(account_ids, admin_password)
        .await
        .map_err(|e| e.to_string())
}

async fn upload_current(c: &mut Config, nas: &NasClient) -> Result<()> {
    if let Some(o) = c.current.as_mut() {
        let auth = serde_json::to_value(read_current_auth()?.context("找不到使用中憑證")?)?;
        let store = load_accounts()?;
        let account = store
            .accounts
            .iter()
            .find(|a| a.id == o.local_id)
            .context("使用中帳號不存在")?;
        same_identity(&saved_auth(account)?, &auth)?;
        if hash(&auth) != o.digest {
            o.revision = nas
                .upload(&o.hub_id, &o.lease_id, o.revision, auth.clone())
                .await?;
            o.digest = hash(&auth);
            save(c)?;
        }
    }
    Ok(())
}

async fn renew_owner(nas: &NasClient, o: &Ownership) -> Result<()> {
    // The server retains expired ownership and only revives this exact lease.
    nas.heartbeat(&o.hub_id, &o.lease_id).await
}

#[tauri::command]
pub async fn nas_recover() -> Result<(), String> {
    async fn perform() -> Result<()> {
        let _guard = AUTH_OPERATION_LOCK.lock().await;
        crate::commands::process::ensure_codex_not_running().map_err(anyhow::Error::msg)?;
        let mut c = load()?.context("請先配對 NAS")?;
        let nas = client(&c)?;
        let live = serde_json::to_value(read_current_auth()?.context("目前憑證不存在")?)?;
        let store = load_accounts()?;
        let mut candidates = c.pending.clone();
        if let Some(o) = &c.current {
            candidates.push(o.clone());
        }
        let candidate_auth: Vec<Value> = candidates
            .iter()
            .map(|o| {
                let account = store
                    .accounts
                    .iter()
                    .find(|a| a.id == o.local_id)
                    .context("租約帳號不存在")?;
                saved_auth(account)
            })
            .collect::<Result<_>>()?;
        let selected = candidates[codex_nas_sync::recovery_index(&candidate_auth, &live)?].clone();
        renew_owner(&nas, &selected).await?;
        c.current = Some(selected.clone());
        c.pending = candidates
            .into_iter()
            .filter(|o| o.lease_id != selected.lease_id)
            .collect();
        save(&c)?;
        upload_current(&mut c, &nas).await?;
        let parsed: crate::types::AuthDotJson = serde_json::from_value(live)?;
        let t = parsed.tokens.context("缺少 OAuth 憑證")?;
        let mut store = load_accounts()?;
        let row = store
            .accounts
            .iter_mut()
            .find(|a| a.id == selected.local_id)
            .context("帳號不存在")?;
        row.auth_data = AuthData::ChatGPT {
            id_token: t.id_token,
            access_token: t.access_token,
            refresh_token: t.refresh_token,
            account_id: t.account_id,
        };
        save_accounts(&store)?;
        set_active_account(&selected.local_id)?;
        while let Some(old) = c.pending.first() {
            nas.release(&old.hub_id, &old.lease_id).await?;
            c.pending.remove(0);
            save(&c)?;
        }
        Ok(())
    }
    perform().await.map_err(|e| e.to_string())
}

// The caller holds AUTH_OPERATION_LOCK and has proved Codex is stopped.
pub async fn switch_locked(target: &str) -> Result<bool> {
    let Some(mut c) = load()? else {
        return Ok(false);
    };
    let store = load_accounts()?;
    let relevant = c.mapping.contains_key(target)
        || store
            .active_account_id
            .as_ref()
            .is_some_and(|id| c.mapping.contains_key(id));
    if !relevant {
        return Ok(false);
    }
    if !c.pending.is_empty() {
        bail!("上次 NAS 切換尚未完成，請先恢復同步");
    }
    if let Some(active) = store
        .active_account_id
        .as_ref()
        .filter(|id| c.mapping.contains_key(*id))
    {
        if c.current.as_ref().map(|o| &o.local_id) != Some(active) {
            bail!("目前帳號缺少可確認的 NAS 租約，已保留本機憑證；請先恢復同步");
        }
    }
    let hub = c
        .mapping
        .get(target)
        .context("請先將目標帳號匯入 NAS")?
        .clone();
    let nas = client(&c)?;
    if let Some(o) = &c.current {
        renew_owner(&nas, o).await?;
    }
    upload_current(&mut c, &nas).await?;
    if c.current.as_ref().is_some_and(|o| o.local_id == target) {
        return Ok(true);
    }
    let account = store
        .accounts
        .iter()
        .find(|a| a.id == target)
        .context("目標帳號不存在")?;
    let expected = saved_auth(account)?;
    let lease = nas.acquire(&hub).await?;
    let next = Ownership {
        local_id: target.into(),
        hub_id: hub,
        lease_id: lease.lease_id,
        revision: lease.revision,
        digest: hash(&lease.auth),
    };
    // Journal the new lease before any local write; a crash keeps both accounts fenced.
    c.pending.push(next.clone());
    save(&c)?;
    same_identity(&expected, &lease.auth)?;
    let parsed: crate::types::AuthDotJson = serde_json::from_value(lease.auth.clone())?;
    let t = parsed.tokens.context("NAS 缺少 OAuth 憑證")?;
    atomic_json(&get_codex_auth_file()?, &lease.auth)?;
    let mut fresh_store = load_accounts()?;
    let row = fresh_store
        .accounts
        .iter_mut()
        .find(|a| a.id == target)
        .context("帳號已被移除")?;
    row.auth_data = AuthData::ChatGPT {
        id_token: t.id_token,
        access_token: t.access_token,
        refresh_token: t.refresh_token,
        account_id: t.account_id,
    };
    save_accounts(&fresh_store)?;
    set_active_account(target)?;
    touch_account(target)?;
    let previous = c.current.replace(next);
    c.pending.clear();
    if let Some(old) = previous {
        c.pending.push(old);
    }
    save(&c)?;
    // Failure to release the old account cannot undo an already committed local switch.
    if let Some(old) = c.pending.first() {
        if nas.release(&old.hub_id, &old.lease_id).await.is_ok() {
            c.pending.clear();
            save(&c)?;
        }
    }
    Ok(true)
}

pub async fn cached_usage(a: &StoredAccount) -> Result<Option<UsageInfo>> {
    let Some(c) = load()? else {
        return Ok(None);
    };
    let Some(hub) = c.mapping.get(&a.id) else {
        return Ok(None);
    };
    let v = client(&c)?.accounts().await?;
    let u = v["accounts"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"].as_str() == Some(hub)))
        .context("NAS 找不到帳號")?;
    Ok(Some(UsageInfo {
        account_id: a.id.clone(),
        plan_type: a.plan_type.clone(),
        primary_used_percent: u["primary_used_percent"].as_f64(),
        primary_window_minutes: Some(300),
        primary_resets_at: u["primary_reset_at"].as_i64(),
        secondary_used_percent: u["weekly_used_percent"].as_f64(),
        secondary_window_minutes: Some(10080),
        secondary_resets_at: u["weekly_reset_at"].as_i64(),
        has_credits: None,
        unlimited_credits: None,
        credits_balance: None,
        error: u["last_error_code"].as_str().map(String::from),
    }))
}

pub fn start() {
    tauri::async_runtime::spawn(async {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut last_heartbeat = std::time::Instant::now() - std::time::Duration::from_secs(30);
        loop {
            timer.tick().await;
            let _guard = AUTH_OPERATION_LOCK.lock().await;
            let result: Result<()> = async {
                let Some(mut c) = load()? else {
                    return Ok(());
                };
                let nas = client(&c)?;
                if !c.pending.is_empty() {
                    bail!("NAS 切換紀錄待恢復；帳號保持鎖定");
                }
                if let Some(o) = &c.current {
                    if last_heartbeat.elapsed().as_secs() >= 30 {
                        renew_owner(&nas, o).await?;
                        last_heartbeat = std::time::Instant::now();
                    }
                }
                upload_current(&mut c, &nas).await?;
                Ok(())
            }
            .await;
            if let Ok(mut error) = LAST_ERROR.lock() {
                *error = result.err().map(|e| e.to_string());
            }
        }
    });
}
