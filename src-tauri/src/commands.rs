use crate::crypto;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;
use tauri::{Manager, State};

// ... existing code ...
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingShard {
    pub id: String,         // 임시 발급 ID (uuid 등)
    pub label: String,      // 비밀 라벨 (ex: "MasterPassword")
    pub shard_data: String, // Shard B 또는 C의 데이터
    pub shard_type: String, // "B" (모바일 전송용) 또는 "C" (백업 수단용)
}

pub struct PendingShardState(pub Mutex<Vec<PendingShard>>);

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretMetadata {
    pub label: String,
    pub date: String,
}

#[tauri::command]
pub async fn create_and_save_shards(
    app: tauri::AppHandle,
    state: State<'_, PendingShardState>,
    label: String,
    secret_key: String,
) -> Result<(), String> {
    let shares = crypto::split_into_shards(&secret_key)?;

    if shares.is_empty() {
        return Err("No shares generated".into());
    }

    // 첫 번째 조각을 로컬 저장용으로 선택
    let local_shard = &shares[0];

    // HWID 기반 AES-GCM 암호화
    let encrypted_local_shard = crypto::encrypt_shard_with_hwid(local_shard)?;

    // OS 금고(Windows Credential Manager 등)에 저장 (라벨을 서비스명으로 사용)
    let entry = Entry::new("NLOC_Vault", &label)
        .map_err(|e| format!("Failed to access OS Keyring: {}", e))?;

    entry
        .set_password(&encrypted_local_shard)
        .map_err(|e| format!("Failed to save to OS Keyring: {}", e))?;

    // 메타데이터(라벨, 날짜)를 vault_index.json에 기록
    let app_dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;

    let index_path = app_dir.join("vault_index.json");

    let mut secrets: Vec<SecretMetadata> = if index_path.exists() {
        let content = fs::read_to_string(&index_path).unwrap_or_else(|_| "[]".to_string());
        serde_json::from_str(&content).unwrap_or_else(|_| vec![])
    } else {
        vec![]
    };

    // 현재 시간을 YYYY-MM-DD 형식으로 (간단히)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    secrets.push(SecretMetadata {
        label: label.clone(),
        date: format!("Unix {}", current_time), // TODO: Use better datetime formatting later if needed
    });

    let json_content = serde_json::to_string_pretty(&secrets).map_err(|e| e.to_string())?;
    fs::write(index_path, json_content).map_err(|e| e.to_string())?;

    // 나머지 조각들 분리: 메모리 큐(PendingShardState)에 넣어서 나중에 폰 접속 시 전송하거나 PDF 출력 대기
    use uuid::Uuid;
    let mut pending_queue = state.0.lock().unwrap();

    if shares.len() >= 2 {
        pending_queue.push(PendingShard {
            id: Uuid::new_v4().to_string(),
            label: label.clone(),
            shard_data: shares[1].clone(),
            shard_type: "B".to_string(), // Shard B designed for mobile transfer
        });
    }

    if shares.len() >= 3 {
        pending_queue.push(PendingShard {
            id: Uuid::new_v4().to_string(),
            label: label.clone(),
            shard_data: shares[2].clone(),
            shard_type: "C".to_string(), // Shard C designed for physical/third-party backup
        });
    }

    Ok(())
}

#[tauri::command]
pub async fn backup_shard_c(
    app: tauri::AppHandle,
    state: State<'_, PendingShardState>,
    shard_id: String,
) -> Result<(), String> {
    use tauri_plugin_dialog::DialogExt;

    // 1. Find the shard
    let shard_data = {
        let queue = state.0.lock().unwrap();
        let shard = queue
            .iter()
            .find(|s| s.id == shard_id && s.shard_type == "C")
            .ok_or_else(|| "Shard C not found in queue".to_string())?;
        shard.shard_data.clone()
    };

    // 2. Open Save Dialog (Async-friendly via oneshot)
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Save Backup Shard (C)")
        .set_file_name("NLOC_Backup_Shard_C.txt")
        .save_file(move |path| {
            let _ = tx.send(path);
        });

    let file_path = rx.await.map_err(|e| e.to_string())?;

    if let Some(path) = file_path {
        // 3. Write to file
        // path is a FilePath, in v2 it can be converted to string or path
        let path_str = path.to_string();
        std::fs::write(path_str, shard_data).map_err(|e| e.to_string())?;

        // 4. Remove from queue
        let mut queue = state.0.lock().unwrap();
        if let Some(index) = queue.iter().position(|s| s.id == shard_id) {
            queue.remove(index);
        }
        Ok(())
    } else {
        Err("Save cancelled".into())
    }
}

#[tauri::command]
pub async fn get_pending_shards(
    state: State<'_, PendingShardState>,
) -> Result<Vec<PendingShard>, String> {
    let queue = state.0.lock().unwrap();
    Ok(queue.clone())
}

#[tauri::command]
pub async fn get_saved_secrets(app: tauri::AppHandle) -> Result<Vec<SecretMetadata>, String> {
    let app_dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let index_path = app_dir.join("vault_index.json");

    if !index_path.exists() {
        return Ok(vec![]);
    }

    let content = fs::read_to_string(&index_path).map_err(|e| e.to_string())?;
    let secrets: Vec<SecretMetadata> = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(secrets)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustedNode {
    pub name: String,
    pub public_key: String, // Hex encoded ED25519 Public Key
    pub date_added: String,
}

pub async fn add_trusted_node_internal(
    app: &tauri::AppHandle,
    name: String,
    public_key: String,
) -> Result<(), String> {
    let app_dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;

    let index_path = app_dir.join("trusted_nodes.json");

    let mut nodes: Vec<TrustedNode> = if index_path.exists() {
        let content = fs::read_to_string(&index_path).unwrap_or_else(|_| "[]".to_string());
        serde_json::from_str(&content).unwrap_or_else(|_| vec![])
    } else {
        vec![]
    };

    // 중복 방지 로직 (이미 있으면 통과)
    if nodes.iter().any(|n| n.public_key == public_key) {
        return Ok(());
    }

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    nodes.push(TrustedNode {
        name,
        public_key,
        date_added: format!("Unix {}", current_time),
    });

    let json_content = serde_json::to_string_pretty(&nodes).map_err(|e| e.to_string())?;
    fs::write(index_path, json_content).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn add_trusted_node(
    app: tauri::AppHandle,
    name: String,
    public_key: String,
) -> Result<(), String> {
    add_trusted_node_internal(&app, name, public_key).await
}

#[tauri::command]
pub async fn get_trusted_nodes(app: tauri::AppHandle) -> Result<Vec<TrustedNode>, String> {
    let app_dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let index_path = app_dir.join("trusted_nodes.json");

    if !index_path.exists() {
        return Ok(vec![]);
    }

    let content = fs::read_to_string(&index_path).map_err(|e| e.to_string())?;
    let nodes: Vec<TrustedNode> = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(nodes)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub public_key: String,
    pub ip_address: String,
    pub port: u16,
    pub session_token: String,
}

#[tauri::command]
pub async fn get_host_info(_app: tauri::AppHandle) -> Result<HostInfo, String> {
    let pub_key = crypto::get_host_public_key_hex()?;

    // Generate unique DDNS subdomain using SHA256 of the public key
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pub_key.as_bytes());
    let hash_result = hasher.finalize();
    let hash_hex = hex::encode(hash_result);
    // Take first 12 characters for a reasonable subdomain length
    let target_address = format!("nloc-{}.duckdns.org", &hash_hex[..12]);

    Ok(HostInfo {
        public_key: pub_key,
        ip_address: target_address,
        port: 5000,
        session_token: "temp_token123".to_string(), // TODO: 실제 임시 토큰 생성 로직
    })
}
