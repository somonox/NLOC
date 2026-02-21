use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use keyring::Entry;
use machine_uid;
use rand::{rngs::OsRng, thread_rng, Rng};
use sha2::{Digest, Sha256};
use vsss_rs::Gf256;

// 어떤 형태의 문자열(비밀)이든 3개로 분산시키는 범용 함수
pub fn split_into_shards(secret: &str) -> Result<Vec<String>, String> {
    let mut rng = thread_rng();

    // (2, 3) 스킴: 3개 중 2개면 복구 가능
    let shares = Gf256::split_array(2, 3, secret.as_bytes(), &mut rng)
        .map_err(|e| format!("Sharding failed: {:?}", e))?;

    Ok(shares.iter().map(hex::encode).collect())
}

/// 현재 기기의 HWID를 가져와 SHA-256으로 32바이트 AES 키를 생성합니다.
fn derive_hwid_key() -> Result<[u8; 32], String> {
    let hwid = machine_uid::get().map_err(|e| format!("Failed to get HWID: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(hwid.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// 주어진 텍스트(샤드)를 무작위 Nonce와 HWID 기반 키로 AES-256-GCM 암호화합니다.
/// 결과는 `Nonce + Ciphertext` 형태의 Base64 인코딩 문자열입니다.
pub fn encrypt_shard_with_hwid(shard: &str) -> Result<String, String> {
    let key_bytes = derive_hwid_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // 96-bit (12 bytes) 무작위 Nonce 생성
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 암호화
    let ciphertext = cipher
        .encrypt(nonce, shard.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // 출력 형식: Nonce (12 bytes) + Ciphertext
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    // Base64 인코딩하여 반환
    Ok(general_purpose::STANDARD.encode(combined))
}

/// HWID 기반 키로 저장된 Base64 문자열을 해독하여 원본 샤드를 복원합니다.
#[allow(dead_code)]
pub fn decrypt_shard_with_hwid(encrypted_base64: &str) -> Result<String, String> {
    let combined = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| format!("Invalid base64 payload: {}", e))?;

    if combined.len() < 12 {
        return Err("Payload too short to contain a valid nonce.".into());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key_bytes = derive_hwid_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        format!(
            "Decryption failed (maybe wrong HWID or tampered data): {}",
            e
        )
    })?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))
}

// --------------------------------------------------------------------------------
// ECDH Session Key Encryption
// --------------------------------------------------------------------------------

/// ECDH Session Key(32 bytes)를 사용하여 데이터를 AES-256-GCM으로 암호화합니다.
/// 반환값: (Nonce 12bytes Hex, Ciphertext Hex)
pub fn encrypt_with_session_key(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(String, String), String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((hex::encode(nonce_bytes), hex::encode(ciphertext)))
}

/// ECDH Session Key(32 bytes)를 사용하여 데이터를 AES-256-GCM으로 복호화합니다.
pub fn decrypt_with_session_key(
    key: &[u8; 32],
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Nonce must be 12 bytes".into());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext =
        hex::decode(ciphertext_hex).map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))
}

// --------------------------------------------------------------------------------
// NLOC Architecture: ED25519 Host Identity Management
// --------------------------------------------------------------------------------

/// 로컬 장치의 ED25519 키 쌍을 가져오거나, 없으면 새로 생성하여 HWID로 암호화 후 OS 금고에 저장합니다.
pub fn get_or_create_host_keypair() -> Result<SigningKey, String> {
    let entry = Entry::new("NLOC_Vault", "host_identity_key")
        .map_err(|e| format!("Failed to access OS Keyring: {}", e))?;

    // 1. 기존 키가 있는지 확인
    if let Ok(encrypted_base64) = entry.get_password() {
        if let Ok(decrypted_hex) = decrypt_shard_with_hwid(&encrypted_base64) {
            if let Ok(secret_bytes) = hex::decode(&decrypted_hex) {
                if secret_bytes.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&secret_bytes);
                    return Ok(SigningKey::from_bytes(&bytes));
                }
            }
        }
    }

    // 2. 키가 없거나 복호화 실패 시 새로 생성
    let mut csprng = OsRng;
    let new_key = SigningKey::generate(&mut csprng);

    // 3. Private Key(32 bytes)를 hex로 인코딩 후 HWID로 암호화하여 저장
    let secret_hex = hex::encode(new_key.to_bytes());
    let encrypted_key = encrypt_shard_with_hwid(&secret_hex)?;

    entry
        .set_password(&encrypted_key)
        .map_err(|e| format!("Failed to save host identity to OS Keyring: {}", e))?;

    Ok(new_key)
}

/// 호스트의 공개키를 Hex 문자열로 반환합니다. (폰과의 QR 페어링용)
pub fn get_host_public_key_hex() -> Result<String, String> {
    let signing_key = get_or_create_host_keypair()?;
    let verifying_key = signing_key.verifying_key();
    Ok(hex::encode(verifying_key.to_bytes()))
}
