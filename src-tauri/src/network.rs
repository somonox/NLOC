use ed25519_dalek::{Verifier, VerifyingKey};
use log::{error, info};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum NetworkMessage {
    Challenge {
        nonce: String,
    },
    ChallengeResponse {
        signature: String,
        public_key: String,
        ecdh_public_key: String,
    },
    AuthSuccess {
        ecdh_public_key: String,
    },
    AuthFailed {
        reason: String,
    },
    EncryptedPayload {
        nonce: String,
        ciphertext: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum AppMessage {
    StoreShard {
        id: String,
        label: String,
        shard_data: String,
    },
    StoreShardAck {
        id: String,
        success: bool,
    },
}

// Raw TCP Server Implementation
pub async fn run_tcp_server(app_handle: tauri::AppHandle) {
    let port = 5000;
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TCP port {}: {}", port, e);
            return;
        }
    };
    info!("NLOC TCP Server listening on port {}", port);

    while let Ok((stream, addr)) = listener.accept().await {
        info!("New TCP connection from: {}", addr);
        let app_handle = app_handle.clone();
        tokio::spawn(async move {
            handle_tcp_connection(stream, addr, app_handle).await;
        });
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    addr: std::net::SocketAddr,
    app_handle: tauri::AppHandle,
) {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    let challenge = NetworkMessage::Challenge {
        nonce: nonce_hex.clone(),
    };
    if let Ok(m) = serde_json::to_string(&challenge) {
        let _ = writer.write_all(format!("{}\n", m).as_bytes()).await;
        info!("Sent challenge to {}: {}", addr, nonce_hex);
    }

    let mut authenticated = false;
    let mut session_key = [0u8; 32];
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(1000));
    let mut line = String::new();

    loop {
        tokio::select! {
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => {
                        info!("TCP Connection closed (EOF): {}", addr);
                        break;
                    }
                    Ok(_) => {
                        let text = line.trim();
                        if !text.is_empty() {
                            if !authenticated {
                                if let Ok(msg) = serde_json::from_str::<NetworkMessage>(text) {
                                    if let NetworkMessage::ChallengeResponse { signature, public_key, ecdh_public_key } = msg {
                                        if verify_signature(&nonce_hex, &signature, &public_key) {
                                            if let Ok(host_pub) = perform_ecdh(&ecdh_public_key, &mut session_key) {
                                                let reply = NetworkMessage::AuthSuccess { ecdh_public_key: host_pub };
                                                if let Ok(r) = serde_json::to_string(&reply) {
                                                    let _ = writer.write_all(format!("{}\n", r).as_bytes()).await;
                                                    authenticated = true;
                                                    info!("TCP Authenticated: {}", addr);

                                                    // Register as trusted node
                                                    let _ = crate::commands::add_trusted_node_internal(
                                                        &app_handle,
                                                        format!("Mobile ({})", addr),
                                                        public_key.clone()
                                                    ).await;
                                                }
                                            } else {
                                                error!("ECDH failed for {}", addr);
                                            }
                                        } else {
                                            info!("Invalid signature from {}", addr);
                                        }
                                    }
                                }
                            } else {
                                // Process Secure messages (future use)
                            }
                        }
                        line.clear();
                    }
                    Err(e) => {
                        error!("TCP Error for {}: {}", addr, e);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if authenticated {
                    let state = app_handle.state::<crate::commands::PendingShardState>();
                    let mut shard_to_send = None;
                    {
                        let mut queue = state.0.lock().unwrap();
                        if let Some(pos) = queue.iter().position(|s| s.shard_type == "B") {
                            shard_to_send = Some(queue.remove(pos));
                        }
                    }
                    if let Some(shard) = shard_to_send {
                        let app_msg = AppMessage::StoreShard {
                            id: shard.id,
                            label: shard.label.clone(),
                            shard_data: shard.shard_data
                        };
                        let app_msg_str = serde_json::to_string(&app_msg).unwrap();
                        if let Ok((nonce, ciphertext)) = crate::crypto::encrypt_with_session_key(&session_key, app_msg_str.as_bytes()) {
                            let net_msg = NetworkMessage::EncryptedPayload { nonce, ciphertext };
                            if let Ok(net_msg_str) = serde_json::to_string(&net_msg) {
                                let _ = writer.write_all(format!("{}\n", net_msg_str).as_bytes()).await;
                                info!("Sent shard {} via TCP to {}", shard.label, addr);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn verify_signature(nonce: &str, signature: &str, public_key: &str) -> bool {
    match (hex::decode(public_key), hex::decode(signature)) {
        (Ok(pub_bytes), Ok(sig_bytes)) => {
            if pub_bytes.len() == 32 && sig_bytes.len() == 64 {
                let mut pub_array = [0u8; 32];
                pub_array.copy_from_slice(&pub_bytes);
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&sig_bytes);
                if let (Ok(vk), Ok(sig)) = (
                    VerifyingKey::from_bytes(&pub_array),
                    ed25519_dalek::Signature::from_slice(&sig_array),
                ) {
                    return vk.verify(nonce.as_bytes(), &sig).is_ok();
                }
            }
        }
        _ => (),
    }
    false
}

fn perform_ecdh(mobile_pub_hex: &str, out_session_key: &mut [u8; 32]) -> Result<String, String> {
    use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
    let host_secret = EphemeralSecret::random(&mut OsRng);
    let host_public = EncodedPoint::from(host_secret.public_key());
    let mobile_pub_bytes = hex::decode(mobile_pub_hex).map_err(|e| e.to_string())?;
    let mobile_pub_point =
        EncodedPoint::from_bytes(&mobile_pub_bytes).map_err(|e| e.to_string())?;
    let mobile_pub_key =
        PublicKey::from_sec1_bytes(mobile_pub_point.as_bytes()).map_err(|e| e.to_string())?;
    let shared = host_secret.diffie_hellman(&mobile_pub_key);

    let secret_bytes = shared.raw_secret_bytes();
    out_session_key.copy_from_slice(secret_bytes.as_slice());

    Ok(hex::encode(host_public.as_bytes()))
}
