import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import QRCode from "react-qr-code";
import "./App.css";

interface SecretMetadata {
  label: string;
  date: string;
}

interface HostInfo {
  publicKey: string;
  ipAddress: string;
  port: number;
  sessionToken: string;
}

interface PendingShard {
  id: string;
  label: string;
  shardType: string;
}

function App() {
  const [label, setLabel] = useState("");
  const [content, setContent] = useState("");
  const [status, setStatus] = useState("시스템 준비 완료");
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null);
  const [pendingShards, setPendingShards] = useState<PendingShard[]>([]);

  const loadSecrets = async () => {
    try {
      const data = await invoke<SecretMetadata[]>("get_saved_secrets");
      setSecrets(data);
    } catch (err) {
      console.error("Failed to load secrets:", err);
    }
  };

  const loadPendingShards = async () => {
    try {
      const shards = await invoke<PendingShard[]>("get_pending_shards");
      setPendingShards(shards);
    } catch (err) {
      console.error("Failed to load pending shards:", err);
    }
  };

  const loadHostInfo = async () => {
    try {
      const info = await invoke<HostInfo>("get_host_info");
      setHostInfo(info);
    } catch (err) {
      console.error("Failed to load host info:", err);
    }
  };

  useEffect(() => {
    loadSecrets();
    loadHostInfo();
    loadPendingShards();
  }, []);

  const handleDistribute = async () => {
    if (!label || !content) {
      alert("라벨과 내용을 모두 입력해주세요.");
      return;
    }

    try {
      setStatus("🔐 샤딩 및 분산 저장 중...");
      await invoke<void>("create_and_save_shards", {
        label: label,
        secretKey: content
      });
      setStatus(`✅ 성공: 첫 번째 조각은 로컬 금고에 안전하게 저장되었습니다.\n나머지 조각 분산 대기열 추가 완료.`);
      setLabel(""); setContent(""); // 입력창 초기화
      loadSecrets(); // 목록 갱신
      loadPendingShards(); // 대기열 갱신
    } catch (err) {
      setStatus(`❌ 실패: ${err}`);
    }
  };

  const handleBackupShardC = async (id: string) => {
    try {
      setStatus("💾 백업 파일 저장 중...");
      await invoke("backup_shard_c", { shardId: id });
      setStatus("✅ 백업 저장 완료: 보조 수단(USB, PDF 등)에 안전하게 보관하세요.");
      loadPendingShards();
    } catch (err) {
      if (err === "Save cancelled") {
        setStatus("⚠️ 백업 저장이 취소되었습니다.");
      } else {
        setStatus(`❌ 백업 실패: ${err}`);
      }
    }
  };

  return (
    <div className="nloc-dashboard">
      <header>
        <h1>NLOC Vault</h1>
        <div className="node-status">이웃 노드: <span className="status-online">● 연결 대기 중</span></div>
      </header>

      <main>
        {hostInfo && (
          <div className="pairing-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '20px', padding: '15px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '8px' }}>
            <h2>NLOC Phone Pairing</h2>
            <p style={{ fontSize: '0.9em', color: '#ccc', marginBottom: '15px' }}>핸드폰의 NLOC 앱으로 아래 QR 코드를 스캔하세요.</p>
            <div style={{ background: 'white', padding: '10px', borderRadius: '8px' }}>
              <QRCode value={JSON.stringify(hostInfo)} size={150} />
            </div>
            <p style={{ fontSize: '0.8em', color: '#aaa', marginTop: '10px' }}>Address: {hostInfo.ipAddress} | Port: {hostInfo.port}</p>
          </div>
        )}

        <div className="input-card">
          <h2>새로운 비밀 저장</h2>
          <input
            type="text"
            placeholder="자산 이름 (예: Github SSH Key)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
          <textarea
            placeholder="비밀 내용 또는 문서 텍스트"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
          <button onClick={handleDistribute}>안전하게 쪼개서 분산하기</button>
        </div>

        <div className="status-terminal">
          <p>{status}</p>
        </div>

        {pendingShards.length > 0 && (
          <div className="saved-secrets-card" style={{ marginTop: '20px', borderLeft: '4px solid #ffaa00' }}>
            <h2>전송 대기열 (Pending Shards)</h2>
            <p style={{ fontSize: '0.85em', color: '#888', marginBottom: '10px' }}>모바일 기기 연결 또는 물리적 백업이 필요한 조각들입니다.</p>
            <ul className="secrets-list">
              {pendingShards.map((s, idx) => (
                <li key={idx} className="secret-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong>{s.label}</strong>
                    <span className="secret-date" style={{ marginLeft: '10px', color: s.shardType === 'B' ? '#4CAF50' : '#2196F3' }}>
                      Type {s.shardType}
                    </span>
                  </div>
                  {s.shardType === 'C' && (
                    <button
                      onClick={() => handleBackupShardC(s.id)}
                      style={{ padding: '4px 10px', fontSize: '0.8em', margin: 0, width: 'auto' }}
                    >
                      파일로 저장
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {secrets.length > 0 && (
          <div className="saved-secrets-card" style={{ marginTop: '20px' }}>
            <h2>내 금고 (Local Vault)</h2>
            <ul className="secrets-list">
              {secrets.map((s, idx) => (
                <li key={idx} className="secret-item">
                  <strong>{s.label}</strong>
                  <span className="secret-date">{s.date}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;