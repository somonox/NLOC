import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TouchableOpacity, ScrollView, SafeAreaView, Alert } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import { StatusBar } from 'expo-status-bar';
import * as crypto from './src/crypto';
import { NLOCClient } from './src/network';
import { Buffer } from 'buffer';

export default function App() {
    const [permission, requestPermission] = useCameraPermissions();
    const [isScanning, setIsScanning] = useState(false);
    const [status, setStatus] = useState('시스템 준비 완료');
    const [myPublicKey, setMyPublicKey] = useState('');
    const [savedShards, setSavedShards] = useState<any[]>([]);
    const [client, setClient] = useState<NLOCClient | null>(null);

    useEffect(() => {
        loadProfile();
        loadShards();
    }, []);

    const loadProfile = async () => {
        const priv = await crypto.getOrCreateIdentity();
        const pub = await crypto.getPublicKey(priv);
        setMyPublicKey(Buffer.from(pub).toString('hex'));
    };

    const loadShards = async () => {
        const shards = await crypto.getSavedShards();
        setSavedShards(shards);
    };

    const handleBarCodeScanned = ({ data }: { data: string }) => {
        setIsScanning(false);
        try {
            const info = JSON.parse(data);
            if (info.ipAddress && info.port) {
                startConnection({ ip: info.ipAddress, port: info.port });
            } else {
                Alert.alert('오류', '올바른 NLOC QR 코드가 아닙니다.');
            }
        } catch (e) {
            Alert.alert('오류', 'QR 코드 파싱 실패');
        }
    };

    const startConnection = (info: { ip: string, port: number }) => {
        if (client) client.disconnect();

        const newClient = new NLOCClient(
            info,
            (newStatus) => setStatus(newStatus),
            () => {
                loadShards();
                Alert.alert('성공', '비밀 조각(Shard B)을 수신하여 안전하게 저장했습니다.');
            }
        );
        newClient.connect();
        setClient(newClient);
    };

    if (!permission) return <View />;
    if (!permission.granted) {
        return (
            <View style={styles.container}>
                <Text style={{ color: 'white', textAlign: 'center', marginBottom: 20 }}>
                    QR 코드를 스캔하려면 카메라 권한이 필요합니다.
                </Text>
                <TouchableOpacity style={styles.button} onPress={requestPermission}>
                    <Text style={styles.buttonText}>카메라 권한 허용</Text>
                </TouchableOpacity>
            </View>
        );
    }

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar style="light" />
            <View style={styles.header}>
                <Text style={styles.title}>NLOC Mobile</Text>
                <View style={styles.statusBadge}>
                    <Text style={styles.statusText}>{status}</Text>
                </View>
            </View>

            <ScrollView style={styles.content}>
                <View style={styles.card}>
                    <Text style={styles.cardTitle}>내 모바일 노드 ID</Text>
                    <Text style={styles.pubKey} numberOfLines={2}>{myPublicKey}</Text>
                    <Text style={styles.infoText}>데스크탑 앱의 '신뢰할 수 있는 노드'에 이 ID를 추가해야 인증이 통과됩니다.</Text>
                </View>

                {!isScanning ? (
                    <TouchableOpacity style={styles.scanButton} onPress={() => setIsScanning(true)}>
                        <Text style={styles.buttonText}>데스크탑 페어링 (QR 스캔)</Text>
                    </TouchableOpacity>
                ) : (
                    <View style={styles.cameraContainer}>
                        <CameraView
                            style={styles.camera}
                            onBarcodeScanned={handleBarCodeScanned}
                            barcodeScannerSettings={{
                                barcodeTypes: ['qr'],
                            }}
                        />
                        <TouchableOpacity style={styles.cancelButton} onPress={() => setIsScanning(false)}>
                            <Text style={styles.buttonText}>취소</Text>
                        </TouchableOpacity>
                    </View>
                )}

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>저장된 비밀 조각 ({savedShards.length})</Text>
                    {savedShards.length === 0 ? (
                        <Text style={styles.emptyText}>저장된 조각이 없습니다.</Text>
                    ) : (
                        savedShards.map((s) => (
                            <View key={s.id} style={styles.shardItem}>
                                <Text style={styles.shardLabel}>{s.label}</Text>
                                <Text style={styles.shardDate}>{new Date(s.date).toLocaleString()}</Text>
                            </View>
                        ))
                    )}
                </View>
            </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#0f172a',
    },
    header: {
        padding: 20,
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(255,255,255,0.1)',
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
    },
    title: {
        fontSize: 24,
        fontWeight: 'bold',
        color: '#38bdf8',
    },
    statusBadge: {
        backgroundColor: 'rgba(56, 189, 248, 0.1)',
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 12,
    },
    statusText: {
        color: '#38bdf8',
        fontSize: 12,
    },
    content: {
        flex: 1,
        padding: 20,
    },
    card: {
        backgroundColor: 'rgba(255,255,255,0.05)',
        padding: 15,
        borderRadius: 12,
        marginBottom: 20,
    },
    cardTitle: {
        color: '#94a3b8',
        fontSize: 14,
        marginBottom: 8,
    },
    pubKey: {
        color: 'white',
        fontSize: 12,
        fontFamily: 'monospace',
        backgroundColor: 'rgba(0,0,0,0.2)',
        padding: 8,
        borderRadius: 4,
    },
    infoText: {
        color: '#64748b',
        fontSize: 11,
        marginTop: 8,
    },
    scanButton: {
        backgroundColor: '#0ea5e9',
        padding: 15,
        borderRadius: 12,
        alignItems: 'center',
        marginBottom: 20,
    },
    buttonText: {
        color: 'white',
        fontWeight: 'bold',
        fontSize: 16,
    },
    cameraContainer: {
        height: 300,
        borderRadius: 12,
        overflow: 'hidden',
        marginBottom: 20,
    },
    camera: {
        flex: 1,
    },
    cancelButton: {
        position: 'absolute',
        bottom: 10,
        left: 10,
        right: 10,
        backgroundColor: 'rgba(0,0,0,0.6)',
        padding: 10,
        borderRadius: 8,
        alignItems: 'center',
    },
    section: {
        marginTop: 10,
    },
    sectionTitle: {
        color: 'white',
        fontSize: 18,
        fontWeight: 'bold',
        marginBottom: 15,
    },
    emptyText: {
        color: '#64748b',
        textAlign: 'center',
        marginTop: 20,
    },
    shardItem: {
        backgroundColor: 'rgba(255,255,255,0.03)',
        padding: 15,
        borderRadius: 10,
        marginBottom: 10,
        borderLeftWidth: 3,
        borderLeftColor: '#4ade80',
    },
    shardLabel: {
        color: 'white',
        fontWeight: 'bold',
        fontSize: 16,
    },
    shardDate: {
        color: '#94a3b8',
        fontSize: 12,
        marginTop: 4,
    },
    button: {
        backgroundColor: '#0ea5e9',
        padding: 15,
        borderRadius: 12,
        alignSelf: 'center',
    }
});
