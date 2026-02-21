import 'react-native-get-random-values';
import * as SecureStore from 'expo-secure-store';
import * as ed25519 from '@noble/ed25519';
import { p256 } from '@noble/curves/nist';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { Buffer } from 'buffer';

// Configure ed25519 to use sha512 from @noble/hashes (Required for v3)
ed25519.hashes.sha512 = (msg) => sha512(msg);

// Ensure crypto.webcrypto is available for noble libraries
if (typeof (global as any).crypto === 'undefined') {
    (global as any).crypto = {
        getRandomValues: (arr: any) => require('react-native-get-random-values').getRandomValues(arr),
    };
}

const ED_KEY_ID = 'nloc_mobile_identity';

export async function getOrCreateIdentity(): Promise<Uint8Array> {
    const existing = await SecureStore.getItemAsync(ED_KEY_ID);
    if (existing) {
        return Buffer.from(existing, 'hex');
    }
    const privKey = ed25519.utils.randomSecretKey();
    const hex = Buffer.from(privKey).toString('hex');
    await SecureStore.setItemAsync(ED_KEY_ID, hex);
    return privKey;
}

export async function getPublicKey(privKey: Uint8Array): Promise<Uint8Array> {
    return await ed25519.getPublicKeyAsync(privKey);
}

export async function signChallenge(privKey: Uint8Array, challengeHex: string): Promise<Uint8Array> {
    const nonceBytes = Buffer.from(challengeHex, 'hex');
    return await ed25519.signAsync(nonceBytes, privKey);
}

export interface ECDHKeyPair {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}

export function generateECDHKeyPair(): ECDHKeyPair {
    const priv = p256.utils.randomSecretKey();
    const pub = p256.getPublicKey(priv);
    return { privateKey: priv, publicKey: pub };
}

export function deriveSharedSecret(myPriv: Uint8Array, theirPubHex: string): Uint8Array {
    const theirPub = Buffer.from(theirPubHex, 'hex');
    const shared = p256.getSharedSecret(myPriv, theirPub);
    // Handle different potential outputs from getSharedSecret to ensure we get the 32-byte X coordinate
    if (shared.length === 65) return shared.slice(1, 33); // Uncompressed: [0x04, X, Y]
    if (shared.length === 33) return shared.slice(1, 33); // Compressed: [0x02/0x03, X]
    return shared; // Already 32 bytes (X)
}

export async function saveShard(id: string, label: string, data: string) {
    const key = `shard_${id}`;
    const payload = JSON.stringify({ label, data, date: new Date().toISOString() });
    await SecureStore.setItemAsync(key, payload);

    // Update index
    const indexStr = await SecureStore.getItemAsync('shard_index');
    const index = indexStr ? JSON.parse(indexStr) : [];
    if (!index.includes(id)) {
        index.push(id);
        await SecureStore.setItemAsync('shard_index', JSON.stringify(index));
    }
}

export async function getSavedShards() {
    const indexStr = await SecureStore.getItemAsync('shard_index');
    if (!indexStr) return [];
    const index: string[] = JSON.parse(indexStr);
    const shards = [];
    for (const id of index) {
        const data = await SecureStore.getItemAsync(`shard_${id}`);
        if (data) shards.push({ id, ...JSON.parse(data) });
    }
    return shards;
}
