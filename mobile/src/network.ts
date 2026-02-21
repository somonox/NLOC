import { Buffer } from 'buffer';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes';
import * as crypto from './crypto';

// @ts-ignore
import dgram from 'react-native-udp';

export interface ConnectionInfo {
    ip: string;
    port: number;
}

export class NLOCClient {
    private client: any = null;
    private sessionKey: Uint8Array | null = null;
    private ecdhPair = crypto.generateECDHKeyPair();
    private statusCallback: (status: string) => void;
    private shardCallback: (shard: any) => void;
    private authenticated = false;

    constructor(
        private info: ConnectionInfo,
        statusCallback: (status: string) => void,
        shardCallback: (shard: any) => void
    ) {
        this.statusCallback = statusCallback;
        this.shardCallback = shardCallback;
    }

    async connect() {
        const connectStr = `Punching UDP hole to ${this.info.ip}:${this.info.port}...`;
        this.statusCallback(connectStr);
        console.log(connectStr);

        const identityPriv = await crypto.getOrCreateIdentity();
        const identityPub = await crypto.getPublicKey(identityPriv);

        this.client = dgram.createSocket({ type: 'udp4' });
        this.client.bind(); // Bind to ephemeral local port for P2P punching

        let challengeReceived = false;

        this.client.on('message', async (msg: any, rinfo: any) => {
            // Only accept packets from the expected host IP and Port
            if (rinfo.address !== this.info.ip || rinfo.port !== this.info.port) return;

            const text = msg.toString('utf-8').trim();
            if (!text) return;

            try {
                const jsonMsg = JSON.parse(text);
                console.log('Received UDP Message Type:', jsonMsg.type);

                if (jsonMsg.type === 'challenge' && !this.authenticated) {
                    challengeReceived = true;
                    this.statusCallback('Challenge received. Authenticating...');
                    const signature = await crypto.signChallenge(identityPriv, jsonMsg.nonce);

                    const response = {
                        type: 'challengeResponse',
                        signature: Buffer.from(signature).toString('hex'),
                        publicKey: Buffer.from(identityPub).toString('hex'),
                        ecdhPublicKey: Buffer.from(this.ecdhPair.publicKey).toString('hex')
                    };
                    const payload = JSON.stringify(response) + '\n';
                    this.client.send(payload, undefined, undefined, this.info.port, this.info.ip);
                } else if (jsonMsg.type === 'authSuccess') {
                    this.statusCallback('Authentication Successful! Link Secure.');
                    this.authenticated = true;
                    this.sessionKey = crypto.deriveSharedSecret(this.ecdhPair.privateKey, jsonMsg.ecdhPublicKey);
                    console.log('Mobile derived UDP session key');
                } else if (jsonMsg.type === 'authFailed') {
                    this.statusCallback(`Auth Failed: ${jsonMsg.reason}`);
                } else if (jsonMsg.type === 'encryptedPayload') {
                    await this.handleSecureMessage(jsonMsg);
                }
            } catch (err) {
                console.error('UDP Message Parse Error:', err);
            }
        });

        this.client.on('error', (e: any) => {
            console.error('UDP Error:', e);
            this.statusCallback(`Connection Error: ${e.message}`);
        });

        // STUN / Hole Punching Init
        const punchHole = () => {
            if (!challengeReceived) {
                this.client.send('hello\n', undefined, undefined, this.info.port, this.info.ip, (err: any) => {
                    if (err) console.error('UDP Punch Error:', err);
                    else console.log('Sent UDP hole-punch packet');
                });
            }
        };

        punchHole();
        let attempts = 0;
        const interval = setInterval(() => {
            if (challengeReceived || attempts >= 10) {
                clearInterval(interval);
                if (!challengeReceived) {
                    this.statusCallback('Failed to punch UDP hole (Timeout).');
                }
            } else {
                punchHole();
                attempts++;
            }
        }, 1000);
    }

    private async handleSecureMessage(msg: any) {
        if (!this.sessionKey) return;

        try {
            const nonce = Buffer.from(msg.nonce, 'hex');
            const ciphertext = Buffer.from(msg.ciphertext, 'hex');

            const aes = gcm(this.sessionKey, nonce);
            const plaintext = aes.decrypt(ciphertext);

            const appMsg = JSON.parse(Buffer.from(plaintext).toString('utf-8'));

            if (appMsg.action === 'storeShard') {
                this.statusCallback(`Receiving shard: ${appMsg.label}`);
                await crypto.saveShard(appMsg.id, appMsg.label, appMsg.shardData);
                this.shardCallback({ id: appMsg.id, label: appMsg.label });
                this.statusCallback(`✅ Shard stored: ${appMsg.label}`);
            }
        } catch (err) {
            console.error('Decryption Error:', err);
        }
    }

    disconnect() {
        if (this.client) this.client.close();
    }
}
