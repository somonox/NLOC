import { Buffer } from 'buffer';
import { gcm } from '@noble/ciphers/aes';
import * as crypto from './crypto';

import TcpSocket from 'react-native-tcp-socket';

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
        const connectStr = `Connecting via TCP to ${this.info.ip}:${this.info.port}...`;
        this.statusCallback(connectStr);
        console.log(connectStr);

        const identityPriv = await crypto.getOrCreateIdentity();
        const identityPub = await crypto.getPublicKey(identityPriv);

        const options = {
            port: this.info.port,
            host: this.info.ip,
        };

        this.client = TcpSocket.createConnection(options, () => {
            this.statusCallback('TCP connected! Waiting for challenge...');
            console.log('TCP Socket explicitly opened.');
        });

        let buffer = '';

        this.client.on('data', async (data: any) => {
            buffer += data.toString('utf-8');
            let lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const msg = JSON.parse(line);
                    console.log('Received Message Type:', msg.type);
                    if (msg.type === 'challenge' && !this.authenticated) {
                        this.statusCallback('Challenge received. Authenticating...');
                        const signature = await crypto.signChallenge(identityPriv, msg.nonce);

                        const response = {
                            type: 'challengeResponse',
                            signature: Buffer.from(signature).toString('hex'),
                            publicKey: Buffer.from(identityPub).toString('hex'),
                            ecdhPublicKey: Buffer.from(this.ecdhPair.publicKey).toString('hex')
                        };
                        this.client?.write(JSON.stringify(response) + '\n');
                    } else if (msg.type === 'authSuccess') {
                        this.statusCallback('Authentication Successful!');
                        this.authenticated = true;
                        this.sessionKey = crypto.deriveSharedSecret(this.ecdhPair.privateKey, msg.ecdhPublicKey);
                        console.log('Mobile derived TCP session key');
                    } else if (msg.type === 'authFailed') {
                        this.statusCallback(`Auth Failed: ${msg.reason}`);
                    } else if (msg.type === 'encryptedPayload') {
                        await this.handleSecureMessage(msg);
                    }
                } catch (err) {
                    console.error('TCP Message Error:', err);
                }
            }
        });

        this.client.on('error', (e: any) => {
            console.error('TCP Error:', e);
            this.statusCallback(`Connection Error: ${e.message}`);
        });

        this.client.on('close', () => {
            this.statusCallback('Connection closed');
            console.log('TCP Socket closed.');
            this.authenticated = false;
        });
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
        if (this.ws) this.ws.close();
    }
}
