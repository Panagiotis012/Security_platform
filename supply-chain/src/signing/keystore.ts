/**
 * Encrypted keystore for supply-chain signing keys.
 *
 * Goal: keep signing keys stable across restarts while avoiding plaintext
 * private keys at rest in the Docker volume.
 *
 * Notes:
 * - This is NOT a replacement for a real KMS/HSM in production.
 * - The master key MUST be unique and kept secret.
 */

import crypto from 'crypto';
import { mkdir, readFile, rename, writeFile } from 'fs/promises';
import path from 'path';
import type { RegisteredKey } from './key-registry';

export type KeystoreEncryptedBlob = {
  enc: 'AES-256-GCM';
  iv_b64: string;
  tag_b64: string;
  ciphertext_b64: string;
};

export type KeystoreKeyEntry = {
  record: RegisteredKey;
  privateKey: KeystoreEncryptedBlob;
};

export type KeystoreFile = {
  version: 1;
  updatedAt: string;
  keys: KeystoreKeyEntry[];
};

function looksHex(s: string): boolean {
  return /^[0-9a-fA-F]+$/.test(s);
}

export function parseKeystoreMasterKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('SUPPLY_CHAIN_KEYSTORE_MASTER_KEY is missing');

  // Accept either:
  // - 64 hex chars (32 bytes)
  // - base64 of 32 bytes
  if (trimmed.length === 64 && looksHex(trimmed)) {
    const buf = Buffer.from(trimmed, 'hex');
    if (buf.length !== 32) throw new Error('SUPPLY_CHAIN_KEYSTORE_MASTER_KEY must be 32 bytes');
    return buf;
  }

  // Fall back to base64.
  const buf = Buffer.from(trimmed, 'base64');
  if (buf.length !== 32) {
    throw new Error('SUPPLY_CHAIN_KEYSTORE_MASTER_KEY must be 32 bytes (64 hex chars or base64-encoded)');
  }
  return buf;
}

function encryptPem(pem: string, masterKey: Buffer): KeystoreEncryptedBlob {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    enc: 'AES-256-GCM',
    iv_b64: iv.toString('base64'),
    tag_b64: tag.toString('base64'),
    ciphertext_b64: ciphertext.toString('base64'),
  };
}

function decryptPem(blob: KeystoreEncryptedBlob, masterKey: Buffer): string {
  if (blob.enc !== 'AES-256-GCM') throw new Error('Unsupported keystore encryption');
  const iv = Buffer.from(blob.iv_b64, 'base64');
  const tag = Buffer.from(blob.tag_b64, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext_b64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

function normalizeLoadedFile(raw: unknown): KeystoreFile {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Invalid keystore JSON');
  const obj = raw as Record<string, unknown>;
  if (obj['version'] !== 1) throw new Error('Unsupported keystore version');
  if (!Array.isArray(obj['keys'])) throw new Error('Invalid keystore JSON: keys');
  return {
    version: 1,
    updatedAt: typeof obj['updatedAt'] === 'string' ? obj['updatedAt'] : new Date().toISOString(),
    keys: obj['keys'] as KeystoreKeyEntry[],
  };
}

export class SupplyChainKeystore {
  private readonly filePath: string;
  private readonly masterKey: Buffer;
  private file: KeystoreFile = { version: 1, updatedAt: new Date().toISOString(), keys: [] };

  constructor(filePath: string, masterKey: Buffer) {
    this.filePath = filePath;
    this.masterKey = masterKey;
  }

  async load(): Promise<void> {
    try {
      const text = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(text) as unknown;
      this.file = normalizeLoadedFile(parsed);
    } catch (err: unknown) {
      // If missing, start empty.
      const code = ((): string | undefined => {
        if (!err || typeof err !== 'object' || Array.isArray(err)) return undefined;
        const v = (err as { code?: unknown }).code;
        return typeof v === 'string' ? v : undefined;
      })();
      if (code === 'ENOENT') {
        this.file = { version: 1, updatedAt: new Date().toISOString(), keys: [] };
        return;
      }
      throw err;
    }
  }

  isEmpty(): boolean {
    return this.file.keys.length === 0;
  }

  listRecords(): RegisteredKey[] {
    return this.file.keys.map((e) => ({ ...e.record }));
  }

  getRecord(keyId: string): RegisteredKey | null {
    const idx = this.file.keys.findIndex((e) => e.record.keyId === keyId);
    if (idx < 0) return null;
    return { ...this.file.keys[idx]!.record };
  }

  getPrivateKeyPem(keyId: string): string | null {
    const idx = this.file.keys.findIndex((e) => e.record.keyId === keyId);
    if (idx < 0) return null;
    return decryptPem(this.file.keys[idx]!.privateKey, this.masterKey);
  }

  async upsert(record: RegisteredKey, privateKeyPem: string): Promise<void> {
    const idx = this.file.keys.findIndex((e) => e.record.keyId === record.keyId);
    const entry: KeystoreKeyEntry = {
      record: { ...record },
      privateKey: encryptPem(privateKeyPem, this.masterKey),
    };
    if (idx < 0) this.file.keys.push(entry);
    else this.file.keys[idx] = entry;
    await this.persist();
  }

  async updateRecord(record: RegisteredKey): Promise<void> {
    const idx = this.file.keys.findIndex((e) => e.record.keyId === record.keyId);
    if (idx < 0) {
      throw new Error(`Keystore missing key record ${record.keyId}`);
    }
    // Preserve existing encrypted private key blob.
    const existing = this.file.keys[idx]!;
    this.file.keys[idx] = { record: { ...record }, privateKey: existing.privateKey };
    await this.persist();
  }

  private async persist(): Promise<void> {
    this.file.updatedAt = new Date().toISOString();
    const dir = path.dirname(this.filePath);
    await mkdir(dir, { recursive: true });

    const tmpPath = path.join(dir, `.keystore.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    const payload = JSON.stringify(this.file, null, 2) + '\n';
    await writeFile(tmpPath, payload, { mode: 0o600 });
    await rename(tmpPath, this.filePath);
  }
}
