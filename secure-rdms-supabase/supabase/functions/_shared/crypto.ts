function keyBytes() {
  const raw = Deno.env.get('RDMS_ENCRYPTION_KEY');
  if (!raw) throw new Error('RDMS_ENCRYPTION_KEY is not configured');
  const bytes = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
  if (bytes.length !== 32) throw new Error('RDMS_ENCRYPTION_KEY must be base64-encoded 32 bytes');
  return bytes;
}
export async function encryptFile(plain: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyBytes(), 'AES-GCM', false, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const envelope = new Uint8Array(iv.length + encrypted.length);
  envelope.set(iv); envelope.set(encrypted, iv.length);
  return envelope;
}
export async function decryptFile(envelope: Uint8Array) {
  if (envelope.length < 29) throw new Error('Encrypted file is invalid');
  const iv = envelope.slice(0, 12), ciphertext = envelope.slice(12);
  const key = await crypto.subtle.importKey('raw', keyBytes(), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext));
}
