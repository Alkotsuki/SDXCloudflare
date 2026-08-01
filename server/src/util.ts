// Low-level byte helpers used across attestation/assertion verification.
// Workers provide WebCrypto (crypto.subtle) and atob/btoa.

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

/** Constant-time byte comparison. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Convert an ASN.1 DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`)
 * to the raw r||s form (64 bytes for P-256) that WebCrypto's verify expects.
 */
export function derEcdsaToRaw(der: Uint8Array): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('Invalid DER: expected SEQUENCE');
  // Sequence length (may be long-form, ignored — we read each INTEGER explicitly).
  let lenByte = der[offset++];
  if (lenByte & 0x80) offset += lenByte & 0x7f;

  const readInt = (): Uint8Array => {
    if (der[offset++] !== 0x02) throw new Error('Invalid DER: expected INTEGER');
    const len = der[offset++];
    let v = der.slice(offset, offset + len);
    offset += len;
    // Strip leading zero padding, then left-pad to 32 bytes.
    while (v.length > 32 && v[0] === 0x00) v = v.slice(1);
    if (v.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(v, 32 - v.length);
      v = padded;
    }
    return v;
  };

  const r = readInt();
  const s = readInt();
  return concat(r, s);
}

export function readUInt32BE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) >>> 0) +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  );
}
