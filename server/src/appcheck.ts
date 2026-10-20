// Firebase App Check token verification, implemented against WebCrypto so it runs in Workers.
//
// Follows "Verify App Check tokens using a JWT library":
//   https://firebase.google.com/docs/app-check/custom-resource-backend#other
import { base64ToBytes, utf8 } from './util';

const JWKS_URL = 'https://firebaseappcheck.googleapis.com/v1/jwks';
// Firebase asks backends not to cache the key set for longer than 6 hours.
const JWKS_TTL_MS = 6 * 60 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;

type Jwk = JsonWebKey & { kid: string };

// Per-isolate cache; a cold isolate refetches.
let jwksCache: { keys: Jwk[]; fetchedAt: number } | undefined;

async function jwks(forceRefresh: boolean): Promise<Jwk[]> {
  if (!forceRefresh && jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;
  const response = await fetch(JWKS_URL);
  if (!response.ok) throw new Error(`JWKS fetch failed (${response.status})`);
  const { keys } = (await response.json()) as { keys: Jwk[] };
  jwksCache = { keys, fetchedAt: Date.now() };
  return keys;
}

function base64UrlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return base64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

function decodeSegment<T>(segment: string): T {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as T;
}

/**
 * Verify an App Check token (the `X-Firebase-AppCheck` header). Returns the Firebase App ID it
 * was issued to. Throws on any failure.
 */
export async function verifyAppCheckToken(params: {
  token: string;
  projectNumber: string;
  /** Allowed Firebase App IDs (`sub`). Empty = any app in the project. */
  appIds: string[];
  now?: number;
}): Promise<{ appId: string }> {
  const { token, projectNumber, appIds } = params;
  const now = params.now ?? Math.floor(Date.now() / 1000);

  const segments = token.split('.');
  if (segments.length !== 3) throw new Error('Malformed token');
  const [headerB64, payloadB64, signatureB64] = segments;

  const header = decodeSegment<{ alg?: string; typ?: string; kid?: string }>(headerB64);
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || !header.kid) throw new Error('Unexpected token header');

  // A kid we have not seen means Firebase rotated keys since our last fetch.
  let jwk = (await jwks(false)).find((k) => k.kid === header.kid);
  jwk ??= (await jwks(true)).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Unknown signing key');

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'verify',
  ]);
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64UrlToBytes(signatureB64),
    utf8(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error('Signature invalid');

  const payload = decodeSegment<{ iss?: string; aud?: string | string[]; sub?: string; exp?: number }>(payloadB64);
  if (payload.iss !== `https://firebaseappcheck.googleapis.com/${projectNumber}`) throw new Error('Issuer mismatch');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(`projects/${projectNumber}`)) throw new Error('Audience mismatch');
  if (typeof payload.exp !== 'number' || payload.exp + CLOCK_SKEW_SECONDS < now) throw new Error('Token expired');
  if (!payload.sub || (appIds.length > 0 && !appIds.includes(payload.sub))) throw new Error('App ID mismatch');

  return { appId: payload.sub };
}
