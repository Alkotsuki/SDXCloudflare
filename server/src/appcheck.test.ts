// Self-check for appcheck.ts: `npm test`. Signs tokens with a throwaway RSA key and serves it as the JWKS.
import assert from 'node:assert/strict';
import { verifyAppCheckToken } from './appcheck';

const b64url = (bytes: Uint8Array | string) =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const { privateKey, publicKey } = (await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify']
)) as CryptoKeyPair;
const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'k1' };
globalThis.fetch = (async () => new Response(JSON.stringify({ keys: [jwk] }))) as typeof fetch;

const now = 1_800_000_000;
async function sign(payload: object, header: object = { alg: 'RS256', typ: 'JWT', kid: 'k1' }) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(input)));
  return `${input}.${b64url(sig)}`;
}
const good = {
  iss: 'https://firebaseappcheck.googleapis.com/123',
  aud: ['projects/123', 'projects/my-project'],
  sub: '1:123:ios:abc',
  exp: now + 3600,
};
const check = (token: string, appIds: string[] = []) =>
  verifyAppCheckToken({ token, projectNumber: '123', appIds, now });

assert.deepEqual(await check(await sign(good)), { appId: '1:123:ios:abc' });
assert.deepEqual(await check(await sign(good), ['1:123:ios:abc']), { appId: '1:123:ios:abc' });
await assert.rejects(check(await sign(good), ['1:123:ios:other']), /App ID mismatch/);
await assert.rejects(check(await sign({ ...good, exp: now - 120 })), /expired/);
await assert.rejects(check(await sign({ ...good, iss: 'https://firebaseappcheck.googleapis.com/999' })), /Issuer/);
await assert.rejects(check(await sign({ ...good, aud: ['projects/999'] })), /Audience/);
await assert.rejects(check(await sign(good, { alg: 'none', typ: 'JWT', kid: 'k1' })), /header/);
await assert.rejects(check(await sign(good, { alg: 'RS256', typ: 'JWT', kid: 'nope' })), /Unknown signing key/);
const [h, , s] = (await sign(good)).split('.');
await assert.rejects(check(`${h}.${b64url(JSON.stringify({ ...good, sub: '1:123:ios:evil' }))}.${s}`), /Signature/);
console.log('appcheck: ok');
