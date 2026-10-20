// Must be first: @peculiar/x509 v2 pulls in tsyringe, which needs the
// reflect-metadata polyfill loaded before it is imported.
import 'reflect-metadata';
import { verifyAttestation, verifyAssertion, type DeviceRecord } from './appattest';
import { verifyAppCheckToken } from './appcheck';
import { base64ToBytes, bytesToBase64, sha256 } from './util';

export interface Env {
  PROXY_KV: KVNamespace;
  // Firebase App Check (current clients). Project number from Firebase console → Project settings.
  FIREBASE_PROJECT_NUMBER?: string;
  // Comma-separated Firebase App IDs (`1:123:ios:abc`) allowed to call; unset = any app in the project.
  FIREBASE_APP_IDS?: string;
  // App Attest (legacy clients, SDXCloudflare before App Check). Also gates the dev bypass:
  // APPATTEST_ENV = "production" disables it.
  APP_ID: string;
  APPATTEST_ENV: string;
  DAILY_REQUEST_CAP: string;
  KILL_SWITCH: string;
  OPENAI_BASE_URL: string;
  OPENAI_API_KEY: string;
  DEV_BYPASS_TOKEN?: string;
  // Cloudflare AI Gateway token, required only when the gateway has
  // "Authenticated Gateway" enabled. Sent as `cf-aig-authorization`.
  AI_GATEWAY_TOKEN?: string;
  // Optional guards, off unless set. REQUIRE_STORE_FALSE = "1" refuses bodies without
  // `"store": false` (apps that promise nothing is kept at OpenAI). MAX_BODY_BYTES caps the body.
  REQUIRE_STORE_FALSE?: string;
  MAX_BODY_BYTES?: string;
}

const CHALLENGE_TTL_SECONDS = 300;
const DEVICE_TTL_SECONDS = 60 * 60 * 24 * 365; // refreshed on every accepted assertion

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function deviceKey(keyId: string) {
  return `device:${keyId}`;
}
function challengeKey(challenge: string) {
  return `chal:${challenge}`;
}

// --- /attest/challenge -------------------------------------------------------
// /attest/* and the X-Proxy-Key-Id/Assertion/Client-Data headers serve only legacy App Attest
// clients. Remove them (and appattest.ts, appleRoot.ts, the cbor/x509 deps) once those app
// versions are no longer in use.

async function handleChallenge(env: Env): Promise<Response> {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const challenge = bytesToBase64(random);
  await env.PROXY_KV.put(challengeKey(challenge), '1', { expirationTtl: CHALLENGE_TTL_SECONDS });
  return json({ challenge });
}

/** Consume a one-time challenge; returns false if absent/expired/already used. */
async function consumeChallenge(env: Env, challenge: string): Promise<boolean> {
  const exists = await env.PROXY_KV.get(challengeKey(challenge));
  if (!exists) return false;
  await env.PROXY_KV.delete(challengeKey(challenge));
  return true;
}

// --- /attest/register --------------------------------------------------------

async function handleRegister(request: Request, env: Env): Promise<Response> {
  const body = (await request.json()) as { keyId?: string; attestation?: string; challenge?: string };
  if (!body.keyId || !body.attestation || !body.challenge) {
    return json({ error: 'Missing keyId/attestation/challenge' }, 400);
  }
  if (!(await consumeChallenge(env, body.challenge))) {
    return json({ error: 'Invalid or expired challenge' }, 400);
  }

  try {
    const record = await verifyAttestation({
      attestationBase64: body.attestation,
      challenge: body.challenge,
      keyId: body.keyId,
      appId: env.APP_ID,
      env: env.APPATTEST_ENV,
    });
    await env.PROXY_KV.put(deviceKey(body.keyId), JSON.stringify(record), {
      expirationTtl: DEVICE_TTL_SECONDS,
    });
    return json({ ok: true });
  } catch (err) {
    return json({ error: `Attestation rejected: ${(err as Error).message}` }, 401);
  }
}

// --- rate limiting -----------------------------------------------------------

function dayStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Coarse per-device daily cap. Best-effort (KV is not transactional). */
async function overDailyCap(env: Env, keyId: string): Promise<boolean> {
  const cap = parseInt(env.DAILY_REQUEST_CAP, 10) || 0;
  if (cap <= 0) return false;
  const key = `rl:${keyId}:${dayStamp()}`;
  const current = parseInt((await env.PROXY_KV.get(key)) ?? '0', 10);
  if (current >= cap) return true;
  await env.PROXY_KV.put(key, String(current + 1), { expirationTtl: 60 * 60 * 48 });
  return false;
}

// --- /v1/responses (the proxy) ----------------------------------------------

async function handleProxy(request: Request, env: Env): Promise<Response> {
  if (env.KILL_SWITCH === '1') return json({ error: 'Service temporarily disabled' }, 503);

  const bodyBytes = new Uint8Array(await request.arrayBuffer());

  const maxBytes = parseInt(env.MAX_BODY_BYTES ?? '', 10);
  if (maxBytes > 0 && bodyBytes.byteLength > maxBytes) return json({ error: 'Request too large' }, 413);
  if (env.REQUIRE_STORE_FALSE === '1') {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as { store?: unknown };
      if (parsed.store !== false) return json({ error: 'store must be false' }, 400);
    } catch {
      return json({ error: 'Malformed body' }, 400);
    }
  }

  const devToken = request.headers.get('X-Proxy-Dev-Token');
  const devBypass =
    env.APPATTEST_ENV !== 'production' &&
    !!env.DEV_BYPASS_TOKEN &&
    devToken === env.DEV_BYPASS_TOKEN;

  let rateLimitKey = 'dev';
  const appCheckToken = request.headers.get('X-Firebase-AppCheck');

  if (!devBypass && appCheckToken) {
    if (!env.FIREBASE_PROJECT_NUMBER) return json({ error: 'App Check not configured' }, 500);
    try {
      await verifyAppCheckToken({
        token: appCheckToken,
        projectNumber: env.FIREBASE_PROJECT_NUMBER,
        appIds: (env.FIREBASE_APP_IDS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
      });
    } catch (err) {
      return json({ error: `App Check rejected: ${(err as Error).message}` }, 401);
    }
    // ponytail: the install id is client-chosen, so a caller holding valid App Check tokens can
    // rotate it to dodge the per-device cap. Use App Check limited-use tokens + replay protection
    // if that matters; AI Gateway rate limits still apply.
    const installId = request.headers.get('X-Proxy-Install-Id') ?? '';
    rateLimitKey = /^[A-Za-z0-9-]{8,64}$/.test(installId)
      ? `install:${installId}`
      : `ip:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}`;
  } else if (!devBypass) {
    const keyId = request.headers.get('X-Proxy-Key-Id');
    const assertion = request.headers.get('X-Proxy-Assertion');
    const clientDataB64 = request.headers.get('X-Proxy-Client-Data');
    if (!keyId || !assertion || !clientDataB64) {
      return json({ error: 'Missing App Check or App Attest headers' }, 401);
    }

    const stored = await env.PROXY_KV.get(deviceKey(keyId));
    if (!stored) return json({ error: 'Device not registered' }, 401);
    const device = JSON.parse(stored) as DeviceRecord;

    const clientData = base64ToBytes(clientDataB64);
    let parsedClientData: { challenge?: string; bodySHA256?: string };
    try {
      parsedClientData = JSON.parse(new TextDecoder().decode(clientData));
    } catch {
      return json({ error: 'Malformed client data' }, 400);
    }
    if (!parsedClientData.challenge || !(await consumeChallenge(env, parsedClientData.challenge))) {
      return json({ error: 'Invalid or expired challenge' }, 401);
    }

    // Bind the assertion to the exact body we will forward upstream.
    const bodyHash = bytesToBase64(await sha256(bodyBytes));
    if (parsedClientData.bodySHA256 !== bodyHash) {
      return json({ error: 'Request body hash mismatch' }, 401);
    }

    try {
      const { signCount } = await verifyAssertion({
        assertionBase64: assertion,
        clientData,
        device,
        appId: env.APP_ID,
      });
      // Persist the advanced counter so replays are rejected next time.
      await env.PROXY_KV.put(
        deviceKey(keyId),
        JSON.stringify({ ...device, signCount }),
        { expirationTtl: DEVICE_TTL_SECONDS }
      );
    } catch (err) {
      return json({ error: `Assertion rejected: ${(err as Error).message}` }, 401);
    }

    rateLimitKey = keyId;
  }

  if (await overDailyCap(env, rateLimitKey)) {
    return json({ error: 'Daily request limit reached' }, 429);
  }

  // Inject the shared key and forward verbatim. Streaming (SSE) and any
  // response-chaining tool calls pass through unchanged.
  const upstreamHeaders: Record<string, string> = {
    authorization: `Bearer ${env.OPENAI_API_KEY}`,
    'content-type': request.headers.get('content-type') ?? 'application/json',
  };
  // Gateway-level auth, required when AI Gateway "Authenticated Gateway" is on.
  if (env.AI_GATEWAY_TOKEN) {
    upstreamHeaders['cf-aig-authorization'] = `Bearer ${env.AI_GATEWAY_TOKEN}`;
  }
  const upstream = await fetch(`${env.OPENAI_BASE_URL}/v1/responses`, {
    method: 'POST',
    headers: upstreamHeaders,
    body: bodyBytes,
  });

  const headers = new Headers();
  const contentType = upstream.headers.get('content-type');
  if (contentType) headers.set('content-type', contentType);
  return new Response(upstream.body, { status: upstream.status, headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

    switch (url.pathname) {
      case '/attest/challenge':
        return handleChallenge(env);
      case '/attest/register':
        return handleRegister(request, env);
      case '/v1/responses':
        return handleProxy(request, env);
      default:
        return json({ error: 'Not found' }, 404);
    }
  },
};
