// App Attest attestation & assertion verification, implemented against
// WebCrypto so it runs in the Cloudflare Workers runtime.
//
// Follows Apple's "Validating apps that connect to your server":
//   https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
import 'reflect-metadata'; // required by tsyringe (transitive dep of @peculiar/x509 v2)
import { decode as cborDecode } from 'cbor-x';
import * as asn1js from 'asn1js';
import { X509Certificate, cryptoProvider } from '@peculiar/x509';
import { APPLE_APP_ATTEST_ROOT_CA_PEM } from './appleRoot';
import {
  base64ToBytes,
  concat,
  derEcdsaToRaw,
  readUInt32BE,
  sha256,
  timingSafeEqual,
  utf8,
} from './util';

cryptoProvider.set(crypto as unknown as Crypto);

const NONCE_OID = '1.2.840.113635.100.8.2';

/** What we persist per device after a successful attestation. */
export interface DeviceRecord {
  /** Base64 SPKI of the attested EC P-256 public key (for assertion verification). */
  publicKeySpki: string;
  /** Last accepted assertion sign counter (strictly increasing). */
  signCount: number;
}

function aaguidFor(env: string): Uint8Array {
  // 16 bytes. Production is "appattest" padded with zeros; sandbox is "appattestdevelop".
  const text = env === 'development' ? 'appattestdevelop' : 'appattest';
  const out = new Uint8Array(16);
  out.set(utf8(text).subarray(0, 16));
  return out;
}

interface AuthData {
  rpIdHash: Uint8Array;
  signCount: number;
  aaguid?: Uint8Array;
  credentialId?: Uint8Array;
}

function parseAuthData(authData: Uint8Array, includeAttestedCredential: boolean): AuthData {
  const rpIdHash = authData.subarray(0, 32);
  const signCount = readUInt32BE(authData, 33);
  if (!includeAttestedCredential) return { rpIdHash, signCount };

  const aaguid = authData.subarray(37, 53);
  const credIdLen = (authData[53] << 8) | authData[54];
  const credentialId = authData.subarray(55, 55 + credIdLen);
  return { rpIdHash, signCount, aaguid, credentialId };
}

/** Walk an ASN.1 tree for the 32-byte nonce octet string in the credCert extension. */
function extractNonce(extnValue: ArrayBuffer): Uint8Array {
  const parsed = asn1js.fromBER(extnValue);
  if (parsed.offset === -1) throw new Error('Could not parse nonce extension');
  const octets: Uint8Array[] = [];
  const walk = (node: unknown): void => {
    if (!node) return;
    if (node instanceof asn1js.OctetString) {
      octets.push(new Uint8Array(node.valueBlock.valueHexView));
    }
    const children = (node as { valueBlock?: { value?: unknown[] } }).valueBlock?.value;
    if (Array.isArray(children)) children.forEach(walk);
  };
  walk(parsed.result);
  const nonce = octets.find((o) => o.length === 32);
  if (!nonce) throw new Error('Nonce not found in credCert extension');
  return nonce;
}

async function importEcVerifyKey(spki: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}

/**
 * Verify an attestation object. Returns the device record to persist (public key
 * + initial counter). Throws on any failure.
 */
export async function verifyAttestation(params: {
  attestationBase64: string;
  challenge: string;
  keyId: string;
  appId: string;
  env: string;
}): Promise<DeviceRecord> {
  const { attestationBase64, challenge, keyId, appId, env } = params;

  const attestation = cborDecode(base64ToBytes(attestationBase64)) as {
    fmt: string;
    attStmt: { x5c: Uint8Array[] };
    authData: Uint8Array;
  };

  if (attestation.fmt !== 'apple-appattest') throw new Error('Unexpected attestation format');
  const x5c = attestation.attStmt?.x5c;
  if (!x5c || x5c.length < 2) throw new Error('Missing certificate chain');

  const authData = new Uint8Array(attestation.authData);

  // 1. Verify the certificate chain: credCert <- intermediate <- Apple root.
  const credCert = new X509Certificate(new Uint8Array(x5c[0]));
  const intermediateCert = new X509Certificate(new Uint8Array(x5c[1]));
  const rootCert = new X509Certificate(APPLE_APP_ATTEST_ROOT_CA_PEM);

  const intermediateKey = await intermediateCert.publicKey.export(crypto as unknown as Crypto);
  const rootKey = await rootCert.publicKey.export(crypto as unknown as Crypto);

  const credSignedByIntermediate = await credCert.verify({ publicKey: intermediateKey, signatureOnly: true });
  const intermediateSignedByRoot = await intermediateCert.verify({ publicKey: rootKey, signatureOnly: true });
  if (!credSignedByIntermediate || !intermediateSignedByRoot) {
    throw new Error('Certificate chain verification failed');
  }

  // 2. nonce = SHA256(authData || SHA256(challenge)); compare with credCert extension.
  const clientDataHash = await sha256(utf8(challenge));
  const expectedNonce = await sha256(concat(authData, clientDataHash));
  const ext = credCert.getExtension(NONCE_OID);
  if (!ext) throw new Error('credCert missing nonce extension');
  const actualNonce = extractNonce(ext.value);
  if (!timingSafeEqual(expectedNonce, actualNonce)) throw new Error('Attestation nonce mismatch');

  // 3. keyId must equal SHA256(uncompressed EC public key of credCert).
  const spki = new Uint8Array(credCert.publicKey.rawData);
  const verifyKey = await importEcVerifyKey(spki);
  const rawPoint = new Uint8Array((await crypto.subtle.exportKey('raw', verifyKey)) as ArrayBuffer);
  const keyHash = await sha256(rawPoint);
  const keyIdBytes = base64ToBytes(keyId);
  if (!timingSafeEqual(keyHash, keyIdBytes)) throw new Error('keyId does not match attested public key');

  // 4. Parse & validate authData.
  const parsed = parseAuthData(authData, true);
  const rpIdHash = await sha256(utf8(appId));
  if (!timingSafeEqual(parsed.rpIdHash, rpIdHash)) throw new Error('rpIdHash (App ID) mismatch');
  if (!parsed.aaguid || !timingSafeEqual(parsed.aaguid, aaguidFor(env))) {
    const got = parsed.aaguid ? new TextDecoder().decode(parsed.aaguid).replace(/\0+$/, '') : 'none';
    throw new Error(`aaguid mismatch: device sent "${got}", server expects "${env}" env`);
  }
  if (!parsed.credentialId || !timingSafeEqual(parsed.credentialId, keyIdBytes)) {
    throw new Error('Credential ID does not match keyId');
  }

  return { publicKeySpki: btoa(String.fromCharCode(...spki)), signCount: parsed.signCount };
}

/**
 * Verify an assertion over `clientData`. Returns the new sign counter to persist.
 * Throws on any failure (signature, App ID, or replayed counter).
 */
export async function verifyAssertion(params: {
  assertionBase64: string;
  clientData: Uint8Array;
  device: DeviceRecord;
  appId: string;
}): Promise<{ signCount: number }> {
  const { assertionBase64, clientData, device, appId } = params;

  const assertion = cborDecode(base64ToBytes(assertionBase64)) as {
    signature: Uint8Array;
    authenticatorData: Uint8Array;
  };
  const authenticatorData = new Uint8Array(assertion.authenticatorData);
  const signature = new Uint8Array(assertion.signature);

  // 1. nonce = SHA256(authenticatorData || SHA256(clientData)); verify signature over it.
  const clientDataHash = await sha256(clientData);
  const nonce = await sha256(concat(authenticatorData, clientDataHash));

  const verifyKey = await importEcVerifyKey(base64ToBytes(device.publicKeySpki));
  const rawSig = derEcdsaToRaw(signature);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verifyKey, rawSig, nonce);
  if (!valid) throw new Error('Assertion signature invalid');

  // 2. App ID (rpIdHash) must match.
  const parsed = parseAuthData(authenticatorData, false);
  const rpIdHash = await sha256(utf8(appId));
  if (!timingSafeEqual(parsed.rpIdHash, rpIdHash)) throw new Error('Assertion rpIdHash mismatch');

  // 3. Counter must strictly increase (replay protection).
  if (parsed.signCount <= device.signCount) throw new Error('Assertion counter did not increase (replay?)');

  return { signCount: parsed.signCount };
}
