// Verification of Firebase ID tokens, written with the Web Crypto API
// (crypto.subtle), which works both in Node and in a Cloudflare Worker.
//
// A Firebase ID token is a JWT: three parts separated by dots,
//   header . payload . signature
// Each part is base64url text. The header and the payload are JSON.
// The signature proves that Google signed the first two parts.

export interface Jwk {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg?: string;
  use?: string;
}

export type KeyProvider = () => Promise<Jwk[]>;

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
}

export interface VerifiedToken {
  uid: string;
  payload: Record<string, unknown>;
}

export const AUTH_ERRORS: ReadonlySet<string> = new Set([
  'malformed-token',
  'invalid-algorithm',
  'unknown-key',
  'invalid-signature',
  'invalid-claims',
]);

export function base64UrlDecode(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(input) || input.length % 4 === 1) {
    throw new Error('invalid-base64url');
  }

  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split('.');

  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error('malformed-token');
  }

  try {
    const readObject = (part: string): Record<string, unknown> => {
      const bytes = base64UrlDecode(part);
      const value: unknown = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(bytes),
      );

      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('not-an-object');
      }

      return value as Record<string, unknown>;
    };

    return {
      header: readObject(parts[0]),
      payload: readObject(parts[1]),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64UrlDecode(parts[2]),
    };
  } catch {
    throw new Error('malformed-token');
  }
}

export function checkClaims(
  payload: Record<string, unknown>,
  projectId: string,
  nowSec: number,
): void {
  const valid =
    payload.aud === projectId &&
    payload.iss === `https://securetoken.google.com/${projectId}` &&
    typeof payload.exp === 'number' &&
    Number.isFinite(payload.exp) &&
    payload.exp > nowSec &&
    typeof payload.iat === 'number' &&
    Number.isFinite(payload.iat) &&
    payload.iat <= nowSec &&
    typeof payload.sub === 'string' &&
    payload.sub.length > 0 &&
    payload.sub.length <= 128;

  if (!valid) {
    throw new Error('invalid-claims');
  }
}

export function getBearerToken(
  header: string | null | undefined,
): string | null {
  const match = header?.match(/^\s*Bearer\s+(\S+)\s*$/i);
  return match?.[1] ?? null;
}

export async function verifyFirebaseIdToken(
  token: string,
  projectId: string,
  getKeys: KeyProvider,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<VerifiedToken> {
  const jwt = decodeJwt(token);

  if (jwt.header.alg !== 'RS256') {
    throw new Error('invalid-algorithm');
  }

  const keys = await getKeys();
  const jwk =
    typeof jwt.header.kid === 'string'
      ? keys.find((key) => key.kid === jwt.header.kid)
      : undefined;

  if (!jwk) {
    throw new Error('unknown-key');
  }

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  const validSignature = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    jwt.signature,
    new TextEncoder().encode(jwt.signingInput),
  );

  if (!validSignature) {
    throw new Error('invalid-signature');
  }

  checkClaims(jwt.payload, projectId, nowSec);

  return {
    uid: jwt.payload.sub as string,
    payload: jwt.payload,
  };
}