import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { createHandler, type Env } from './index';
import { PROJECT, goodPayload, makeKey, signToken, type TestKey } from './testkit';

let key: TestKey;
let other: TestKey;

before(async () => {
  key = await makeKey('test-key-1');
  other = await makeKey('test-key-1');
});

const ORIGIN = 'https://app.example.com';
const SECRET = 'dummy-secret-value-123';
const env: Env = { FIREBASE_PROJECT_ID: PROJECT, ALLOWED_ORIGIN: ORIGIN, API_SECRET: SECRET };
const getKeys = async () => [key.jwk];
const handler = createHandler(getKeys);

const nowSec = () => Math.floor(Date.now() / 1000);
const goodToken = (over: Record<string, unknown> = {}) => signToken(key, goodPayload(nowSec(), over));
const call = (path: string, init: RequestInit = {}, e: Env = env, h = handler) =>
  h(new Request('https://worker.test' + path, init), e);
const bearer = (token: string): RequestInit => ({ headers: { Authorization: `Bearer ${token}` } });

// ------------------------------------------------------------------- /health
test('GET /health is public and answers { ok: true }', async () => {
  const res = await call('/health');
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test('answers are JSON', async () => {
  const res = await call('/health');
  assert.match(res.headers.get('Content-Type') ?? '', /application\/json/);
});

test('POST /health is not allowed', async () => {
  const res = await call('/health', { method: 'POST' });
  assert.equal(res.status, 405);
  assert.equal(res.headers.get('Allow'), 'GET');
  assert.deepEqual(await res.json(), { error: 'method-not-allowed' });
});

// ----------------------------------------------------------------------- /me
test('GET /me without a token answers 401', async () => {
  const res = await call('/me');
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

test('GET /me with a garbage token answers 401', async () => {
  const res = await call('/me', bearer('garbage'));
  assert.equal(res.status, 401);
});

test('GET /me with a valid token answers the uid and email', async () => {
  const res = await call('/me', bearer(await goodToken()));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { uid: 'user-1', email: 'alice@example.com' });
});

test('GET /me answers email null when the token has no email', async () => {
  const res = await call('/me', bearer(await goodToken({ email: undefined })));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { uid: 'user-1', email: null });
});

test('GET /me with an expired token answers 401', async () => {
  const res = await call('/me', bearer(await goodToken({ exp: nowSec() - 10 })));
  assert.equal(res.status, 401);
});

test('GET /me with a token for another project answers 401', async () => {
  const res = await call('/me', bearer(await goodToken({ aud: 'another-project' })));
  assert.equal(res.status, 401);
});

test('GET /me with a token signed by a different key answers 401', async () => {
  const forged = await signToken(other, goodPayload(nowSec()));
  const res = await call('/me', bearer(forged));
  assert.equal(res.status, 401);
});

test('POST /me is not allowed', async () => {
  const res = await call('/me', { method: 'POST', ...bearer(await goodToken()) });
  assert.equal(res.status, 405);
});

test('when the keys cannot be downloaded the answer is 503, not 401, and nothing leaks', async () => {
  const broken = createHandler(async () => { throw new Error('jwks-fetch-failed'); });
  const res = await call('/me', bearer(await goodToken()), env, broken);
  assert.equal(res.status, 503);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), { error: 'auth-unavailable' });
  assert.ok(!text.includes('jwks'));
});

// ------------------------------------------------------------ /secret-status
test('GET /secret-status without a token answers 401', async () => {
  const res = await call('/secret-status');
  assert.equal(res.status, 401);
});

test('GET /secret-status says configured: true when the secret exists, without revealing it', async () => {
  const res = await call('/secret-status', bearer(await goodToken()));
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), { configured: true });
  assert.ok(!text.includes(SECRET));
  assert.ok(!text.includes('dummy-secret'));
});

test('GET /secret-status says configured: false when there is no secret', async () => {
  const noSecret: Env = { FIREBASE_PROJECT_ID: PROJECT, ALLOWED_ORIGIN: ORIGIN };
  const res = await call('/secret-status', bearer(await goodToken()), noSecret);
  assert.deepEqual(await res.json(), { configured: false });
});

test('GET /secret-status says configured: false for an empty secret', async () => {
  const empty: Env = { FIREBASE_PROJECT_ID: PROJECT, ALLOWED_ORIGIN: ORIGIN, API_SECRET: '' };
  const res = await call('/secret-status', bearer(await goodToken()), empty);
  assert.deepEqual(await res.json(), { configured: false });
});

// ----------------------------------------------------------------- the rest
test('an unknown path answers 404', async () => {
  const res = await call('/nothing-here');
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'not-found' });
});

test('OPTIONS answers the CORS preflight with 204 and the allowed origin', async () => {
  const res = await call('/me', { method: 'OPTIONS' });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), ORIGIN);
  assert.match(res.headers.get('Access-Control-Allow-Headers') ?? '', /Authorization/);
});

test('error answers also carry the CORS header, so the browser can read them', async () => {
  const res = await call('/me');
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), ORIGIN);
});

test('the allowed origin is never the wildcard', async () => {
  const none: Env = { FIREBASE_PROJECT_ID: PROJECT };
  const res = await call('/health', {}, none);
  assert.notEqual(res.headers.get('Access-Control-Allow-Origin'), '*');
});

test('GET /me rejects a signed token that claims HS256', async () => {
  const token = await signToken(key, goodPayload(nowSec()), { alg: 'HS256' });
  const res = await call('/me', bearer(token));

  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

test('GET /secret-status rejects a payload changed after signing', async () => {
  const token = await goodToken();
  const [header, , signature] = token.split('.');
  const changedPayload = goodPayload(nowSec(), { sub: 'admin-user' });
  const forged = [
    header,
    Buffer.from(JSON.stringify(changedPayload)).toString('base64url'),
    signature,
  ].join('.');

  const res = await call('/secret-status', bearer(forged));
  assert.equal(res.status, 401);
  const body = await res.text();
  assert.deepEqual(JSON.parse(body), { error: 'unauthorized' });
  assert.ok(!body.includes(SECRET));
});
