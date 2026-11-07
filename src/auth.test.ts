import test from 'node:test';
import assert from 'node:assert/strict';
import { base64UrlDecode, checkClaims, decodeJwt, getBearerToken, verifyFirebaseIdToken } from './auth';
import { NOW, PROJECT, b64url, goodPayload, makeKey, signToken } from './testkit';

const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

// ------------------------------------------------------------ base64UrlDecode
test('base64UrlDecode decodes plain text', () => {
  assert.equal(text(base64UrlDecode('aGVsbG8')), 'hello');
});

test('base64UrlDecode works with every padding length', () => {
  assert.equal(text(base64UrlDecode('aA')), 'h');
  assert.equal(text(base64UrlDecode('aGk')), 'hi');
  assert.equal(text(base64UrlDecode('aGVy')), 'her');
});

test('base64UrlDecode understands - and _', () => {
  assert.deepEqual(Array.from(base64UrlDecode('-_8')), [0xfb, 0xff]);
});

test('base64UrlDecode rejects invalid text', () => {
  assert.throws(() => base64UrlDecode('a!b'));
});

// ------------------------------------------------------------------ decodeJwt
test('decodeJwt returns the header, the payload and the signing input', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW));
  const jwt = decodeJwt(token);
  assert.equal(jwt.header.alg, 'RS256');
  assert.equal(jwt.header.kid, 'test-key-1');
  assert.equal(jwt.payload.sub, 'user-1');
  assert.equal(jwt.signingInput, token.split('.').slice(0, 2).join('.'));
  assert.ok(jwt.signature.length > 0);
});

for (const [label, token] of [
  ['an empty string', ''],
  ['two parts', 'aaa.bbb'],
  ['four parts', 'aaa.bbb.ccc.ddd'],
  ['an empty part', `${b64url('{}')}..${b64url('x')}`],
  ['a header that is not JSON', `${b64url('not json')}.${b64url('{}')}.${b64url('x')}`],
  ['a payload that is not an object', `${b64url('{}')}.${b64url('[]')}.${b64url('x')}`],
  ['a signature that is not base64url', `${b64url('{}')}.${b64url('{}')}.a!b`],
] as const) {
  test(`decodeJwt rejects ${label}`, () => {
    assert.throws(() => decodeJwt(token), { message: 'malformed-token' });
  });
}

// ---------------------------------------------------------------- checkClaims
test('checkClaims accepts a good payload', () => {
  assert.doesNotThrow(() => checkClaims(goodPayload(NOW), PROJECT, NOW));
});

test('checkClaims accepts iat equal to now', () => {
  assert.doesNotThrow(() => checkClaims(goodPayload(NOW, { iat: NOW }), PROJECT, NOW));
});

for (const [label, over] of [
  ['a wrong audience', { aud: 'another-project' }],
  ['a wrong issuer', { iss: 'https://securetoken.google.com/another-project' }],
  ['an expired token', { exp: NOW - 1 }],
  ['a token that expires exactly now', { exp: NOW }],
  ['an exp that is not a number', { exp: String(NOW + 100) }],
  ['an iat in the future', { iat: NOW + 1 }],
  ['a missing sub', { sub: undefined }],
  ['an empty sub', { sub: '' }],
  ['a sub that is not a string', { sub: 12345 }],
  ['a sub longer than 128 characters', { sub: 'x'.repeat(129) }],
] as const) {
  test(`checkClaims rejects ${label}`, () => {
    assert.throws(() => checkClaims(goodPayload(NOW, over), PROJECT, NOW), { message: 'invalid-claims' });
  });
}

// ------------------------------------------------------------- getBearerToken
test('getBearerToken reads a Bearer header', () => {
  assert.equal(getBearerToken('Bearer abc.def.ghi'), 'abc.def.ghi');
});

test('getBearerToken ignores the case of the word Bearer', () => {
  assert.equal(getBearerToken('bearer abc'), 'abc');
});

test('getBearerToken returns null for a missing or wrong header', () => {
  assert.equal(getBearerToken(null), null);
  assert.equal(getBearerToken(undefined), null);
  assert.equal(getBearerToken(''), null);
  assert.equal(getBearerToken('Basic abc'), null);
  assert.equal(getBearerToken('Bearer'), null);
  assert.equal(getBearerToken('Bearer   '), null);
});

// ------------------------------------------------------ verifyFirebaseIdToken
test('verifyFirebaseIdToken returns the uid for a valid token', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW));
  const result = await verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW);
  assert.equal(result.uid, 'user-1');
  assert.equal(result.payload.email, 'alice@example.com');
});

test('verifyFirebaseIdToken finds the right key among several', async () => {
  const other = await makeKey('other-key');
  const key = await makeKey('test-key-1');
  const token = await signToken(key, goodPayload(NOW));
  const result = await verifyFirebaseIdToken(token, PROJECT, async () => [other.jwk, key.jwk], NOW);
  assert.equal(result.uid, 'user-1');
});

test('verifyFirebaseIdToken rejects a malformed token', async () => {
  const key = await makeKey();
  await assert.rejects(verifyFirebaseIdToken('not-a-token', PROJECT, async () => [key.jwk], NOW), { message: 'malformed-token' });
});

test('verifyFirebaseIdToken rejects the algorithm HS256', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW), { alg: 'HS256' });
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW), { message: 'invalid-algorithm' });
});

test('verifyFirebaseIdToken rejects the algorithm none', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW), { alg: 'none' });
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW), { message: 'invalid-algorithm' });
});

test('verifyFirebaseIdToken rejects an unknown key id', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW), { kid: 'unknown' });
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW), { message: 'unknown-key' });
});

test('verifyFirebaseIdToken rejects a payload that was changed after signing', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW));
  const [header, , signature] = token.split('.');
  const forged = `${header}.${b64url(JSON.stringify(goodPayload(NOW, { sub: 'admin-user' })))}.${signature}`;
  await assert.rejects(verifyFirebaseIdToken(forged, PROJECT, async () => [key.jwk], NOW), { message: 'invalid-signature' });
});

test('verifyFirebaseIdToken rejects a token signed with a different key', async () => {
  const real = await makeKey('test-key-1');
  const attacker = await makeKey('test-key-1'); // same kid, different key
  const token = await signToken(attacker, goodPayload(NOW));
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [real.jwk], NOW), { message: 'invalid-signature' });
});

test('verifyFirebaseIdToken rejects an expired token even when the signature is good', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW, { exp: NOW - 10 }));
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW), { message: 'invalid-claims' });
});

test('verifyFirebaseIdToken rejects a token for another project', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW, { aud: 'another-project', iss: 'https://securetoken.google.com/another-project' }));
  await assert.rejects(verifyFirebaseIdToken(token, PROJECT, async () => [key.jwk], NOW), { message: 'invalid-claims' });
});

test('verifyFirebaseIdToken passes errors from the key provider through unchanged', async () => {
  const key = await makeKey();
  const token = await signToken(key, goodPayload(NOW));
  await assert.rejects(
    verifyFirebaseIdToken(token, PROJECT, async () => { throw new Error('jwks-fetch-failed'); }, NOW),
    { message: 'jwks-fetch-failed' },
  );
});
