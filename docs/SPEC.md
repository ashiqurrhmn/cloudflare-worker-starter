# Cloudflare Worker Specification

Write the code in `src/auth.ts` and `src/index.ts`. The tests in `src/auth.test.ts` and `src/handler.test.ts` describe the expected behaviour exactly. `src/keys.ts` and `src/testkit.ts` are complete.

## What the Worker does

It offers a few small web addresses. Some are public, some need a valid Firebase ID token from a signed-in user. The Worker proves who the caller is by checking the token's **signature** with Google's public keys, then checking its **claims**.

## Routes

| Method and path | Needs a token | Answer |
|---|---|---|
| `OPTIONS` (any path) | No | `204`, CORS headers, empty body |
| `GET /health` | No | `200` `{ "ok": true }` |
| `GET /me` | Yes | `200` `{ "uid": "...", "email": "..." }` (`email` is `null` when the token has none) |
| `GET /secret-status` | Yes | `200` `{ "configured": true }` or `{ "configured": false }`. **Never** the secret itself |
| any other path | No | `404` `{ "error": "not-found" }` |
| wrong method on a known path | | `405` `{ "error": "method-not-allowed" }` and, for `/health`, the header `Allow: GET` |

## Errors

| Situation | Answer |
|---|---|
| No token, or a token that is not acceptable | `401` `{ "error": "unauthorized" }` |
| The public keys could not be downloaded (a server problem, not the caller's fault) | `503` `{ "error": "auth-unavailable" }` and `console.error` of the real reason |

The real error message must never be sent to the caller. Every answer, including errors, carries the CORS headers and `Content-Type: application/json`.

## Token checks (`verifyFirebaseIdToken`)

In this order: decode the token, the algorithm must be `RS256`, find the key by `kid`, verify the signature, then check the claims:

| Claim | Must be |
|---|---|
| `aud` | the project ID |
| `iss` | `https://securetoken.google.com/<project ID>` |
| `exp` | a number greater than the current time |
| `iat` | a number less than or equal to the current time |
| `sub` | a non-empty string of at most 128 characters (this is the uid) |

## Variables and secrets

| Name | Kind | Where it lives |
|---|---|---|
| `FIREBASE_PROJECT_ID` | public configuration | `wrangler.jsonc`, `vars` |
| `ALLOWED_ORIGIN` | public configuration | `wrangler.jsonc`, `vars` |
| `API_SECRET` | **secret** | local: `.dev.vars` (ignored by Git). Deployed: `wrangler secret put API_SECRET` |
| `JWKS_URL` | local testing only | `.dev.vars` only. Never in a deployed Worker |

## Working method

1. Run `npm test` and observe the failing tests.
2. Implement `src/auth.ts` until every `auth` test passes.
3. Implement `src/index.ts` following the TODO comments until every `handler` test passes.
4. Run the Worker locally with `npm run dev`, start the local key server with `npm run jwks`, and call your routes with `curl`.
5. Read your code once more and ask: "Could anyone get a `200` without a genuine token?"
