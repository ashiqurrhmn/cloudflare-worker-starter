# Cloudflare Worker Starter

Week 1 exercise: write a Cloudflare Worker in TypeScript that verifies Firebase ID tokens, keeps a secret out of the browser, and answers a few routes.

## What you will learn

- What a Worker is and why secrets belong there and never in browser code
- How a JWT (a Firebase ID token) is built, and how its signature and claims are verified
- The difference between public variables, secrets, and local-only values
- CORS, and why an error must not leak internal details
- Running a Worker locally with Wrangler, and (optionally) deploying it

## Prerequisites

- Node.js 20.3 or newer (`node -v`)
- Git
- A free Cloudflare account **only** if you do the optional deploy (Part E)

Everything else runs on your computer. **No card is needed** for this exercise.

## Setup

```
npm install
npm test
```

On the first run the tests fail. This is expected, because the code is not written yet.

## Parts

- **Part A:** write `src/auth.ts` until the `auth` tests pass.
- **Part B:** write `src/index.ts` until the `handler` tests pass.
- **Part C:** run locally with `npm run dev` and `npm run jwks`, and call the Worker with `curl`.
- **Part D:** test with a real token from your own Firebase sandbox project (from the Firebase exercise).
- **Part E (optional):** deploy to Cloudflare's free plan and set a real secret with `wrangler secret put`.

Read `docs/SPEC.md` first. The instruction document explains each part in detail.

## Deliverables

- Repository link with your completed `auth.ts` and `index.ts` (no `node_modules`, no `.dev.vars`, no tokens)
- Output of `npm test` with all tests passing
- Output of your `curl` calls (hide any token) from Part C
- Your two additional tests
- A table: for each safeguard in your code, which risk it prevents and how you proved it

## Rules of the exercise

- Never commit `.dev.vars`, tokens, keys or any secret. Use dummy values for practice.
- A token is a credential. Do not paste a real token into chat, the report or a screenshot.
- Never set `JWKS_URL` in a deployed Worker.
- Be ready to explain every line of your code in the review.
