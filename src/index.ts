import { AUTH_ERRORS, getBearerToken, verifyFirebaseIdToken, type KeyProvider } from './auth';
import { jwksProvider } from './keys';

export interface Env {
  FIREBASE_PROJECT_ID: string; // public configuration (wrangler.jsonc, vars)
  ALLOWED_ORIGIN?: string; // public configuration: the one web page allowed to call this Worker
  API_SECRET?: string; // a SECRET: set with `wrangler secret put` or in .dev.vars
  JWKS_URL?: string; // LOCAL DEVELOPMENT ONLY. Never set this in a deployed Worker.
}

const DEFAULT_ORIGIN = 'http://localhost:5173';

// Complete. Headers that let the allowed web page call this Worker from a browser.
export function corsHeaders(env: Env): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || DEFAULT_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    Vary: 'Origin',
  };
}

// Complete. Builds a JSON response that always includes the CORS headers.
export function json(body: unknown, status: number, env: Env, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env), ...extra },
  });
}

/**
 * Build the request handler. The key provider is a parameter so that the tests
 * can supply their own keys without any network access.
 *
 * Routes (see docs/SPEC.md for the exact answers):
 *   OPTIONS anything   -> 204, CORS headers, no body
 *   GET /health        -> public
 *   GET /me            -> needs a valid Firebase ID token
 *   GET /secret-status -> needs a valid Firebase ID token
 *   anything else      -> 404
 */
export function createHandler(getKeys: KeyProvider) {
  return async function handle(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
      });
    }

    const path = new URL(request.url).pathname;

    if (path === '/health') {
      if (request.method !== 'GET') {
        return json({ error: 'method-not-allowed' }, 405, env, { Allow: 'GET' });
      }
      return json({ ok: true }, 200, env);
    }

    if (path === '/me' || path === '/secret-status') {
      if (request.method !== 'GET') {
        return json({ error: 'method-not-allowed' }, 405, env);
      }

      const token = getBearerToken(request.headers.get('Authorization'));
      if (!token) {
        return json({ error: 'unauthorized' }, 401, env);
      }

      let verified: Awaited<ReturnType<typeof verifyFirebaseIdToken>>;
      try {
        verified = await verifyFirebaseIdToken(token, env.FIREBASE_PROJECT_ID, getKeys);
      } catch (error) {
        if (error instanceof Error && AUTH_ERRORS.has(error.message)) {
          return json({ error: 'unauthorized' }, 401, env);
        }
        console.error(error);
        return json({ error: 'auth-unavailable' }, 503, env);
      }

      if (path === '/me') {
        return json({
          uid: verified.uid,
          email: typeof verified.payload.email === 'string' ? verified.payload.email : null,
        }, 200, env);
      }

      return json({ configured: typeof env.API_SECRET === 'string' && env.API_SECRET.length > 0 }, 200, env);
    }

    return json({ error: 'not-found' }, 404, env);
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return createHandler(jwksProvider(env.JWKS_URL))(request, env);
  },
};
