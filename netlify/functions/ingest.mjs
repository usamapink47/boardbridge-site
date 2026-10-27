// Netlify Function (v2 format): BoardBridge token-ingest receiver.
//
// The OAuth callback function (oauth-callback.js) exchanges the
// authorisation code and POSTs the resulting token pair here, because a
// serverless function cannot write to the publisher host's token file.
// This function stores each pair in the site's Netlify Blobs store,
// keyed by the opaque account label. The local publisher later fetches
// pairs back over GET with the same bearer secret and writes them to
// its own tokens.json (0600 file) via tokens.py.
//
// Security: every request must carry Authorization: Bearer
// TOKEN_INGEST_SECRET (set in the Netlify dashboard, never in code).
// Tokens, codes and secrets are never logged or echoed. Responses are
// generic JSON. Nothing here approves a pin or flips the Standard gate.
//
// NOTE: this file uses the v2 function format (default export taking a
// Request) instead of the v1 handler form, because on this site the v1
// form threw MissingBlobsEnvironmentError: the Blobs environment was
// not injected for v1 handlers, so getStore() failed before handling
// the request. If the v2 form still fails, the documented fallback is
// explicit siteID + token from environment variables (a Netlify
// personal access token) — that needs the account holder's approval
// first, because it creates an account-level credential.

import { getStore } from '@netlify/blobs';

const LABEL_RE = /^[A-Za-z0-9_-]{1,64}$/;

function json(statusCode, obj) {
  return new Response(JSON.stringify(obj), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}

export default async (req) => {
  const secret = process.env.TOKEN_INGEST_SECRET;
  const auth = req.headers.get('authorization') || '';
  if (!secret || auth !== `Bearer ${secret}`) {
    return json(401, { error: 'unauthorized' });
  }
  const store = getStore({ name: 'boardbridge-tokens' });
  if (req.method === 'POST') {
    let data;
    try {
      data = await req.json();
    } catch {
      return json(400, { error: 'bad payload' });
    }
    const label = data && data.label;
    const tokenResponse = data && data.token_response;
    if (!label || !LABEL_RE.test(label)) {
      return json(400, { error: 'bad payload' });
    }
    if (!tokenResponse || !tokenResponse.access_token || !tokenResponse.refresh_token) {
      return json(400, { error: 'bad payload' });
    }
    await store.setJSON(label, {
      token_response: tokenResponse,
      stored_at: new Date().toISOString(),
    });
    return json(200, { ok: true });
  }
  if (req.method === 'GET') {
    const url = new URL(req.url);
    const label = url.searchParams.get('label');
    if (!label || !LABEL_RE.test(label)) {
      return json(400, { error: 'bad payload' });
    }
    const entry = await store.get(label, { type: 'json' });
    if (!entry) {
      return json(404, { error: 'not found' });
    }
    return json(200, entry);
  }
  return json(405, { error: 'method not allowed' });
};
