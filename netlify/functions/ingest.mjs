// Netlify Function: BoardBridge token-ingest receiver.
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

import { getStore } from '@netlify/blobs';

const LABEL_RE = /^[A-Za-z0-9_-]{1,64}$/;

function authed(event) {
  const secret = process.env.TOKEN_INGEST_SECRET;
  if (!secret) return false;
  const headers = event.headers || {};
  const h = headers.authorization || headers.Authorization || '';
  return h === `Bearer ${secret}`;
}

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  };
}

export async function handler(event) {
  if (!authed(event)) {
    return json(401, { error: 'unauthorized' });
  }
  const store = getStore('boardbridge-tokens');
  if (event.httpMethod === 'POST') {
    let data;
    try {
      data = JSON.parse(event.body || '{}');
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
  if (event.httpMethod === 'GET') {
    const params = event.queryStringParameters || {};
    const label = params.label;
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
}
