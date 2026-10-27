// Netlify Function: Pinterest OAuth callback (Node, no dependencies).
//
// Deployed path: this file lives at netlify/functions/oauth-callback.js
// and is reached at /oauth/callback via the redirect in callback/netlify.toml
// (Netlify Functions are otherwise served under /.netlify/functions/).
//
// Behaviour mirrors callback/handler.py exactly, in this order:
//   1. Config check FIRST (fail closed before spending the single-use code).
//   2. Pinterest error -> generic failure, no token call.
//   3. Require code + state; verify HMAC-signed state (same format as
//      callback/state.py) and recover the opaque account label.
//   4. Exchange the code (POST https://api.pinterest.com/v5/oauth/token,
//      HTTP Basic client_id:client_secret, form-encoded body).
//   5. Deliver the token pair to the publisher host's ingestion endpoint,
//      which must store it via tokens.py (0600 file). The ingestion
//      endpoint is NOT part of this skeleton: if TOKEN_INGEST_URL is not
//      set, this function refuses BEFORE exchanging, so no code is wasted
//      and no token pair is ever created that has nowhere to go.
//
// Safety: tokens, codes, secrets and state values are never logged or
// echoed. Responses are generic HTML. The Standard-access gate and the
// approval queue are untouched: connecting an account approves no pin.
//
// Environment variables (placeholders only — set in the Netlify dashboard,
// never in code): PINTEREST_APP_ID, PINTEREST_APP_SECRET,
// PINTEREST_REDIRECT_URI (must match the URI registered in the Pinterest
// app character-for-character), STATE_SECRET, TOKEN_INGEST_URL,
// TOKEN_INGEST_SECRET, CONTINUOUS_REFRESH ("true" only for apps created
// before 25 Sep 2025), API_BASE_URL (default https://api.pinterest.com/v5).

const crypto = require("crypto");

const API_BASE_URL = process.env.API_BASE_URL || "https://api.pinterest.com/v5";

function b64urlDecode(text) {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"),
    "base64").toString("utf8");
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function verifyState(state, secret) {
  if (!state || !secret) throw new Error("missing state");
  const parts = state.split(".");
  if (parts.length !== 4) throw new Error("malformed state");
  const [labelPart, noncePart, expiryPart, digest] = parts;
  const payload = `${labelPart}.${noncePart}.${expiryPart}`;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(digest))) {
    throw new Error("state signature mismatch");
  }
  const expiry = Number(expiryPart);
  if (!Number.isInteger(expiry) || expiry * 1000 <= Date.now()) {
    throw new Error("state expired");
  }
  const label = b64urlDecode(labelPart);
  if (!label) throw new Error("malformed state");
  // Nonce must decode; its value is never used beyond this check.
  b64urlDecode(noncePart);
  return label;
}

function page(title, body) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return { statusCode: 200, headers: { "Content-Type": "text/html; charset=utf-8" },
    body: `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title></head><body><h1>${esc(title)}</h1><p>${esc(body)}</p></body></html>` };
}

function fail(statusCode, body) {
  const r = page("Authorization failed", body);
  r.statusCode = statusCode;
  return r;
}

exports.handler = async (event) => {
  // 1. Config check FIRST — never spend a single-use code on a broken setup.
  const appId = process.env.PINTEREST_APP_ID;
  const appSecret = process.env.PINTEREST_APP_SECRET;
  const redirectUri = process.env.PINTEREST_REDIRECT_URI;
  const stateSecret = process.env.STATE_SECRET;
  const ingestUrl = process.env.TOKEN_INGEST_URL;
  const ingestSecret = process.env.TOKEN_INGEST_SECRET;
  if (!appId || !appSecret || !redirectUri || !stateSecret || !ingestUrl || !ingestSecret) {
    return fail(500, "The callback is not configured yet. No account was connected.");
  }

  const params = event.queryStringParameters || {};

  // 2. Pinterest-side error.
  if (params.error) {
    if (params.error === "access_denied") {
      return fail(400, "Access was denied on Pinterest's consent screen. No account was connected. You can close this window and try again.");
    }
    return fail(400, "Pinterest did not complete authorization. No account was connected. You can close this window and try again.");
  }

  // 3. Required parameters + state verification (one generic message).
  if (!params.code || !params.state) {
    return fail(400, "This link is incomplete: the authorization code or state is missing. Please start the authorization again from the beginning.");
  }
  let label;
  try {
    label = verifyState(params.state, stateSecret);
  } catch (e) {
    return fail(403, "This authorization link could not be verified or has expired. No account was connected. Please start the authorization again.");
  }

  // 4. Code exchange.
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: redirectUri,
  });
  if (process.env.CONTINUOUS_REFRESH === "true") body.set("continuous_refresh", "true");
  let tokenResp;
  try {
    const res = await fetch(`${API_BASE_URL}/oauth/token`, {
      method: "POST",
      headers: {
        Authorization: "Basic " + Buffer.from(`${appId}:${appSecret}`).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });
    if (!res.ok) throw new Error("token exchange failed");
    tokenResp = await res.json();
  } catch (e) {
    return fail(502, "The token exchange failed. The code may have expired or already been used. No account was connected. Please start the authorization again.");
  }
  if (!tokenResp.access_token || !tokenResp.refresh_token) {
    return fail(502, "Pinterest returned an incomplete token response. No account was connected. Please try again.");
  }

  // 5. Deliver to the publisher host for storage via tokens.py. The token
  // pair is sent only to this one configured endpoint, over HTTPS, and
  // is never logged or shown. If delivery fails, the pair is discarded
  // (never stored anywhere) and a fresh OAuth run is required.
  try {
    const res = await fetch(ingestUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ingestSecret}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ label, token_response: tokenResp }),
    });
    if (!res.ok) throw new Error("ingest failed");
  } catch (e) {
    return fail(502, "The token pair could not be stored. No account was connected. Please try again.");
  }

  return page("Account connected",
    `Account '${label}' is connected. You can close this window. Publishing stays off until Standard access is confirmed and a public test pin has been verified for this account.`);
};
