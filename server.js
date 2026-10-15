import express from "express";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import fs from "node:fs";
import pg from "pg";

const env = process.env;
const PORT = parseInt(env.PORT || "8080", 10);
const RESOURCE_URL = env.RESOURCE_URL;                 // https://mcp-oauth.example.com/mcp
const ORIGIN = new URL(RESOURCE_URL).origin;
const MODE = env.MODE || "direct";
const ISSUER = env.ISSUER;                             // https://idp.example.com/application/o/your-app/
const USERINFO_URL = env.USERINFO_URL;                 // https://idp.example.com/application/o/userinfo/
const UPSTREAM = new URL(env.UPSTREAM);                // http://sparkyfitness-mcp:3001 (https:// works too)
const UPSTREAM_TLS = UPSTREAM.protocol === "https:";
const KEY_STORE = env.KEY_STORE || "/data/keys.json";
const KEY_NAME = env.KEY_NAME || "mcp";
const OAUTH_STORE = env.OAUTH_STORE || "/data/oauth.json";
const OAUTH_ISSUER = env.OAUTH_ISSUER || ORIGIN;
const UPSTREAM_AUTHORIZATION_ENDPOINT = env.UPSTREAM_AUTHORIZATION_ENDPOINT;
const UPSTREAM_TOKEN_ENDPOINT = env.UPSTREAM_TOKEN_ENDPOINT;
const UPSTREAM_CLIENT_ID = env.UPSTREAM_CLIENT_ID;
const UPSTREAM_CLIENT_SECRET = env.UPSTREAM_CLIENT_SECRET;
const OPENWEBUI_URL = env.OPENWEBUI_URL;               // optional: http://open-webui:8080 (accept Open WebUI session tokens)
const SPARKYFITNESS_URL = env.SPARKYFITNESS_URL;       // optional: shown to users without an account
const UPSTREAM_CALLBACK_URL = env.UPSTREAM_CALLBACK_URL || `${ORIGIN}/oauth/callback`;

if (!RESOURCE_URL || !ISSUER || !USERINFO_URL || !env.UPSTREAM) {
  throw new Error("RESOURCE_URL, ISSUER, USERINFO_URL and UPSTREAM are required");
}
if (MODE === "broker" && (!UPSTREAM_AUTHORIZATION_ENDPOINT || !UPSTREAM_TOKEN_ENDPOINT ||
  !UPSTREAM_CLIENT_ID || !UPSTREAM_CLIENT_SECRET)) {
  throw new Error("broker mode requires upstream OAuth endpoint and client settings");
}

const pool = new pg.Pool({
  host: env.PGHOST,
  port: parseInt(env.PGPORT || "5432", 10),
  user: env.PGUSER,
  password: env.PGPASSWORD,
  database: env.PGDATABASE,
  max: 4,
});

// Persistent map: email -> { key (plaintext), id (api_key uuid), userId }
let store = {};
try { store = JSON.parse(fs.readFileSync(KEY_STORE, "utf8")); } catch { /* first run */ }
let oauth = { clients: {}, transactions: {}, codes: {}, access: {}, refresh: {} };
if (MODE === "broker") {
  try { oauth = { ...oauth, ...JSON.parse(fs.readFileSync(OAUTH_STORE, "utf8")) }; }
  catch { /* first broker start */ }
}
function saveStore() {
  try { fs.writeFileSync(KEY_STORE, JSON.stringify(store), { mode: 0o600 }); }
  catch (e) { console.error("[shim] store write failed:", e.message); }
}
function saveOAuth() {
  try { fs.writeFileSync(OAUTH_STORE, JSON.stringify(oauth), { mode: 0o600 }); }
  catch (e) { console.error("[shim] oauth store write failed:", e.message); }
}

const CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
function genKey() {
  const b = crypto.randomBytes(64);
  let s = "";
  for (let i = 0; i < 64; i++) s += CHARSET[b[i] % CHARSET.length];
  return s;
}
// better-auth stores key as base64url(sha256(plaintext)) — verified against a real key.
const hashKey = (k) => crypto.createHash("sha256").update(k).digest("base64url");

async function provisionKey(email) {
  const e = email.toLowerCase();
  if (store[e]?.key) return store[e].key;
  const r = await pool.query('SELECT id FROM "user" WHERE lower(email)=$1 LIMIT 1', [e]);
  if (!r.rows.length) {
    const err = new Error("no_sparky_user");
    err.code = "NO_USER";
    throw err;
  }
  const userId = r.rows[0].id;
  const K = genKey();
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO api_key (id,name,key,reference_id,start,prefix,enabled,config_id,created_at,updated_at)
     VALUES ($1,$2,$3,$4,$5,'',true,'default',now(),now())`,
    [id, KEY_NAME, hashKey(K), userId, K.slice(0, 6)]
  );
  store[e] = { key: K, id, userId };
  saveStore();
  console.log(`[shim] provisioned api_key ${id} for ${e} -> user ${userId}`);
  return K;
}

// Validate the bearer token by calling the IdP's OIDC userinfo endpoint.
// Works whether the IdP issues opaque OR JWT access tokens, and returns the email/sub.
const tokenCache = new Map(); // token -> { email, exp(ms) }
async function resolveEmail(token) {
  const now = Date.now();
  const cached = tokenCache.get(token);
  if (cached && cached.exp > now) return cached.email;
  let r = await fetch(USERINFO_URL, { headers: { Authorization: `Bearer ${token}` } });
  // Not an IdP token: it may be an Open WebUI session token (tool auth "Session").
  // Open WebUI itself says whose token it is, so nothing here can be forged by the caller.
  const viaOpenWebui = !r.ok && Boolean(OPENWEBUI_URL);
  if (viaOpenWebui) {
    r = await fetch(`${OPENWEBUI_URL}/api/v1/auths/`, { headers: { Authorization: `Bearer ${token}` } });
  }
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    const err = new Error(`${viaOpenWebui ? "openwebui" : "userinfo"}_${r.status}`);
    err.code = "BAD_TOKEN";
    err.detail = body.slice(0, 140);
    throw err;
  }
  const claims = await r.json();
  const email = String(claims.email || claims.sub || "");
  if (!email.includes("@")) {
    const err = new Error("no_email_claim");
    err.code = "NO_EMAIL";
    err.detail = JSON.stringify(claims).slice(0, 140);
    throw err;
  }
  tokenCache.set(token, { email, exp: now + 300000 }); // cache 5 min
  return email;
}

const PRM = {
  resource: RESOURCE_URL,
  authorization_servers: [MODE === "broker" ? OAUTH_ISSUER : ISSUER],
  bearer_methods_supported: ["header"],
  scopes_supported: ["openid", "profile", "email"],
};

const app = express();
app.disable("x-powered-by");

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const opaque = () => crypto.randomBytes(32).toString("base64url");
const nowSeconds = () => Math.floor(Date.now() / 1000);
const formEncode = (values) => new URLSearchParams(values).toString();

function brokerMetadata() {
  return {
    issuer: OAUTH_ISSUER,
    authorization_endpoint: `${ORIGIN}/oauth/authorize`,
    token_endpoint: `${ORIGIN}/oauth/token`,
    registration_endpoint: `${ORIGIN}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "email"],
  };
}

function clientFor(id) {
  return oauth.clients[id];
}

function validRedirect(client, redirectUri) {
  return Boolean(client && Array.isArray(client.redirect_uris) &&
    client.redirect_uris.includes(redirectUri));
}

function pruneOAuth() {
  const cutoff = nowSeconds() - 600;
  for (const [id, value] of Object.entries(oauth.transactions)) if (value.expires_at < cutoff) delete oauth.transactions[id];
  for (const [id, value] of Object.entries(oauth.codes)) if (value.expires_at < nowSeconds()) delete oauth.codes[id];
  for (const [id, value] of Object.entries(oauth.access)) if (value.expires_at < nowSeconds()) delete oauth.access[id];
  for (const [id, value] of Object.entries(oauth.refresh)) if (value.expires_at < nowSeconds()) delete oauth.refresh[id];
}

async function exchangeUpstream(code, verifier) {
  const r = await fetch(UPSTREAM_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: formEncode({
      grant_type: "authorization_code",
      code,
      redirect_uri: UPSTREAM_CALLBACK_URL,
      client_id: UPSTREAM_CLIENT_ID,
      client_secret: UPSTREAM_CLIENT_SECRET,
      code_verifier: verifier,
    }),
  });
  if (!r.ok) throw new Error(`upstream_token_${r.status}`);
  return r.json();
}

async function upstreamEmail(accessToken) {
  const r = await fetch(USERINFO_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!r.ok) throw new Error(`upstream_userinfo_${r.status}`);
  const claims = await r.json();
  const email = String(claims.email || claims.sub || "");
  if (!email.includes("@")) throw new Error("upstream_userinfo_missing_email");
  return email.toLowerCase();
}

async function brokerEmail(token) {
  pruneOAuth();
  const entry = oauth.access[sha256(token)];
  if (!entry || entry.expires_at <= nowSeconds()) {
    const err = new Error("bridge_token_expired");
    err.code = "BAD_TOKEN";
    throw err;
  }
  if (entry.resource && entry.resource !== RESOURCE_URL) {
    const err = new Error("bridge_token_wrong_resource");
    err.code = "BAD_TOKEN";
    throw err;
  }
  return entry.email;
}

app.get("/health", (_q, s) => s.json({ status: "ok" }));

app.get(
  ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"],
  (_q, s) => s.json(PRM)
);

// Insurance: some clients fetch AS metadata from the resource origin — proxy to the IdP.
app.get(
  ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"],
  async (_q, s) => {
    if (MODE === "broker") return s.json(brokerMetadata());
    try {
      const r = await fetch(ISSUER + ".well-known/openid-configuration");
      s.status(r.status).type("application/json").send(await r.text());
    } catch {
      s.status(502).json({ error: "as_metadata_unavailable" });
    }
  }
);

if (MODE === "broker") {
  app.use(express.urlencoded({ extended: false }));
  // Dynamic client registration is unauthenticated (RFC 7591, ChatGPT needs it) and every
  // client is persisted in OAUTH_STORE, so it is bounded: MAX_CLIENTS in total, small bodies,
  // few short https redirect URIs. Errors use the RFC 7591 section 3.2.2 shape. Existing clients are never re-validated or dropped.
  const MAX_CLIENTS = parseInt(env.MAX_CLIENTS || "200", 10);
  const MAX_REDIRECT_URIS = 5;
  const MAX_URI_LENGTH = 512;
  const MAX_NAME_LENGTH = 100;
  const dcrError = (res, status, error, description) =>
    res.status(status).set("Cache-Control", "no-store").json({ error, error_description: description });
  const validRedirectUri = (uri) => {
    if (typeof uri !== "string" || uri.length > MAX_URI_LENGTH) return false;
    try {
      const u = new URL(uri);
      if (u.hash) return false;
      return u.protocol === "https:" ||
        (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
    } catch { return false; }
  };
  const dcrJson = express.json({ limit: "4kb" });
  app.post("/oauth/register", (req, res, next) => dcrJson(req, res, (err) => {
    if (err) {
      const tooLarge = err.type === "entity.too.large";
      return dcrError(res, 400, "invalid_client_metadata",
        tooLarge ? "registration request too large" : "malformed JSON");
    }
    next();
  }), (req, res) => {
    if (Object.keys(oauth.clients).length >= MAX_CLIENTS) {
      console.error(`[shim] DCR refused: client limit ${MAX_CLIENTS} reached`);
      return dcrError(res, 429, "invalid_client_metadata", "client registration limit reached");
    }
    const redirectUris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris : [];
    if (!redirectUris.length || redirectUris.length > MAX_REDIRECT_URIS ||
        !redirectUris.every(validRedirectUri)) {
      return dcrError(res, 400, "invalid_redirect_uri",
        `1-${MAX_REDIRECT_URIS} absolute https redirect_uris of at most ${MAX_URI_LENGTH} characters`);
    }
    const clientName = req.body.client_name ?? "ChatGPT";
    if (typeof clientName !== "string" || clientName.length > MAX_NAME_LENGTH) {
      return dcrError(res, 400, "invalid_client_metadata",
        `client_name must be a string of at most ${MAX_NAME_LENGTH} characters`);
    }
    const clientId = `chatgpt-${opaque()}`;
    oauth.clients[clientId] = {
      client_name: clientName || "ChatGPT",
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
    };
    saveOAuth();
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: nowSeconds(),
      client_name: oauth.clients[clientId].client_name,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  app.get("/oauth/authorize", (req, res) => {
    const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, resource } = req.query;
    const client = clientFor(client_id);
    if (response_type !== "code" || !validRedirect(client, redirect_uri) ||
        code_challenge_method !== "S256" || !code_challenge) {
      return res.status(400).send("invalid authorization request");
    }
    const transactionId = opaque();
    const upstreamVerifier = opaque();
    oauth.transactions[transactionId] = {
      client_id,
      redirect_uri,
      state,
      resource: resource || RESOURCE_URL,
      code_challenge,
      scope: scope || "openid profile email",
      upstream_verifier: upstreamVerifier,
      expires_at: nowSeconds() + 600,
    };
    saveOAuth();
    const upstream = new URL(UPSTREAM_AUTHORIZATION_ENDPOINT);
    upstream.search = new URLSearchParams({
      client_id: UPSTREAM_CLIENT_ID,
      redirect_uri: UPSTREAM_CALLBACK_URL,
      response_type: "code",
      scope: "openid profile email",
      state: transactionId,
      code_challenge: sha256(upstreamVerifier),
      code_challenge_method: "S256",
    }).toString();
    res.redirect(upstream.toString());
  });

  app.get("/oauth/callback", async (req, res) => {
    const transaction = oauth.transactions[req.query.state];
    if (!transaction || transaction.expires_at <= nowSeconds()) return res.status(400).send("expired OAuth transaction");
    delete oauth.transactions[req.query.state];
    if (req.query.error) return res.status(400).send(`upstream authorization failed: ${req.query.error}`);
    try {
      const tokens = await exchangeUpstream(req.query.code, transaction.upstream_verifier);
      const email = await upstreamEmail(tokens.access_token);
      const code = opaque();
      oauth.codes[sha256(code)] = {
        client_id: transaction.client_id,
        redirect_uri: transaction.redirect_uri,
        email,
        resource: transaction.resource,
        scope: transaction.scope,
        code_challenge: transaction.code_challenge,
        expires_at: nowSeconds() + 300,
      };
      saveOAuth();
      const redirect = new URL(transaction.redirect_uri);
      redirect.searchParams.set("code", code);
      if (transaction.state) redirect.searchParams.set("state", transaction.state);
      res.redirect(redirect.toString());
    } catch (e) {
      console.error(`[oauth] upstream exchange failed: ${e.message}`);
      res.status(502).send("upstream OAuth exchange failed");
    }
  });

  app.post("/oauth/token", async (req, res) => {
    pruneOAuth();
    if (req.body.grant_type === "authorization_code") {
      const entry = oauth.codes[sha256(req.body.code || "")];
      const client = clientFor(req.body.client_id);
      if (!entry || entry.expires_at <= nowSeconds() || !client ||
          entry.client_id !== req.body.client_id || entry.redirect_uri !== req.body.redirect_uri ||
          !validRedirect(client, req.body.redirect_uri) ||
          sha256(req.body.code_verifier || "") !== entry.code_challenge) {
        return res.status(400).json({ error: "invalid_grant" });
      }
      delete oauth.codes[sha256(req.body.code)];
      const access = opaque();
      const refresh = opaque();
      oauth.access[sha256(access)] = { email: entry.email, resource: entry.resource, expires_at: nowSeconds() + 3600 };
      oauth.refresh[sha256(refresh)] = { email: entry.email, resource: entry.resource, expires_at: nowSeconds() + 30 * 86400 };
      saveOAuth();
      return res.json({ access_token: access, token_type: "Bearer", expires_in: 3600, refresh_token: refresh, scope: entry.scope });
    }
    if (req.body.grant_type === "refresh_token") {
      const entry = oauth.refresh[sha256(req.body.refresh_token || "")];
      if (!entry || entry.expires_at <= nowSeconds()) return res.status(400).json({ error: "invalid_grant" });
      const access = opaque();
      oauth.access[sha256(access)] = { email: entry.email, resource: entry.resource, expires_at: nowSeconds() + 3600 };
      saveOAuth();
      return res.json({ access_token: access, token_type: "Bearer", expires_in: 3600, refresh_token: req.body.refresh_token, scope: "openid profile email" });
    }
    return res.status(400).json({ error: "unsupported_grant_type" });
  });
}

const challenge = () =>
  `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"`;

async function authenticate(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    console.log(`[mcp] 401 no-bearer ${req.method} ${req.originalUrl}`);
    res.set("WWW-Authenticate", challenge());
    return res.status(401).json({ error: "unauthorized" });
  }
  try {
    const email = MODE === "broker" ? await brokerEmail(h.slice(7)) : await resolveEmail(h.slice(7));
    req.sparkyKey = await provisionKey(email);
    console.log(`[mcp] ok ${req.method} email=${email}`);
    next();
  } catch (e) {
    if (e.code === "NO_USER") {
      console.log(`[mcp] 403 no-sparky-account`);
      return res.status(403).json({
        error: "no_sparkyfitness_account",
        detail: `Log in to SparkyFitness${SPARKYFITNESS_URL ? ` at ${SPARKYFITNESS_URL}` : ""} once with this account first.`,
      });
    }
    console.log(`[mcp] 401 ${e.code || "err"}: ${e.message} ${e.detail || ""}`);
    res.set("WWW-Authenticate", challenge());
    return res.status(401).json({ error: "invalid_token", detail: String(e.message || e) });
  }
}

// Reverse-proxy /mcp to the upstream MCP server, injecting the per-user x-api-key.
app.use("/mcp", authenticate, (req, res) => {
  const headers = { ...req.headers, host: UPSTREAM.host, "x-api-key": req.sparkyKey };
  delete headers.authorization;
  const opts = {
    hostname: UPSTREAM.hostname,
    port: UPSTREAM.port || (UPSTREAM_TLS ? 443 : 80),
    path: UPSTREAM.pathname.replace(/\/$/, "") + req.originalUrl, // keep a path prefix in UPSTREAM
    method: req.method,
    headers,
  };
  const up = (UPSTREAM_TLS ? https : http).request(opts, (ur) => {
    res.writeHead(ur.statusCode || 502, ur.headers);
    ur.pipe(res);
  });
  up.on("error", (e) => {
    if (!res.headersSent) res.status(502).json({ error: "upstream_error", detail: String(e.message || e) });
  });
  req.pipe(up);
});

app.listen(PORT, () =>
  console.log(`[shim] listening on ${PORT}; resource=${RESOURCE_URL} issuer=${ISSUER} userinfo=${USERINFO_URL} upstream=${UPSTREAM.href}`)
);
