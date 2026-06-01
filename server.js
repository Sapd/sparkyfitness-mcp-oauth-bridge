import express from "express";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import pg from "pg";

const env = process.env;
const PORT = parseInt(env.PORT || "8080", 10);
const RESOURCE_URL = env.RESOURCE_URL;                 // https://mcp-fitness-oauth.warp10.cc/mcp
const ORIGIN = new URL(RESOURCE_URL).origin;
const ISSUER = env.ISSUER;                             // https://auth.warp10.cc/application/o/claude-mcp/
const USERINFO_URL = env.USERINFO_URL;                 // https://auth.warp10.cc/application/o/userinfo/
const UPSTREAM = new URL(env.UPSTREAM);                // http://sparkyfitness-mcp:3001
const KEY_STORE = env.KEY_STORE || "/data/keys.json";

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
function saveStore() {
  try { fs.writeFileSync(KEY_STORE, JSON.stringify(store), { mode: 0o600 }); }
  catch (e) { console.error("[shim] store write failed:", e.message); }
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
    [id, "claude-mcp", hashKey(K), userId, K.slice(0, 6)]
  );
  store[e] = { key: K, id, userId };
  saveStore();
  console.log(`[shim] provisioned api_key ${id} for ${e} -> user ${userId}`);
  return K;
}

// Validate the bearer token by calling Authentik's userinfo endpoint.
// Works whether Authentik issues opaque OR JWT access tokens, and returns the email/sub.
const tokenCache = new Map(); // token -> { email, exp(ms) }
async function resolveEmail(token) {
  const now = Date.now();
  const cached = tokenCache.get(token);
  if (cached && cached.exp > now) return cached.email;
  const r = await fetch(USERINFO_URL, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    const err = new Error(`userinfo_${r.status}`);
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
  authorization_servers: [ISSUER],
  bearer_methods_supported: ["header"],
  scopes_supported: ["openid", "profile", "email"],
};

const app = express();
app.disable("x-powered-by");

app.get("/health", (_q, s) => s.json({ status: "ok" }));

app.get(
  ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"],
  (_q, s) => s.json(PRM)
);

// Insurance: some clients fetch AS metadata from the resource origin — proxy to Authentik.
app.get(
  ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"],
  async (_q, s) => {
    try {
      const r = await fetch(ISSUER + ".well-known/openid-configuration");
      s.status(r.status).type("application/json").send(await r.text());
    } catch {
      s.status(502).json({ error: "as_metadata_unavailable" });
    }
  }
);

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
    const email = await resolveEmail(h.slice(7));
    req.sparkyKey = await provisionKey(email);
    console.log(`[mcp] ok ${req.method} email=${email}`);
    next();
  } catch (e) {
    if (e.code === "NO_USER") {
      console.log(`[mcp] 403 no-sparky-account`);
      return res.status(403).json({
        error: "no_sparkyfitness_account",
        detail: "Log in at https://fitness.warp10.cc once with this account first.",
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
    port: UPSTREAM.port || 80,
    path: req.originalUrl,
    method: req.method,
    headers,
  };
  const up = http.request(opts, (ur) => {
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
