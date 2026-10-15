# SparkyFitness MCP ↔ OAuth bridge

A tiny reverse proxy that lets you use [SparkyFitness](https://github.com/CodeWithCJ/SparkyFitness)'s
MCP server from **Claude custom connectors** (web, desktop, **and mobile**), **ChatGPT
connectors**, and **Open WebUI**.

SparkyFitness's MCP server authenticates with a static `x-api-key` header. Claude's
custom connectors only speak **OAuth** — there's no field for a static key. This bridge
sits in front of the MCP server, runs the OAuth handshake against **your own identity
provider**, and transparently injects a **per-user** SparkyFitness API key upstream.

```
Claude (web / desktop / mobile)
      │  OAuth 2.1 + PKCE
      ▼
  Your OIDC provider  (Authentik, Keycloak, Auth0, Zitadel, Google, …)
      │  access token (Bearer)
      ▼
  this bridge
   • serves RFC 9728 protected-resource metadata
   • validates the token via the provider's OIDC userinfo endpoint
   • maps the user's email → SparkyFitness user
   • auto-provisions that user's own api_key on first use
   • injects  x-api-key  ─────►  SparkyFitness MCP server
```

Each user logs in with their own account and only ever sees their own data.

## Two modes

The same `server.js` runs in one of two modes (`MODE`); run one container per mode.

| Mode | For | How it authenticates |
|------|-----|----------------------|
| `direct` (default) | Claude connectors, Open WebUI | The client logs in at **your IdP** directly (you paste the IdP's client_id/secret into Claude). The bridge validates the IdP token via userinfo. |
| `broker` | ChatGPT and other clients that need **Dynamic Client Registration** | The bridge is its own small OAuth server towards the client (DCR, public clients, PKCE S256) and brokers the actual login to your IdP with **one** confidential client. Clients get bridge-issued tokens (1 h access, 30 d refresh). |

Most IdPs (Authentik included) don't offer open Dynamic Client Registration, which ChatGPT
requires — that's what broker mode is for.

## Requirements

- A running **SparkyFitness** instance, and network access to its **MCP server** and **Postgres**.
- **Any OIDC identity provider** with a `userinfo` endpoint (Authentik, Keycloak, Auth0,
  Zitadel, Google, Okta, …). *Not* Authentik-specific.
- A Claude plan that supports custom connectors, and/or ChatGPT with connectors (developer
  mode), and/or Open WebUI.

## How it works (direct mode)

1. Claude calls `/mcp` unauthenticated → gets `401` + a `WWW-Authenticate` header
   pointing at `/.well-known/oauth-protected-resource` (RFC 9728), which names your IdP.
2. Claude runs OAuth 2.1 + PKCE against your IdP; the user logs in and consents.
3. Claude calls `/mcp` with the access token. The bridge validates it by calling the
   IdP's **userinfo** endpoint (works for both opaque and JWT access tokens) and reads
   the `email` claim.
4. The bridge maps `email → SparkyFitness user`, **auto-provisions** a SparkyFitness
   API key for that user the first time (cached afterwards), injects it as `x-api-key`,
   and proxies the request to the SparkyFitness MCP server.

### Broker mode

1. The client discovers `/.well-known/oauth-authorization-server` on the bridge itself and
   registers via `POST /oauth/register` (RFC 7591).
2. `GET /oauth/authorize` stores the client's PKCE challenge and redirects to your IdP with
   the bridge's own client and its own PKCE pair.
3. Your IdP redirects back to `/oauth/callback`; the bridge exchanges the code, reads the
   email from userinfo, and hands the client a one-time code.
4. `POST /oauth/token` checks the client's PKCE verifier and issues bridge tokens
   (stored hashed in `OAUTH_STORE`). `/mcp` then works as in direct mode.

Registration is unauthenticated, so it's bounded: at most `MAX_CLIENTS` (default 200)
clients, 4 KB bodies, 1–5 https (or localhost) redirect URIs of ≤ 512 chars.

### Open WebUI (optional, direct mode)

Set `OPENWEBUI_URL` (reachable from the bridge) and add the bridge in Open WebUI as an
**MCP Streamable HTTP** tool with Auth **Session**. Open WebUI then sends the user's own
session token; when your IdP rejects it, the bridge asks Open WebUI
(`GET /api/v1/auths/`) whose token it is and maps that email as usual. The caller can't
forge this — Open WebUI itself answers. (Auth "OAuth" in Open WebUI forwards the short-lived
IdP login token without a refresh token, so it stops working after a few minutes.)

## ⚠️ Caveats / sharp edges (read before deploying)

This bridge couples to **SparkyFitness internals** to mint keys. That's the price of
per-user auto-provisioning without manual key handling:

- **Direct DB writes.** It writes rows into SparkyFitness's `api_key` table, reproducing
  better-auth's key storage (`base64url(sha256(plaintext))`, unsalted). If SparkyFitness
  changes its key hashing/schema, provisioning will break until updated.
- **Needs an RLS-bypassing DB role.** `api_key` has a row-level-security policy keyed on
  the `app.user_id` session variable. Use the database **owner/superuser** role
  (`PGUSER=sparky`), *not* the app role, or you'll get
  `42704 unrecognized configuration parameter "app.user_id"`.
- **Opaque tokens.** Some IdPs (e.g. Authentik) issue opaque access tokens, so JWT/JWKS
  validation won't work — that's why the bridge uses the `userinfo` endpoint instead.
- **Broker state.** In broker mode, `OAUTH_STORE` (`/data/oauth.json`) holds registered
  clients and hashed tokens. Same protection as the key cache.
- **Plaintext key cache.** Provisioned keys are cached as plaintext in
  `KEY_STORE` (`/data/keys.json`). Keep that volume protected; it grants full access to
  those users' SparkyFitness data.
- **Account gating.** Only users who already have a SparkyFitness account (matched by
  email) are allowed; others get `403 no_sparkyfitness_account`.

## Setup (direct mode — Claude, Open WebUI)

1. **Create an OAuth/OIDC application** in your IdP:
   - Confidential client, scopes `openid profile email`.
   - Redirect URIs: `https://claude.ai/api/mcp/auth_callback` and
     `https://claude.com/api/mcp/auth_callback`.
   - If your IdP exposes the email as a claim or sets `sub` to the email, you're set.
2. `cp shim.env.example shim.env` and fill it in (IdP issuer + userinfo, SparkyFitness
   DB/superuser creds, upstream MCP URL, your public host).
3. Put it behind a reverse proxy with TLS (Traefik labels included as an example),
   reachable at `RESOURCE_URL`.
4. `docker compose up -d --build`
5. In **claude.ai → Settings → Connectors → Add custom connector**, enter
   `https://<your-host>/mcp`, and under **Advanced** paste your IdP's
   **client_id / client_secret** (most IdPs don't support Dynamic Client Registration,
   so this is required). Connect → log in → it syncs to mobile.

## Setup (broker mode — ChatGPT)

1. In your IdP, use a confidential client (can be the same app as above) and add the
   redirect URI `https://<broker-host>/oauth/callback`.
2. `cp broker.env.example broker.env` and fill it in.
3. Expose it at its own host behind TLS, then `docker compose --profile broker up -d --build`.
4. In ChatGPT, add a connector with URL `https://<broker-host>/mcp` and OAuth
   authentication; ChatGPT registers itself and sends the user through your IdP login.

## Configuration

| Variable | Mode | Meaning |
|----------|------|---------|
| `RESOURCE_URL` | both | Public URL of this bridge's `/mcp` |
| `ISSUER`, `USERINFO_URL` | both | Your IdP's issuer and OIDC userinfo endpoint |
| `UPSTREAM` | both | SparkyFitness MCP server URL |
| `PGHOST` … `PGDATABASE` | both | SparkyFitness Postgres, owner/superuser role |
| `KEY_STORE` | both | Plaintext key cache (default `/data/keys.json`) |
| `KEY_NAME` | both | Name of the created `api_key` rows (default `mcp`) |
| `SPARKYFITNESS_URL` | both | Optional, shown to users without a SparkyFitness account |
| `OPENWEBUI_URL` | direct | Optional, accept Open WebUI session tokens |
| `MODE` | — | `direct` (default) or `broker` |
| `OAUTH_ISSUER` | broker | Issuer the bridge advertises (default: its origin) |
| `UPSTREAM_AUTHORIZATION_ENDPOINT`, `UPSTREAM_TOKEN_ENDPOINT` | broker | Your IdP's endpoints |
| `UPSTREAM_CLIENT_ID`, `UPSTREAM_CLIENT_SECRET` | broker | The bridge's confidential client at your IdP |
| `UPSTREAM_CALLBACK_URL` | broker | Default `<origin>/oauth/callback` |
| `OAUTH_STORE` | broker | Clients + hashed tokens (default `/data/oauth.json`) |
| `MAX_CLIENTS` | broker | Max. registered clients (default 200) |

## Endpoints

| Path | Purpose |
|------|---------|
| `POST /mcp` | Authenticated MCP proxy (the connector URL) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `GET /.well-known/oauth-authorization-server` | Direct: proxied from your IdP (insurance). Broker: the bridge's own metadata |
| `POST /oauth/register` | Broker: Dynamic Client Registration |
| `GET /oauth/authorize`, `GET /oauth/callback`, `POST /oauth/token` | Broker: OAuth flow |
| `GET /health` | Liveness |

## Security notes

- The SparkyFitness key never leaves the server; access requires a real IdP login
  (MFA-capable, revocable per user at your IdP).
- Treat the `data/` / `data-broker/` volumes and `shim.env` / `broker.env` as secrets.

## License

MIT — see [LICENSE](LICENSE). Not affiliated with the SparkyFitness project.
