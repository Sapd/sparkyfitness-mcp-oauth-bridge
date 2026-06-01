# SparkyFitness MCP ↔ OAuth bridge

A tiny reverse proxy that lets you use [SparkyFitness](https://github.com/CodeWithCJ/SparkyFitness)'s
MCP server from **Claude custom connectors** (web, desktop, **and mobile**).

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

## Requirements

- A running **SparkyFitness** instance, and network access to its **MCP server** and **Postgres**.
- **Any OIDC identity provider** with a `userinfo` endpoint (Authentik, Keycloak, Auth0,
  Zitadel, Google, Okta, …). *Not* Authentik-specific.
- A Claude plan that supports custom connectors.

## How it works

1. Claude calls `/mcp` unauthenticated → gets `401` + a `WWW-Authenticate` header
   pointing at `/.well-known/oauth-protected-resource` (RFC 9728), which names your IdP.
2. Claude runs OAuth 2.1 + PKCE against your IdP; the user logs in and consents.
3. Claude calls `/mcp` with the access token. The bridge validates it by calling the
   IdP's **userinfo** endpoint (works for both opaque and JWT access tokens) and reads
   the `email` claim.
4. The bridge maps `email → SparkyFitness user`, **auto-provisions** a SparkyFitness
   API key for that user the first time (cached afterwards), injects it as `x-api-key`,
   and proxies the request to the SparkyFitness MCP server.

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
- **Plaintext key cache.** Provisioned keys are cached as plaintext in
  `KEY_STORE` (`/data/keys.json`). Keep that volume protected; it grants full access to
  those users' SparkyFitness data.
- **Account gating.** Only users who already have a SparkyFitness account (matched by
  email) are allowed; others get `403 no_sparkyfitness_account`.

## Setup

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

## Endpoints

| Path | Purpose |
|------|---------|
| `POST /mcp` | Authenticated MCP proxy (the connector URL) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `GET /.well-known/oauth-authorization-server` | Proxied from your IdP (insurance) |
| `GET /health` | Liveness |

## Security notes

- The SparkyFitness key never leaves the server; access requires a real IdP login
  (MFA-capable, revocable per user at your IdP).
- Treat the `data/` volume and `shim.env` as secrets.

## License

MIT — see [LICENSE](LICENSE). Not affiliated with the SparkyFitness project.
