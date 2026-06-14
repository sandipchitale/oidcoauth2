# oidcoauth2 — an OAuth 2.1 / OpenID Connect playground

A single Spring Boot application that plays **all three OAuth/OIDC roles at once** —
Authorization Server, Resource Server, and a stateless browser Client — so you can
see a complete, modern authorization flow end-to-end and poke at every moving part.

It is built to *teach the hard, fuzzy bits* that the specs leave underspecified:
the difference between **authentication and authorization**, between **scope** and
**audience**, how **RFC 8707 resource indicators** drive the `aud` claim, what
**audience validation** actually protects, and how **least‑privilege / step‑up
(incremental) authorization** works.

> ⚠️ **Educational demo, not production.** It uses in‑memory users/clients, a
> locally generated CA, `{noop}` passwords, and verbose logging. Don't ship it.

---

## What it demonstrates

- **OAuth 2.1 Authorization Code + PKCE** for a **public client** (no secret).
- **OpenID Connect**: ID token, `/userinfo`, standard scopes (`openid`, `profile`, `email`, …).
- **Three discovery documents** and the **MCP discovery order**:
  - RFC 9728 Protected Resource Metadata — `/.well-known/oauth-protected-resource`
  - RFC 8414 Authorization Server Metadata — `/.well-known/oauth-authorization-server`
  - OIDC Discovery 1.0 — `/.well-known/openid-configuration`
- **RFC 8707 Resource Indicators** driving the access token's `aud` claim (toggle it on/off live).
- **Audience validation** ("door check") at each resource — RFC 9068 / OAuth 2.1 §5.2.
- **Scope vs. audience orthogonality**: `aud` = *"may I enter this resource?"*, scope = *"may I do X here?"*.
- **Least‑privilege / step‑up authorization** (the MCP *Scope Challenge* flow): start with a
  minimal token, get `403 insufficient_scope`, re‑authorize for more.
- **Refresh token rotation** for a public client.
- A **locally trusted TLS certificate chain** (root → intermediate → leaf), à la Caddy/mkcert.

---

## Architecture

One JVM process, three roles, deliberately split across **two hostnames** (both resolve to
`127.0.0.1`) so the audiences are genuinely distinct:

| Role | Hostname | Examples |
| --- | --- | --- |
| **Client** (stateless SPA) | `https://localhost:8443` | `/client.html` |
| **Resource Server** | `https://localhost:8443` | `/get`, `/post`, `/whoami`, `/whereami` |
| **Authorization Server / OpenID Provider** | `https://localhost.apple.com:8443` | `/oauth2/*`, `/userinfo`, `/.well-known/*` |

```
Browser ──TLS──> https://localhost:8443/client.html        (SPA: PKCE public client)
   │
   │  1. discover metadata (same-origin + cross-origin to AS)
   │  2. redirect to AS to log in / consent
   ▼
https://localhost.apple.com:8443/oauth2/authorize          (Authorization Server / OP)
   │  3. authorization code  ──redirect──► back to localhost SPA
   │  4. SPA exchanges code (PKCE + resource indicator) for tokens
   ▼
https://localhost:8443/get|/post|/whoami|/whereami         (Resource Server)
https://localhost.apple.com:8443/userinfo                  (OP UserInfo)
```

Why split hosts? So that the **Resource Server audience** (`https://localhost:8443`) and the
**OP audience** (`https://localhost.apple.com:8443`) are different values — making the `aud`
claim's behaviour visible instead of degenerate.

---

## Project layout

```
src/main/java/dev/sandipchitale/oidcoauth2/
├── Oidcoauth2Application.java
├── config/
│   ├── SecurityConfig.java                              # all 3 security filter chains, token customizer, clients, keys
│   ├── PublicClientRefreshTokenAuthenticationConverter.java
│   ├── PublicClientRefreshTokenAuthenticationProvider.java   # lets a public client use refresh_token
│   └── JwtRefreshTokenGenerator.java                    # JWT (not opaque) refresh tokens
└── web/
    ├── MetadataController.java                          # RFC 9728 protected-resource metadata
    └── ResourceController.java                          # /get /post /whoami /whereami
src/main/resources/
├── application.yaml                                    # port, TLS bundle (from ~/.oidcoauth2/certs)
└── static/client.html                                  # the stateless SPA dashboard
generate-certs.sh                                        # local CA + leaf cert generator
```

---

## Prerequisites

- **JDK 26** (configured via the Gradle toolchain; Gradle will fetch it if needed).
- **`openssl`** on `PATH` (LibreSSL that ships with macOS works).
- **macOS** for the keychain‑trust step (`security` CLI). Other OSes work too — you just trust
  the root CA your own way.
- **A hosts entry** so `localhost.apple.com` resolves locally. Add to `/etc/hosts`:

  ```
  127.0.0.1   localhost.apple.com
  ```

---

## Setup

### 1. Generate the TLS certificate chain

```bash
./generate-certs.sh            # generates the chain AND trusts the root CA (asks for sudo)
# or
./generate-certs.sh --no-trust # generates only; prints the trust command to run later
```

This creates a **Root CA → Intermediate CA → leaf** chain (mirroring how Caddy's internal CA
works) under your home directory — **never in the project tree, never in the jar**:

```
~/.oidcoauth2/certs/   localhost.apple.com.crt (fullchain) + .key   ← read by the app
~/.oidcoauth2/ca/      rootCA.* , intermediateCA.*                  ← issuing material only
```

The leaf is valid for `localhost.apple.com`, `localhost`, `127.0.0.1`, and `::1`.

### 2. Trust the Root CA (macOS)

If you used `--no-trust`, run:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.oidcoauth2/ca/rootCA.crt
```

Then **fully quit and reopen your browser** so it picks up the new trusted root.

---

## Run

```bash
./gradlew bootRun
```

Open **<https://localhost:8443/>** (redirects to `/client.html`).

**Users:** `user` / `password` and `user2` / `password`.

> 💡 The JWT signing key is regenerated on every startup and tokens/sessions are in‑memory.
> After a restart, **clear site data / use a fresh window** — old tokens and cookies are stale.

---

## Using the dashboard

The SPA (`client.html`) is a **fully stateless public client** — it holds tokens only in
`sessionStorage` and talks to the AS/RS purely over HTTP.

1. **Select Scopes** — checkboxes grouped by owner:
   - *OpenID Provider*: `openid`, `profile`, `email`, `address`, `phone`
   - *Resource Server*: `READ`, `WRITE`
2. **RFC 8707 Resource Indicator** toggle — whether to send `resource=https://localhost:8443`.
   - **On** → access token `aud` includes the resource server.
   - **Off** → no resource sent (see the `aud` rules below).
3. **Authenticate** — runs the PKCE flow: redirect to the AS (`localhost.apple.com`), log in,
   consent, redirect back to the SPA (`localhost`), exchange the code for tokens.
4. **API Request Tester** — call `/get` (needs `READ`), `/post` (needs `WRITE`), `/userinfo`
   (needs `openid`), and `/whoami` / `/whereami` (no scope — only a token bound to the RS).
   Each result is shown inline in its card *and* in the docked **System Logs Console**.
5. **Metadata Discovery** tab — shows all three metadata documents and narrates the MCP
   discovery order.

---

## Endpoints

### Authorization Server / OpenID Provider — `https://localhost.apple.com:8443`

| Endpoint | Purpose |
| --- | --- |
| `/oauth2/authorize` | Authorization endpoint (PKCE) |
| `/oauth2/token` | Token endpoint |
| `/oauth2/jwks` | JWK set |
| `/userinfo` | OIDC UserInfo (requires `openid`; `aud` must include the OP) |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata (auto, Spring Authorization Server) |
| `/.well-known/openid-configuration` | OIDC Discovery (auto) |
| `/login` | Form login page |

### Resource Server — `https://localhost:8443`

| Endpoint | Method | Requires |
| --- | --- | --- |
| `/get` | GET | `aud` = RS **and** `SCOPE_READ` |
| `/post` | POST | `aud` = RS **and** `SCOPE_WRITE` |
| `/whoami` | GET | `aud` = RS only (no scope) |
| `/whereami` | GET | `aud` = RS only (no scope) |
| `/.well-known/oauth-protected-resource` | GET | public — RFC 9728 metadata |

---

## Security model (the interesting part)

### Three filter chains (`SecurityConfig`)

1. **`@Order(1)` Authorization Server** — `securityMatcher(endpointsMatcher)`.
   - `anyRequest().authenticated()` (so anonymous `/oauth2/authorize` redirects to `/login`).
   - CSRF disabled for the OAuth endpoints (the SPA `POST`s the token endpoint with no CSRF token).
   - `.oidc(...)` with a custom **UserInfo mapper**.
   - `oauth2ResourceServer().jwt()` using an **audience‑validating decoder** requiring the **OP** audience.
2. **`@Order(2)` Resource Server** — `securityMatcher("/get","/post","/whoami","/whereami")`.
   - `/get`→`SCOPE_READ`, `/post`→`SCOPE_WRITE`, the rest only `authenticated()`.
   - `oauth2ResourceServer().jwt()` using an **audience‑validating decoder** requiring the **RS** audience.
   - `accessDeniedHandler` emits `403` + `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`
     (the MCP **Scope Challenge**), `authenticationEntryPoint` emits `401 invalid_token`.
3. **`@Order(3)` Default** — serves `/`, `/client.html`, the protected‑resource metadata, and form login.

### How the access token's `aud` is set

The `OAuth2TokenCustomizer` sets `aud` to the token's **actual consumer(s)** — never `client`:

```
aud(access_token) = {resource indicators from RFC 8707 `resource` param}
                  ∪ {OP audience  if the `openid` scope is granted}
if that set is empty → the `aud` claim is removed entirely
```

| Scopes | Resource indicator | Access token `aud` |
| --- | --- | --- |
| `openid` | off | `[OP]` |
| `openid` | on | `[RS, OP]` |
| `READ WRITE` | off | *absent* (AS can't know which RS without an indicator) |
| `READ WRITE` | on | `[RS]` |
| `openid READ WRITE` | on | `[RS, OP]` |

Rationale:

- **`client` is wrong.** The client is the token's *bearer*, not its *consumer*.
- **`openid` → OP is allowed** because an `openid` access token has exactly one consumer: this OP's
  `/userinfo`. Unambiguous, so no resource indicator needed.
- **`READ`/`WRITE` → some RS is *not* inferred** from the scope: a scope name doesn't identify *which*
  resource server (think two RSes that both define `READ`). The client must say so via the resource
  indicator. This is the over‑broad‑token / scope‑collision problem RFC 8707 exists to solve.

The **ID token** keeps `aud = client_id` (required by OIDC Core) — the customizer only touches access tokens.

### Audience ≠ authorization (the door vs. the room)

- **Audience validation** answers *"is this token meant for me?"* — enforced by the per‑chain decoder.
  A token whose `aud` doesn't include the resource → `401 invalid_token`, before any scope check.
- **Scope** answers *"is this caller allowed to do X?"* — enforced by `hasAuthority("SCOPE_…")`.

`/whoami` and `/whereami` require **only** a valid, audience‑bound token (no scope). So a **zero‑scope,
least‑privilege token** can enter the RS and hit them, while `/get`/`/post` reject it with `403`. That's
the **foundation of least privilege**: get a minimal token bound to a resource, then grow scopes on
demand via **step‑up authorization** (the `403 insufficient_scope` → re‑authorize loop the SPA implements,
complete with retry limits).

---

## Configuration

`src/main/resources/application.yaml`:

```yaml
app:
  cert-dir: "${OIDCOAUTH2_CERT_DIR:${user.home}/.oidcoauth2/certs}"
spring:
  ssl:
    bundle:
      pem:
        my-server-bundle:
          keystore:
            certificate: "file:${app.cert-dir}/localhost.apple.com.crt"
            private-key:  "file:${app.cert-dir}/localhost.apple.com.key"
server:
  port: 8443
  ssl:
    bundle: my-server-bundle
```

The cert location is resolved from `${user.home}` at runtime — **no hardcoded absolute path and no
dependency on the working directory**. Override it per environment with the `OIDCOAUTH2_CERT_DIR`
environment variable (and `OIDCOAUTH2_CA_DIR` for the generator).

---

## Things to try

- **Resource indicator on/off** — authenticate with `openid` only, toggle the indicator, and watch the
  decoded access token's `aud` flip between `[OP]` and `[RS, OP]`.
- **Least privilege** — `openid` only + indicator **on** → `/whoami` returns `200` (no scope needed) but
  `/get` returns `403` (no `READ`). Then tick `READ` and re‑authorize → `/get` returns `200`.
- **The door check** — indicator **off** + `openid` only → `aud=[OP]` → `/whoami` returns `401`
  (token isn't *for* the RS). Flip the indicator on → `200`.
- **UserInfo claims by scope** — `openid` → `sub` only; add `profile` → `name`; add `email` → `email`.
- **Plain OAuth (no OIDC)** — request only `READ WRITE` (no `openid`): you get an access token but **no
  ID token**, and `/userinfo` is unreachable.

---

## Troubleshooting

- **Browser TLS warning** → you haven't trusted the Root CA, or didn't restart the browser after trusting it.
- **`invalid_grant` on refresh, or `401` everywhere after a restart** → stale tokens/cookies. The signing
  key rotates each startup and state is in‑memory. Clear site data / use a fresh window.
- **`[invalid_request] OAuth 2.0 Parameter: principal`** at `/oauth2/authorize` → you've removed
  `authorizeHttpRequests(anyRequest().authenticated())` from chain 1; without it anonymous authorize
  requests never redirect to the login page.
- **`localhost.apple.com` won't load** → missing `/etc/hosts` entry (see Prerequisites).

---

## References

- OAuth 2.1 — draft-ietf-oauth-v2-1
- RFC 6749 (OAuth 2.0), RFC 6750 (Bearer tokens)
- RFC 7591 (Dynamic Client Registration), RFC 7636 (PKCE)
- RFC 8414 (Authorization Server Metadata)
- RFC 8707 (Resource Indicators)
- RFC 9068 (JWT Profile for Access Tokens)
- RFC 9700 (OAuth 2.0 Security Best Current Practice)
- RFC 9728 (Protected Resource Metadata)
- OpenID Connect Core 1.0 & Discovery 1.0
- Model Context Protocol — Authorization (2025-11-25)
- [Spring Authorization Server](https://docs.spring.io/spring-authorization-server/reference/)
