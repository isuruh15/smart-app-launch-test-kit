# CLAUDE.md — SMART App Launch Test Kit (Local WSO2 Setup)

## What this project is

An [Inferno](https://inferno-framework.github.io/inferno-core/) test kit for the SMART App Launch specification. It tests a FHIR server's SMART authorization flows (Standalone Launch, EHR Launch, Backend Services, Token Introspection) against STU1, STU2, and STU2.2.

This repo has been adapted to run against a **locally hosted WSO2 FHIR setup** (WSO2 APIM as the FHIR gateway, WSO2 IS as the OAuth2/SMART authorization server).

---

## Local WSO2 Setup

### Products

| Product | Role | Default Port |
|---|---|---|
| WSO2 API Manager (APIM) | FHIR API gateway | `8243` (HTTPS) |
| WSO2 Identity Server (IS) | SMART authorization server | `9443` (HTTPS) |

Located at: `/Users/isurus/wso2/healthcare/other/rnd/apim-is/smart/`
- `wso2is-7.3.0/`
- `wso2am-4.6.0/`

### FHIR URL inputs for Inferno UI

When starting a test session, use `host.docker.internal` instead of `localhost` because tests run inside Docker:

| Input | Value |
|---|---|
| FHIR Endpoint (`url`) | `https://host.docker.internal:8243/<fhir-api-context>` |
| Authorization URL | `https://host.docker.internal:9443/oauth2/authorize` |
| Token URL | `https://host.docker.internal:9443/oauth2/token` |
| Introspection URL | `https://host.docker.internal:9443/oauth2/introspect` |

---

## Pre-run Script: `export-wso2-certs.sh`

**Run this before each test run** (or whenever WSO2 keystores change):

```bash
./export-wso2-certs.sh \
  /path/to/wso2is-7.3.0 \
  /path/to/wso2am-4.6.0
```

### What it does

1. **Detects keystore config** from each product's `deployment.toml`
2. **Re-generates self-signed certs** using the original private key, with extended SANs:
   - `DNS:localhost`
   - `DNS:host.docker.internal`
   - `IP:127.0.0.1`
3. **Imports new certs** back into each WSO2 keystore (backing up the original as `.bak`)
4. **Cross-imports certs** into each product's client truststore so internal SSL calls succeed:
   - IS truststore ← IS cert + APIM cert
   - APIM truststore ← APIM cert + IS cert
5. **Copies certs** to `config/wso2is.crt` and `config/wso2apim.crt` for Inferno to trust
6. **Updates `lib/local_ssl_trust.rb`** with the current cert list

After running the script, **restart both WSO2 servers** and then Inferno:

```bash
docker compose restart inferno worker
```

### Why SANs are extended

WSO2 default certs have `CN=localhost` / `SAN=DNS:localhost` only. Inferno runs inside Docker and connects to `host.docker.internal`, which causes TLS hostname verification to fail. The script re-signs certs to include `host.docker.internal` so verification passes.

### JKS lockout note

The script includes a 30-second sleep between IS and APIM processing. This is intentional — Java's JKS format has a brute-force lockout that triggers after multiple failed keytool operations. If the script fails with `Too many failures - try later`, wait 60 seconds and re-run. If the APIM JKS becomes unrecoverable, restore from the clean copy at `wso2am-4.6.0-dev/repository/resources/security/wso2carbon.jks`.

---

## SSL Trust Architecture

### Problem
WSO2 default certs are self-signed. Inferno (inside Docker) must trust them for:
- SMART discovery (`/.well-known/smart-configuration`)
- TLS version tests (`SMARTTLSTest`)
- All token/auth endpoint calls

### Solution

**`lib/local_ssl_trust.rb`** — loaded by both `config.ru` (Puma/web) and `worker.rb` (Sidekiq). Patches `OpenSSL::X509::Store#set_default_paths` to add WSO2 certs to every SSL store created by Ruby:

```ruby
_trusted_certs = %w[config/wso2is.crt config/wso2apim.crt]
```

Must use `super(*args)` (not bare `super`) — bare `super` inside `define_method` raises `RuntimeError` on Ruby 3.3.

**`docker-compose.yml`** volume-mounts `config/`, `config.ru`, `worker.rb`, and `lib/local_ssl_trust.rb` into both `inferno` and `worker` containers so cert changes take effect on restart without a Docker rebuild.

---

## Docker Setup

```bash
# First time
./setup.sh

# Start
docker compose up -d

# Stop
docker compose down

# Apply cert or code changes (no rebuild needed due to volume mounts)
docker compose restart inferno worker
```

Inferno UI: `http://localhost:90`

### Volume mounts (key ones)

| Host path | Container path | Purpose |
|---|---|---|
| `./config/` | `/opt/inferno/config/` | WSO2 certs, nginx config |
| `./config.ru` | `/opt/inferno/config.ru` | SSL trust patch for Puma |
| `./worker.rb` | `/opt/inferno/worker.rb` | SSL trust patch for Sidekiq |
| `./lib/local_ssl_trust.rb` | `/opt/inferno/lib/local_ssl_trust.rb` | Shared SSL trust logic |
| `./data/` | `/opt/inferno/data/` | SQLite test result database |

---

## Troubleshooting

### `SSL_connect ... certificate verify failed (self-signed certificate)`
The `config/` cert files are not present or the containers haven't restarted since `export-wso2-certs.sh` was run.
→ Re-run the script, then `docker compose restart inferno worker`.

### `SSL_connect ... certificate verify failed (hostname mismatch)`
The cert in the WSO2 keystore doesn't include `host.docker.internal` in its SANs.
→ Re-run `export-wso2-certs.sh` and restart WSO2 servers.

### `PKIX path building failed` in WSO2 logs
WSO2's client truststore doesn't trust the new cert. The script handles this in step 4, but WSO2 must be restarted after the script runs.
→ Restart WSO2 IS and APIM.

### `Cannot recover key` from keytool
The JKS key entry password doesn't match the store password. Usually means the JKS was previously modified incorrectly.
→ Restore from the `.bak` file or from `wso2am-4.6.0-dev/`.

### `Too many failures - try later` from keytool
JKS brute-force lockout triggered by earlier failed attempts.
→ Wait 60 seconds, restore from `.bak` if needed, then re-run.

### Tests run fine but `SMARTTLSTest` fails
TLS tests connect to the auth/token URLs and verify TLS >= 1.2. These use the same SSL trust patch. Ensure the token/auth URLs use `host.docker.internal`, not `localhost`.

### Changes to `local_ssl_trust.rb` or `config.ru` not taking effect
These files are volume-mounted, so a Docker rebuild is not needed — but Puma/Sidekiq must be restarted to reload them.
→ `docker compose restart inferno worker`
