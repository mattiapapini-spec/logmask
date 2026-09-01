# LogMask — Technical Documentation

**Version 0.27.6** · Self-hosted, reversible, fail-closed pseudonymization of SOC logs

---

## Table of contents

1. [What LogMask is](#1-what-logmask-is)
2. [Core concepts](#2-core-concepts)
3. [Architecture](#3-architecture)
4. [Installation and deployment](#4-installation-and-deployment)
5. [Configuration](#5-configuration)
6. [User guide](#6-user-guide)
7. [Supported formats](#7-supported-formats)
8. [The pseudonymization engine](#8-the-pseudonymization-engine)
9. [Token shapes reference](#9-token-shapes-reference)
10. [Vendor kits](#10-vendor-kits)
11. [DLP categories and Safe mode](#11-dlp-categories-and-safe-mode)
12. [API reference](#12-api-reference)
13. [Security model](#13-security-model)
14. [Operations and troubleshooting](#14-operations-and-troubleshooting)
15. [Regulatory considerations (EU / Italy, AI use)](#15-regulatory-considerations-eu--italy-ai-use)
16. [Extending LogMask](#16-extending-logmask)

---

## 1. What LogMask is

LogMask is a self-hosted web and CLI tool that **pseudonymizes security logs** so that they can be shared — with an external analyst, a vendor support desk, or an AI assistant — without disclosing client-identifying data, while preserving the analytical and forensic value of the log.

The design goal is a specific, asymmetric one: **never leak client-identifying data, even at the cost of readability**, while keeping indicators of compromise (hashes, GUIDs, URLs, file names, ports, event codes) intact so the log remains useful for investigation.

Two properties make this practical:

- **Reversible by design.** Masking is deterministic and reversible on the tenant that produced it: the same value always becomes the same pseudonym, and the holder of the tenant's vault and key can restore the original. This lets an analyst correlate events across a shared export and later map a finding back to the real host or user.
- **Fail-closed.** When LogMask cannot confidently classify a field, it does not pass it through in the clear. In Safe mode the field is elided; unclassified free text that could carry identity is masked as text rather than kept. The default posture is to protect, not to expose.

> **Pseudonymization, not anonymization.** LogMask performs *pseudonymization*, which is reversible by whoever holds the tenant key and vault. It is **not** irreversible anonymization. A subset of transformations is deliberately irreversible — client names (`CLIENT-…`), secrets (`secret-…`) and elided fields (`[ELIDED]`) are never stored and cannot be recovered. The legal consequences of this distinction are covered in [§15](#15-regulatory-considerations-eu--italy-ai-use).

---

## 2. Core concepts

**Tenant.** Every operation happens in the context of a tenant (a client). Each tenant has its own vault, its own derived keys, and its own authorization scope. Two tenants never share pseudonyms: the same host name masked for tenant A and tenant B produces two different, unrelated tokens.

**Vault.** A per-tenant SQLite database that stores the mapping between a real value and its pseudonym. Original values are stored **encrypted** (AES-GCM, one random nonce per row). The vault is the only thing that makes a masked export reversible; losing it means losing the ability to restore, permanently.

**Pseudonym / token.** The synthetic value that replaces a real one, e.g. `usr-4ozopszr` for a user or `host-ri6jxfsb.masked.local` for a host. Token shapes are listed in [§9](#9-token-shapes-reference).

**Kind.** The category of a value — user, email, fqdn, ipv4, windomain, iban, and so on. The kind determines the token shape and whether the value is reversible.

**Vendor kit.** A YAML rule set that maps a specific product's field names to kinds and actions (mask / keep / text / drop). Kits are what let LogMask classify a Cortex XDR export differently from an Elastic ECS one. See [§10](#10-vendor-kits).

**Safe mode.** A fail-closed switch: any field that no kit and no heuristic could classify is elided (`[ELIDED]`) rather than passed through. See [§11](#11-dlp-categories-and-safe-mode).

**Action.** What happens to a field: `mask` (reversible pseudonym), `keep` (left as-is — for operational metadata and IOCs), `text` (free-text scrubbing, for messages and descriptions), `drop` (removed).

---

## 3. Architecture

LogMask is a single container running a FastAPI application that serves both the JSON API and a single-page web UI.

```
┌──────────────────────────────────────────────────────────┐
│  Browser (single-page app, vanilla JS)                     │
│   • anonymize / restore panels   • kit studio              │
│   • docx / pst / pdf cards        • admin (users, audit)   │
└───────────────┬────────────────────────────────────────────┘
                │ HTTPS (cookie session + CSRF double-submit)
┌───────────────▼────────────────────────────────────────────┐
│  FastAPI app (app.py)                                       │
│   • auth / RBAC (auth.py)         • endpoints               │
│   • request size + security middleware                     │
├─────────────────────────────────────────────────────────────┤
│  Engine (logmask.py)              Structured (structured.py) │
│   • master regex, per-kind        • JSON / NDJSON / CEF /    │
│     builders, guards                LEEF / syslog parsers    │
│   • DLP scanning (dlp.py)         Vendor kits (vendor_kits)  │
│   • CSV / text / identity sweep   Documents:                │
│                                     docx_anon / pst_anon /   │
│                                     pdf_anon                 │
├─────────────────────────────────────────────────────────────┤
│  Per-tenant vault (SQLite, AES-GCM)   Master key (0600)      │
└─────────────────────────────────────────────────────────────┘
```

**Key components:**

- `app.py` — HTTP endpoints, authentication dependency, request-size and security-header middleware, upload handling.
- `auth.py` — user store, Argon2 password hashing, session and CSRF token management, RBAC, login rate limiting, audit log.
- `logmask.py` — the pseudonymization engine: the master regex, the per-kind pseudonym builders, all the correctness guards (IOC, opaque-blob, host-original, person-name, VAT/address, identity-in-text), the CSV engine, and the vault-known sweep.
- `structured.py` — format detection and structured parsers (JSON, NDJSON, CEF, LEEF, syslog).
- `dlp.py` — the DLP category catalog and the sensitive-residual scanner (credentials, IBAN, tax id, phone, VAT, address, cloud id, sensitive URL parameters).
- `vendor_kits.py` — kit loading, validation, hot reload, and vendor detection.
- `docx_anon.py`, `pst_anon.py`, `pdf_anon.py` — document handlers for Word, Outlook archives, and PDF.
- `workflows.py` — the preset "workflow profiles" (ticket, AI analysis, threat hunting, report, field quality).

**Data at rest:** each tenant vault is an encrypted SQLite file under the data directory; the master key is a 32-byte random key stored with `0600` permissions and used to derive per-tenant keys via HMAC.

---

## 4. Installation and deployment

### Requirements

- Docker and Docker Compose.
- No external services: the vault is local SQLite; there is no database server, message broker or cloud dependency.

### Quick start

```bash
# from the project directory
docker compose build --no-cache
docker compose up -d
```

On first start, if no admin password is configured, a random bootstrap password is written to `./data/bootstrap-admin.txt`. Log in as `admin` with that password; you will be required to change it before doing anything else.

The UI is then reachable at `http://<host>:8090/`.

### PowerShell (Windows)

```powershell
cd "$env:USERPROFILE\Claude\Projects\logmask-web-v0.10.4"
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Network exposure

By default the container binds to `0.0.0.0`, i.e. it is reachable from the whole LAN. For a single-workstation, host-only deployment set:

```
LOGMASK_BIND=127.0.0.1
```

in the `.env` file. For a tool that handles client logs this is worth deciding deliberately; see [§13](#13-security-model).

### Ports

The compose file maps `${LOGMASK_PORT:-8090}:8080` — the app listens on `8080` inside the container, published on `8090` on the host by default.

### PDF support and licensing

PDF handling uses **PyMuPDF**, which is distributed under the **AGPL-3.0** license — the same license LogMask itself is released under, so the combined work is license-coherent. Publishing LogMask's source satisfies the AGPL source-availability obligation by construction. For commercial licensing of LogMask without AGPL obligations, see the README (a commercial PyMuPDF license from Artifex is additionally required for the optional PDF module).

---

## 5. Configuration

Configuration is entirely through environment variables (typically set in `.env`) and optional data files under the data directory. Nothing needs to be hard-coded.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LOGMASK_DATA` | `/data` | Data directory (vaults, key, config files) |
| `LOGMASK_BIND` | `0.0.0.0` | Bind address; set `127.0.0.1` for host-only |
| `LOGMASK_PORT` | `8090` | Published host port |
| `LOGMASK_ADMIN_USER` | `admin` | Bootstrap admin username |
| `LOGMASK_ADMIN_PASSWORD` | *(random)* | Bootstrap admin password; if empty, written to `data/bootstrap-admin.txt` |
| `LOGMASK_KEY_FILE` | `data/master.key` | Master key location (32 bytes, `0600`) |
| `LOGMASK_COOKIE_SECURE` | `false` | Set `true` behind HTTPS to mark cookies Secure |
| `LOGMASK_SESSION_IDLE_SECONDS` | `1800` | Idle session timeout |
| `LOGMASK_SESSION_MAX_SECONDS` | `28800` | Absolute session lifetime |
| `LOGMASK_LOGIN_MAX_FAILURES` | `5` | Failed logins before lockout |
| `LOGMASK_LOGIN_WINDOW_SECONDS` | `900` | Lockout window |
| `LOGMASK_MAX_BODY_BYTES` | `12582912` | Max request body |
| `LOGMASK_MAX_FILE_BYTES` | `8388608` | Max uploaded file size |
| `LOGMASK_CLIENT_TERMS` / `_FILE` | — | Client names to mask/scrub (inline or file) |
| `LOGMASK_CLIENT_TERM_MODE` | `pseudonymize` | `pseudonymize` \| `elide` \| `label` |
| `LOGMASK_CLIENT_TERM_LABEL` | `[CLIENTE]` | Label used when mode is `label` |
| `LOGMASK_HOST_TERMS` / `_FILE` | — | Host-name globs owned by the tenant |
| `LOGMASK_TENANT_NETWORKS` / `_FILE` | — | Public CIDRs that identify the client |
| `LOGMASK_PERSON_TERMS` / `_FILE` | — | Real person names present in the tenant |
| `LOGMASK_KEEP_FIELDS` / `_FILE` | — | Field names to force `keep` |
| `LOGMASK_DOCX_MAX_UNCOMPRESSED` | `268435456` | Decompressed-size cap for .docx (zip-bomb guard) |
| `LOGMASK_PST_MAX_EXTRACTED` | `1073741824` | Extracted-size cap for .pst |
| `LOGMASK_READPST_TIMEOUT` | `300` | Timeout (s) for the readpst subprocess |
| `LOGMASK_PDF_MAX_PAGES` | `2000` | Page-count cap for PDF |

The typical production `.env` raises the upload limits for large XQL/Discover exports, e.g. `LOGMASK_MAX_FILE_BYTES=67108864` and `LOGMASK_MAX_BODY_BYTES=100663296`.

### Data files

These live under the data directory and are hot-reloaded where noted. None of them contain real client names in the repository — the repository ships `.example` files only.

| File | Purpose |
|---|---|
| `data/client_terms.txt` | Client names to scrub/mask; one per line |
| `data/host_terms.txt` | Host-name globs the tenant owns (e.g. `WKS*`, `*DC*`) |
| `data/tenant_networks.txt` | Public CIDRs that identify the client |
| `data/person_terms.txt` | Real employee names present in the tenant |
| `data/keep_fields.txt` | Field names to always keep readable |
| `data/persons/` | Given-name and surname lists for generic person detection |
| `data/kits/*.yaml` | User vendor kits (extend or override the built-ins; hot reload) |

> **Secret hygiene.** `client_terms.txt` and `person_terms.txt` contain real, identifying values by their nature. They are configuration, not data to be shared, and should be treated with the same care as any secret.

---

## 6. User guide

The UI is a single page with panels grouped by task.

### Anonymize

Paste a log, or upload one or more files, choose the output format (auto-detected by default), and process. The result panel shows the masked output; a report summarizes what was masked, what was kept, what was elided, and — when a vendor kit matched — the detected vendor and coverage.

Key controls:

- **IP policy** — `do not anonymize IPs` / `anonymize internal IPs only` / `anonymize all IPs`. Default: **all**.
- **URL policy** — `do not anonymize URLs` / `customer hosts only` / `mask all URLs`. Default: **all**. Credentials and sensitive query values are always handled regardless of this setting.
- **Safe mode** — elide unclassified fields (fail-closed). Recommended on.
- **Preserve subnet** — keep the /24 grouping of anonymized IPv4s.
- **Mask tenant public networks** — mask the CIDRs in `tenant_networks.txt` even under "internal IPs only".
- **Vendor kit** — force a specific kit, or leave on auto-detect.
- **Workflow profile** — apply a coherent preset (see below).

### Restore (de-anonymize)

Paste or upload a masked output and get the original values back. This requires the `reverse` permission and is recorded in the audit log. Restore works on text, structured formats, CSV, `.docx` and `.pdf`.

### Document cards

- **Word .docx** — returns an anonymized `.docx` with layout, tables, headers and numbering preserved; only the text changes. A companion card restores a masked `.docx`.
- **Outlook .pst** — extracts every message and returns one record per message (NDJSON or CSV). The message body is available both as `completeHeader` (the message as it comes out of the archive) and `body` (the same content reduced to human-readable text).
- **PDF** — two modes: `laid-out PDF` (returns a PDF with pages and positions preserved and the original text actually removed) or `text` (extracted, anonymized text). A companion card restores a masked PDF.

### Kit studio

Browse the installed kits, open a built-in kit as a starting copy, edit a user kit, validate it, and run a dry-run against a header to see how each column would be classified — without processing any values.

### Sessions

Collect multiple logs (paste and/or files) as separate entries, process them together, and download a single ZIP. Sessions live in memory and reset on reload or logout; nothing is written to disk.

### Workflow profiles

Presets that apply a coherent set of options. As of 0.26.1 every profile masks all IPs and all URLs by default; the only exception is **Threat hunting (internal)**, which deliberately keeps technical indicators readable for internal correlation.

| Profile | Purpose |
|---|---|
| Customer ticket | Client-facing report: useful technical context, internal data and PII protected |
| External AI analysis | Cautious preset for external LLMs: everything masked, secrets and PII minimized |
| Field quality | Anonymization-quality audit: coverage, elisions, field tuning |
| Threat hunting (internal) | Keeps indicators readable for internal correlation; still blocks secrets and PII |
| Report / attachment | High-minimization output for attachments, evidence, reports |

### Administration

User management (create users, assign roles and tenants), the audit log, and the vault reset control (admin only; archives the vault rather than deleting it).

---

## 7. Supported formats

LogMask detects the format automatically, or you can force it.

| Format | Notes |
|---|---|
| Plain text | Free-text scrubbing across the whole input |
| CSV / TSV | Per-column classification via kits and heuristics; vertical key/value exports are transposed automatically |
| JSON / NDJSON | Recursive field masking; arrays and nested objects supported |
| CEF | ArcSight Common Event Format |
| LEEF | IBM QRadar Log Event Extended Format |
| Syslog (key=value) | Structured syslog |
| Word `.docx` | Layout-preserving; returns a valid `.docx` |
| Outlook `.pst` | Per-message extraction; requires `pst-utils` in the image |
| PDF | Layout-preserving redaction or text extraction; requires PyMuPDF |

Byte-level robustness: CSV parsing strips embedded NUL bytes (common in Windows event exports) instead of failing; the transport prefixes used by Elastic/Kibana wrappers (`_source.`, `fields.`, `winlog.event_data.`, …) are stripped before field matching so the inner product kit still applies.

---

## 8. The pseudonymization engine

### The masking pass

`Anonymizer.process(text)` runs a master regex over the input that recognizes, in a fixed precedence order: URLs, e-mail addresses, UPNs, IPv4/IPv6, MAC addresses, user-in-path patterns (`C:\Users\jdoe\…`), FQDNs, and Windows domains. Each match is routed to the pseudonym builder for its kind. After the regex pass, a series of additional passes run:

1. **Bare hostnames** — host tokens not caught by the structured patterns.
2. **SharePoint identities** — `/personal/<who>/` paths.
3. **Person names** — first/last name detection using bundled and tenant lists.
4. **Identity-in-prose** — `User mrossi logged on…` narratives (see below).
5. **DLP scan** — credentials, IBAN, tax id, phone, VAT, address, cloud id, sensitive URL parameters.
6. **Client terms** — configured client names, always masked last as a final sweep.

### Deterministic, keyed pseudonyms

A pseudonym is a keyed hash of the value:

```
pseudonym = builder( HMAC(tenant_key, kind, normalized_value) )
```

Because the derivation is deterministic and tenant-keyed, the same value always yields the same token within a tenant, different tenants yield different tokens, and the mapping cannot be brute-forced without the tenant key. The original value is stored encrypted in the vault so the token is reversible; irreversible kinds (client name, secret) are never vaulted.

### The vault-known sweep

After the main pass, LogMask can sweep the output for values the vault already knows and replace them with their canonical pseudonym — this is how a host named in a free-text message gets the same token it received in its dedicated field. The sweep is cost-adaptive: for a single event against a large vault it searches text→vault via blind index (no decryption); for a huge export against a small vault it reads the vault once. Both strategies produce identical output.

In natural-language contexts (documents, e-mail subjects and bodies) the sweep runs in **prose mode**, which only replaces originals that cannot be common words — those containing a digit or separator (`m.rossi`, `srv-01`, `DOMAIN\user`) or made of multiple words (`Mario Rossi`). This prevents a common word that landed in the vault through a past misclassification (`SOC`, `Windows`, `Sicurezza`) from corrupting readable text.

### Correctness guards

Much of the engine is guards that prevent *wrong* masking, which is as damaging as a leak because it destroys IOCs or corrupts text silently:

- **IOC-hash guard** — a run of ≥16 hex characters is an indicator (hash), never a host; it is kept.
- **Opaque-blob guard** — a token adjacent to `+`, `/` or `=` is inside a base64 blob (e.g. an event `_id`) and is not masked, so unique identifiers are not corrupted.
- **Host-original guard** — only values shaped like a machine name are swept; product words (`Windows`, `Management`) and process names (`WmiPrvSE.exe`) are not.
- **Prose-original guard** — in natural language only identifier-shaped originals are swept.
- **Identity-in-text** — key/value identities inside Windows event messages (`Account Name: mrossi`) and serialized JSON (`"SubjectUserName":"mrossi"`) are masked; log placeholders (`-`, `N/A`, `0x0`, `%%1833`, `localhost`, `SYSTEM`) are not.
- **VAT Luhn check** — a bare 11-digit number is masked as an Italian VAT only if it passes the Luhn checksum; otherwise it is treated as a record id and left alone.
- **Address false-positive guard** — un-labeled addresses require a proper-case street name plus a house number, so `Potential RMM Tool Installation via Uncommon Process` and `traffic via proxy 8080` are not mistaken for addresses.

### Idempotence and reversibility

Processing an already-masked output does not change it: an existing pseudonym is recognized and left as-is. Restoration reverses every reversible token; irreversible tokens (`CLIENT-…`, `secret-…`, `[ELIDED]`) remain, by design.

---

## 9. Token shapes reference

| Kind | Example input | Example token | Reversible |
|---|---|---|---|
| user | `mrossi` | `usr-4ozopszr` | yes |
| email | `a@acme.com` | `usr-6rwixc3e@osgwjo.masked` | yes |
| fqdn / host | `SRV-DC01.corp.local` | `host-ri6jxfsb.masked.local` | yes |
| ipv4 (internal) | `10.20.30.40` | `198.18.x.x` | yes |
| ipv4 (public) | `8.8.8.8` | `198.19.x.x` | yes |
| ipv6 | `fe80::1` | `fd00:…::1` | yes |
| mac | `00:1a:2b:3c:4d:5e` | `02:…` (locally-administered) | yes |
| windomain | `CORP` | `DOM-shphyawa` | yes |
| tax id (CF) | `VRGSRA76B55H501Z` | `cf-tyvu3zav7vpf` | yes |
| iban | `IT60X05428…` | `iban-dwchbizxmfec` | yes |
| phone | `+39 335 1234567` | `tel-vzoftypx33b5` | yes |
| vat / P.IVA | `00743110157` | `vat-y6orweoro2ds` | yes |
| address | `Via Roma 12` | `addr-6krvk6xmear5` | yes |
| person | `Mario Rossi` | `person-… person-…` | yes |
| cloud id / UUID | `6f0c9a7e-…` | `cloud-g2xiyb2gkiq5` | yes |
| SID | `S-1-5-21-…` | `S-1-5-21-…` (synthetic) | yes |
| opaque id | (base64 / hex id) | `id-…` | yes |
| **secret** | `password=Estate2024!` | `secret-…` | **no** (never vaulted) |
| **client name** | `Acme Spa` | `CLIENT-…` | **no** (never vaulted) |
| **elided** | (unclassified, Safe mode) | `[ELIDED]` | **no** |

Synthetic IPv4 uses the benchmarking ranges `198.18.0.0/15` (RFC 2544/6890) so it cannot be confused with real production or private addresses; `198.18/16` marks internal sources and `198.19/16` external. Synthetic IPv6 uses `fd00::/8` (unique-local). Synthetic MACs use the locally-administered `02:…` prefix.

---

## 10. Vendor kits

A kit is a YAML file that maps a vendor's field names to kinds and actions. Detection is by fingerprint fields plus header hints; the highest-scoring kit wins, subject to a minimum confidence.

**Built-in kits (21):** Acronis, AWS CloudTrail, Bitdefender, Cisco Secure Endpoint, Cortex (Palo Alto XDR / XSIAM / XSOAR), CrowdStrike, Darktrace, Elastic ECS, Exabeam (New-Scale CIM 2.0 / Advanced Analytics / Data Lake), Fortinet, Microsoft Defender, Microsoft Entra, Microsoft Sentinel, Okta, Proofpoint, SentinelOne, Sophos, Splunk CIM, Trend Vision One, Wazuh, Zscaler.

**Rule structure.** Each rule has a `pattern` (a regex matched against the field name) plus an `action` and, for `mask`, a `kind`:

```yaml
- pattern: ^(dest|src)_user_(sid|dn|ou|entity_id)$
  action: mask
  kind: user
- pattern: ^action_evtlog_event_id$
  action: keep
- pattern: ^(message|raw_log|description)$
  action: text
```

Rules are evaluated top to bottom; specific rules must precede generic catch-alls (a field like `action_evtlog_event_id` must be kept *before* the generic `.*_id$` rule would mask it).

**User kits.** Files in `data/kits/*.yaml` are loaded on top of the built-ins with hot reload and take priority. Use the kit studio to open a built-in kit as a copy, edit, validate, and dry-run it against a header before saving.

**Coverage is measured, not assumed.** The Exabeam kit, for example, is built on the 1165 field names published in the official `ExabeamLabs/CIMLibrary` repository; a regression test verifies that no field whose name denotes an identity is left readable, while operational fields stay readable.

**No kit may keep unknown fields in the clear.** A vendor kit rule is tagged `vendor:`, and Safe mode deliberately does not re-elide vendor-classified fields — so a catch-all `.* → keep` at the end of a kit would keep *every* unrecognized field readable, defeating fail-closed. A class-wide regression test forbids a `.* → keep` (and a `.* → mask` with a non-masking kind) in any kit. Where a kit needs a catch-all for a field-dense vendor, it uses `.* → text`, which processes unknown values as free text — masking any identity inside them (IP, e-mail, host, `DOMAIN\user`, person or client name) while leaving operational content readable. Every kit must classify users and IPs, and hosts too except for vendors that have no host concept (Proofpoint, AWS CloudTrail, Okta, Entra), which are listed explicitly so an exception is a decision, not an oversight.

---

## 11. DLP categories and Safe mode

Independently of vendor kits, a DLP scan finds high-confidence sensitive values anywhere in the output — including inside free text. Each category has a default action and can be overridden per request.

| Category | Kind | Default |
|---|---|---|
| `credentials` | secret | redact |
| `private_key` | secret | redact |
| `tax_id` | taxid | pseudonymize |
| `iban` | iban | pseudonymize |
| `phone` | phone | pseudonymize |
| `person_name` | person | pseudonymize |
| `address` | address | pseudonymize |
| `vat_id` | vat | pseudonymize |
| `cloud_id` | cloud | pseudonymize |
| `sensitive_url` | secret | redact |

Actions: `pseudonymize` (reversible token), `redact` (`[ELIDED]`, irreversible), `block` (fail the output), `keep` (leave in the clear).

**Safe mode** is the fail-closed switch. With Safe mode on, any populated field that no kit and no heuristic could classify is elided. The rationale is that an unclassified field is exactly where an unexpected identifier hides; passing it through in the clear would be the one place a leak slips out.

**Documents and mail never elide.** On the `.docx`, `.pst` and `.pdf` paths, eliding a field is a net loss — the returned file loses text and restore cannot rebuild it. On those paths every sensitive value becomes a pseudonym instead of `[ELIDED]`. Secrets are the one exception on those paths: they become a deterministic `secret-…` token that is never written to the vault, so the document stays readable but the secret is not recoverable and the tool never becomes a store of clients' passwords.

### Untracked-field overrides

Fields that no kit classifies are elided in Safe mode. To change how a specific field is treated without writing a kit rule, the report shows each untracked field with a dropdown offering three choices, and a **Save missing-field config** button:

- **keep** — leave the value readable (operational metadata, IOCs);
- **pseudonymize** — reversible `id-…` token (always the generic `opaque` kind, which masks any value; a typed kind such as `ipv4` is deliberately not offered because it would return non-conforming values unchanged — a leak);
- **elide** — `[ELIDED]`.

The choices are stored globally by field name in `data/field_overrides.json` (hot reload) and apply to every format — CSV, JSON/NDJSON, CEF, LEEF, syslog — because they are resolved before vendor detection. They are independent of the detected vendor, since untracked fields usually appear precisely when no kit matched. Overrides win over kits, catalog and heuristics, but a field with no override still elides in Safe mode: fail-closed is preserved. Saving requires the `admin` permission, like other configuration changes. Since 0.27.0 `redact` is also a valid kit action, so a user kit can force elision of a field too.

---

## 12. API reference

All endpoints are under `/api`. Session is a cookie; state-changing requests require the CSRF token (double-submit: the `logmask_csrf` cookie value echoed in the `X-CSRF-Token` header). Every request is authorized by role and, where relevant, by tenant.

### Authentication

| Method | Path | Permission | Purpose |
|---|---|---|---|
| POST | `/api/login` | — | Log in; returns session + CSRF cookies |
| GET | `/api/me` | session | Current user, roles, capabilities |
| POST | `/api/logout` | session | End session |
| POST | `/api/change-password` | session | Change own password |

### Anonymize / restore

| Method | Path | Permission | Purpose |
|---|---|---|---|
| POST | `/api/anonymize` | anonymize | Text / CSV / structured input (JSON body) |
| POST | `/api/anonymize-docx` | anonymize | Word document (multipart) |
| POST | `/api/anonymize-pst` | anonymize | Outlook archive (multipart) |
| POST | `/api/anonymize-pdf` | anonymize | PDF (multipart; `output=pdf\|text`) |
| POST | `/api/deanonymize` | reverse | Restore text / structured / CSV |
| POST | `/api/deanonymize-docx` | reverse | Restore a masked `.docx` |
| POST | `/api/deanonymize-pdf` | reverse | Restore a masked PDF |

### Kits and policy

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/api/vendor-kits` | session | List installed kits |
| POST | `/api/kit-dry-run` | session | Classify a header without processing values |
| GET | `/api/kits/files` | admin | List user kit files |
| GET | `/api/kits/files/{name}` | admin | Read a user kit |
| PUT | `/api/kits/files/{name}` | admin | Create/update a user kit (validated) |
| DELETE | `/api/kits/files/{name}` | admin | Delete a user kit |
| POST | `/api/kits/validate` | admin | Validate kit YAML |
| GET | `/api/kits/bundled/{kit_id}` | admin | Read a built-in kit |
| GET | `/api/dlp-categories` | session | DLP category catalog |
| GET | `/api/field-overrides` | session | Current per-field overrides |
| POST | `/api/field-overrides` | admin | Save per-field overrides (keep/mask/redact) |
| GET | `/api/workflow-profiles` | session | Workflow presets |

### Reporting and admin

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/api/tenants` | session | Tenants the user may access |
| GET | `/api/fields` | reports | Field-level statistics |
| GET | `/api/stats` | reports | Vault statistics |
| GET | `/api/admin/users` | admin | List users |
| POST | `/api/admin/users` | admin | Create a user |
| POST | `/api/admin/vault/reset` | admin | Archive-and-reset a tenant vault |
| POST | `/api/admin/secret/reset` | admin | Regenerate the master key (archives key + all vaults) |
| GET | `/api/admin/audit` | audit | Audit log |

### Example — anonymize text

```bash
curl -X POST http://localhost:8090/api/anonymize \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf>" \
  --cookie "logmask_session=<session>; logmask_csrf=<csrf>" \
  -d '{"tenant":"acme","text":"user=mrossi src=10.20.30.40","format":"auto",
       "safe_mode":true,"ip_mode":"all","url_mode":"all"}'
```

Errors are returned as JSON with a `detail` field and, for unexpected errors, an `error_type`; the full traceback stays in the container logs and is never exposed.

---

## 13. Security model

### Authentication and sessions

- **Passwords** are hashed with Argon2 (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`); minimum length 12; the username may not appear in the password.
- **Sessions** are cookies marked `HttpOnly` and `SameSite=strict`; set `LOGMASK_COOKIE_SECURE=true` behind HTTPS. Idle and absolute lifetimes are enforced.
- **CSRF** uses double-submit: a non-`HttpOnly` `logmask_csrf` cookie must be echoed in the `X-CSRF-Token` header on every state-changing request.
- **Login rate limiting**: after `LOGMASK_LOGIN_MAX_FAILURES` failures within the window, the account is locked for the window duration.
- **Bootstrap admin** must change its password on first login before any other action is permitted.

### Roles (RBAC)

| Role | Permissions |
|---|---|
| `operator` | anonymize |
| `analyst` | anonymize, reports |
| `reverser` | anonymize, reports, reverse |
| `admin` | anonymize, reports, reverse, admin, audit |

Restoration (`reverse`) is a distinct, higher privilege and every reversal is written to the audit log with user, tenant, IP and outcome.

### Tenant isolation

Tenant identifiers are validated by regex and canonicalized to a path-safe form (no `.`/`..` traversal), then authorized against the user's tenant scope. Vaults and derived keys are per tenant; a user can only operate on tenants they are granted.

### Cryptography

- A 32-byte master key stored with `0600` permissions.
- Per-tenant keys derived via HMAC.
- Original values encrypted with AES-GCM, one random 12-byte nonce per row.
- Blind indexes (keyed hashes) let the sweep look values up without decrypting the vault.

### Input hardening

- **Request and file size limits** (413 on exceed).
- **`.docx` zip-bomb guard**: a decompressed-size cap with a double check (declared sizes, then a read budget), because the zip index can lie. Verified: a 200 KB document that expands to hundreds of MB is rejected in milliseconds.
- **`.pst` extraction cap**: the extracted size is bounded; `readpst` runs with a timeout and closed stdin so a corrupt or password-protected archive cannot hang the worker.
- **PDF**: page-count cap; encrypted/corrupt PDFs are rejected with a clear message; the produced PDF is re-read and verified that no original value is still extractable before delivery.
- **XML entity expansion** (billion-laughs) is blocked by the parser.
- **CSV NUL bytes** are stripped rather than crashing the parser.
- **Content-Security-Policy** and `Cache-Control: no-store` headers are set; all dynamic DOM in the UI is inserted via `textContent`/escaping, not raw HTML.

### Residual considerations (operator responsibility)

- The default bind is `0.0.0.0` (LAN-reachable); set `LOGMASK_BIND=127.0.0.1` for host-only use.
- The container runs as root; the input caps above mitigate but do not eliminate this.
- `readpst` is third-party C code; the timeout and size cap bound its impact, not its internal vulnerabilities.
- `client_terms.txt` and `person_terms.txt` hold real identifying values and must be protected accordingly.

---

## 14. Operations and troubleshooting

### Vault reset

`Reset vault` (admin only) archives the tenant vault with a timestamp rather than deleting it. Because the vault is the only thing that makes past exports reversible, resetting means losing the mapping for everything already shared; archiving allows recovery if the reset was a mistake. Permanent deletion remains a deliberate, manual choice.

### Reset secret (master key)

`Reset secret` (admin only) regenerates the master key — the secret from which **all** tokens derive. A confirmation pop-up summarizes the risk and requires typing the word `RESET`. The effect is global and destructive to reversibility:

- every future token changes (the same value yields a different pseudonym, `secret-…` included);
- **every existing vault, of every tenant, stops being reversible**, because it was encrypted with the previous key.

As with the vault reset, nothing is deleted: the old key and all existing vaults are **archived** with a timestamp (`master-prereset-…key`, `vault-prereset-…db`) and are recoverable **only together** — restoring both puts you back. Users and sessions do not depend on the master key, so nobody is logged out, and the change takes effect live without a restart.

Use this to obtain a fresh, disconnected secret — for example after copying the folder to another machine, if you deliberately want the new deployment to produce different tokens. Conversely, to preserve continuity across machines, copy `data/master.key` (and the vaults) rather than resetting.

### Audit log

Every anonymize, reverse, field-override save and secret-reset operation is recorded with action, user, tenant, IP, and outcome (plus counts and, for failures, the exception type — never the log content). Use it to review who restored or reset what and when.

### Common situations

| Symptom | Likely cause / action |
|---|---|
| `PST anonymization failed: Failed to fetch` | The `.pst` was still open in Outlook; the file changed during upload. Close Outlook or work on a copy. LogMask reads the file into a stable copy before sending. |
| `il PDF è protetto da password` | Remove the PDF password (open and save a copy without protection) before anonymizing. |
| A field comes out in the clear | It was not classified by any kit; enable Safe mode, or add a user kit rule / a `keep_fields` entry, or run a kit dry-run to see the classification. |
| Everything is `[ELIDED]` | No vendor kit matched and Safe mode elided the unknown fields; force the correct kit or add a user kit. |
| Restore leaves some values as pseudonyms | Those tokens are irreversible by design (`CLIENT-…`, `secret-…`) or belong to a different tenant's vault. |
| It got slow | An earlier release had a vault-size-dependent sweep; current releases are vault-independent. Very large single tokens were a ReDoS vector fixed in 0.26.2. |

### Upgrading

Copy the new release over the project folder (or extract the release ZIP), then `docker compose down && docker compose build --no-cache && docker compose up -d`. Vaults and configuration under the data directory are preserved across upgrades.

---

## 15. Regulatory considerations (EU / Italy, AI use)

> **This section is informational, not legal advice.** It summarizes how LogMask relates to the EU and Italian legal framework as of 2026 so that you can make an informed assessment with your DPO or counsel. It is not a compliance opinion, and LogMask's authors are not your lawyers.

### 15.1 The central legal fact: pseudonymization is not anonymization

Under the GDPR (Regulation (EU) 2016/679), **pseudonymization** is defined in Article 4(5) as processing personal data so that it can no longer be attributed to a data subject without additional information kept separately. Crucially, **Recital 26 states that pseudonymized data which could be attributed to a natural person by the use of additional information is still personal data.** Anonymization, by contrast, is irreversible and — per Recital 26 — falls outside the GDPR.

LogMask performs pseudonymization. Therefore:

- **A LogMask-masked export is, in general, still personal data** under the GDPR, because the vault plus the tenant key is exactly the "additional information" that allows re-identification. Processing it (storing, sharing, sending to an AI service) still requires a legal basis and still triggers GDPR obligations.
- **The vault and master key are the "additional information"** that Article 4(5) requires be "kept separately and subject to technical and organizational measures." LogMask's per-tenant AES-GCM encryption, `0600` master key, RBAC and audit log are the kind of measures the article contemplates — but the *separation* (keeping the vault out of the recipient's hands) is an operational responsibility: never ship the vault together with a masked export.
- **The irreversible transformations behave differently.** Values that LogMask never stores — client names (`CLIENT-…`), secrets (`secret-…`) and elided fields (`[ELIDED]`) — are not reversible even by the vault holder, and for those specific values the export approaches anonymization. The rest remains pseudonymous.

The practical upshot: LogMask is a **data-minimization and risk-reduction control**, not a magic wand that removes data from GDPR scope. It substantially reduces the personal data exposed to a recipient and supports the minimization principle (Art. 5(1)(c)) and security-of-processing obligation (Art. 32), which is precisely its value.

### 15.2 Sending logs to an AI service

The specific use case LogMask targets — masking a log before sending it to an external LLM or AI assistant — sits inside two overlapping regimes.

**GDPR.** Sending a log to a third-party AI service is a processing operation and, if the provider is outside the EU/EEA, potentially a transfer. It needs a legal basis, a data-processing agreement with the provider, and adherence to the minimization principle. The Italian supervisory authority (**Garante per la protezione dei dati personali**) has repeatedly stressed the difficulty of applying minimization to generative-AI services and has taken enforcement action in this area (notably the ChatGPT case, concluded in December 2024 with a €15 million sanction; note that an Italian court later annulled the related measure, so the case law is still evolving). Pseudonymizing the log before it leaves your control is a direct, defensible way to honor minimization: the AI service sees `usr-4ozopszr`, not `mrossi`.

**EU AI Act (Regulation (EU) 2024/1689).** The AI Act applies progressively. Obligations for general-purpose AI models have applied since **2 August 2025**; a major milestone falls on **2 August 2026**, when transparency obligations (Art. 50, e.g. disclosing that a user is interacting with an AI system) and the sanctions regime for GPAI take effect (fines up to 3% of worldwide annual turnover or €15 million, whichever is higher). Timelines for some high-risk systems were subsequently deferred (to December 2027 and August 2028) by the "Digital Omnibus." LogMask itself is not an AI system and is not regulated by the AI Act; its relevance is that it is a control you can place *in front of* an AI system to reduce the personal data that system processes.

### 15.3 The Italian national AI law (Legge 132/2025)

Italy enacted its first organic AI law, **Law No. 132 of 23 September 2025** ("Provisions and delegations to the Government on artificial intelligence"), published in the Official Gazette on 25 September 2025 and **in force since 10 October 2025**. It is expressly coordinated with the EU AI Act and adds national-level direction. It designates two national authorities: the **Agency for Digital Italy (AgID)** for promotion and development, and the **National Cybersecurity Agency (ACN)** for supervision and security. For an organization using AI on data that may contain personal or security-sensitive information, the law reinforces principles of transparency, human oversight and security that a pre-processing control like LogMask helps operationalize.

### 15.4 What LogMask does and does not give you

**It helps you:** minimize the personal and client-identifying data exposed when a log is shared or sent to an AI service; keep a reversible, auditable mapping under your own control; demonstrate a concrete technical measure toward Art. 5(1)(c) minimization and Art. 32 security; and irreversibly remove the most sensitive items (client names, secrets).

**It does not, by itself:** make a masked export "anonymous" or remove it from GDPR scope (the vault makes it re-identifiable); provide a legal basis for processing or transfer; replace a DPA with an AI provider; or absolve you of a DPIA where one is required. Those remain organizational decisions.

**Operational guidance that follows from the above:**

1. **Never ship the vault with the export.** Separation is what keeps the pseudonymization meaningful under Art. 4(5).
2. **Protect the vault and master key** as the sensitive assets they are — they are the re-identification key.
3. **Prefer the more protective settings** when the recipient is external, especially an AI service: all IPs and URLs masked (the 0.26.1 defaults), Safe mode on, secrets and PII minimized. The "External AI analysis" workflow profile encodes this.
4. **Treat `client_terms.txt` / `person_terms.txt`** as confidential configuration.
5. **Keep the audit log** as evidence of who reversed what and when.

---

## 16. Extending LogMask

### Add or override a vendor kit

Create a YAML file in `data/kits/`. It is hot-reloaded and takes priority over the built-in of the same id. Use the kit studio to start from a built-in copy, then validate and dry-run before saving. Order specific rules before generic catch-alls, and prefer `keep` for operational fields and IOCs, `mask` (with a `kind`) for identities, and `text` for free-text fields.

### Add a DLP detector

DLP categories live in `dlp.py` with a label, description, default action, and kind. A new detector adds a regex to the residual scanner and, where the value should be reversible, a matching pseudonym builder kind in `logmask.py`. New categories are surfaced automatically in the UI DLP panel.

### Tune person / host / client detection

Populate the data files: `person_terms.txt` for real employees (masked even as a bare token), `host_terms.txt` for the tenant's host-name globs, `tenant_networks.txt` for public CIDRs that identify the client, `client_terms.txt` for client names. The bundled `data/persons/` lists drive generic name detection.

### Test discipline

Every behavioral change ships with a regression test; the suite is the specification of intended behavior, especially the guards (a masking that is too aggressive is treated as a bug on par with a leak). Run the full suite before building a release.

---

*LogMask 0.27.6 — technical documentation. For the change history see `CHANGELOG.md`.*
