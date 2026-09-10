# SentinelScan API (`sentinelscan-api`)

## Overview
`sentinelscan-api` is the backend API service for **SentinelScan**. Built with Fastify and TypeScript, it provides the core API foundation, environment configuration validation with Zod, PostgreSQL persistence using Prisma, identity and authentication, authorized target management, scan orchestration backed by a real OWASP ZAP integration, centralized logging and error handling, and container packaging.

> **Stage 4 Notice**: This repository currently implements the backend foundation (Stage 0), identity and authentication (Stage 1), target registration/management (Stage 2), scan orchestration (Stage 3), and **real OWASP ZAP execution (Stage 4)**. Creating a scan now actually crawls and active-scans the target through a ZAP daemon reachable over the internal Docker network — see [OWASP ZAP Integration](#owasp-zap-integration) below for the target-safety policy, scope enforcement, timeouts, cancellation, and concurrency model this relies on. What Stage 4 deliberately does **not** do: it does not persist findings (raw ZAP results are logged as a summary and discarded, not stored), does not normalize or correlate anything, and does not run any AI analysis. There is also no SentinelScan-native discovery engine or scanner yet — ZAP is the only scan engine. `User`, `Target` and `Scan` are still the only domain models; later stages will attach findings, AI analyses and reports to `Scan`.

---

## Technology Stack
- **Runtime**: Node.js v22 LTS
- **Framework**: Fastify 5
- **Language**: TypeScript (Strict mode enabled)
- **Database ORM**: Prisma 6 (configured for Neon PostgreSQL)
- **Validation**: Zod
- **Authentication**: `@fastify/jwt` + `@fastify/cookie` (HttpOnly session cookies)
- **Password Hashing**: bcrypt (`bcryptjs`)
- **OAuth / OIDC**: `@fastify/oauth2` + `google-auth-library`
- **Security Scanning Engine**: OWASP ZAP daemon (`ghcr.io/zaproxy/zaproxy`), driven via its JSON HTTP API — no ZAP client SDK dependency, just native `fetch`
- **IP range classification (SSRF policy)**: `ipaddr.js`
- **Testing**: Vitest
- **Linting**: ESLint
- **Containerization**: Docker (multi-stage)
- **CI/CD**: GitHub Actions (Primary CI), Jenkins

---

## Project Structure
```
sentinelscan-api/
├── prisma/
│   ├── migrations/           # Versioned SQL migrations
│   └── schema.prisma         # Datasource, generator, User, Target and Scan models
├── src/
│   ├── app.ts                # Fastify app factory with middleware & error handling
│   ├── config.ts             # Zod environment validation & startup check
│   ├── server.ts             # Server entrypoint with graceful shutdown
│   ├── db/
│   │   └── prisma.ts         # Lazy Prisma client singleton
│   ├── lib/
│   │   ├── email-service.ts    # Verification email delivery (development / Resend)
│   │   ├── email.ts            # Email normalization
│   │   ├── errors.ts           # AppError hierarchy with HTTP status codes
│   │   ├── password.ts         # bcrypt hashing / verification
│   │   ├── prisma-errors.ts    # Unique-constraint & foreign-key-constraint detection
│   │   ├── target-safety.ts    # SSRF policy: is this URL safe to hand to ZAP?
│   │   ├── url.ts              # Target URL validation, normalization & scope-regex builder
│   │   ├── validation.ts       # Zod → 400 ValidationError bridge
│   │   └── zap-client.ts       # ZapClient interface + HTTP implementation
│   ├── modules/
│   │   ├── auth/
│   │   │   ├── auth.routes.ts    # /auth/register, /login, /verify-email, /me, /logout, ...
│   │   │   ├── auth.schemas.ts   # Zod request schemas & password policy
│   │   │   ├── auth.service.ts   # Registration, login, verification, Google account resolution
│   │   │   └── google.routes.ts  # /auth/google, /auth/google/callback
│   │   ├── targets/
│   │   │   ├── target.routes.ts  # /targets CRUD + nested POST /:targetId/scans
│   │   │   ├── target.schemas.ts # Zod request schemas & URL normalization wiring
│   │   │   └── target.service.ts # Ownership-enforced create/list/get/update/delete
│   │   └── scans/
│   │       ├── scan.routes.ts        # GET /scans, GET /scans/:id, POST /scans/:id/cancel
│   │       ├── scan.schemas.ts       # Zod request schemas, list-query pagination
│   │       ├── scan.service.ts       # Lifecycle state machine, ownership-enforced operations
│   │       ├── scan-executor.ts      # ScanExecutor interface + inert NotImplementedScanExecutor
│   │       └── zap-scan-executor.ts  # The real Stage 4 executor: ZapClient-driven, mutex-serialized
│   ├── plugins/
│   │   └── authentication.ts # JWT + cookie session, `authenticate` preHandler
│   ├── repositories/
│   │   ├── user.repository.ts          # UserRepository interface & PublicUser
│   │   ├── prisma-user.repository.ts   # Prisma implementation
│   │   ├── token.repository.ts         # Email verification token repository
│   │   ├── target.repository.ts        # TargetRepository interface & PublicTarget
│   │   ├── prisma-target.repository.ts # Prisma implementation (ownership-scoped queries)
│   │   ├── scan.repository.ts          # ScanRepository interface & PublicScan
│   │   └── prisma-scan.repository.ts   # Prisma implementation (atomic CAS transitions)
│   ├── routes/
│   │   └── health.ts         # GET /health, GET /health/zap
│   └── types/
│       └── fastify.d.ts      # Fastify/JWT type augmentation
├── tests/
│   ├── helpers/
│   │   ├── in-memory-user.repository.ts   # Database-free User/token/email test doubles
│   │   ├── in-memory-target.repository.ts # Database-free TargetRepository for tests
│   │   ├── in-memory-scan.repository.ts   # Database-free ScanRepository (reproduces CAS semantics)
│   │   ├── fake-zap-client.ts             # Scriptable ZapClient test double (no real HTTP)
│   │   └── fake-scan-executor.ts          # No-op ScanExecutor so orchestration tests don't touch ZAP
│   ├── auth.test.ts              # Registration, verification, login, session, logout tests
│   ├── google-auth.test.ts       # Google identity & unconfigured-provider tests
│   ├── targets.test.ts           # Target CRUD, ownership isolation, validation tests
│   ├── scans.test.ts             # Scan orchestration, lifecycle, ownership isolation tests
│   ├── target-safety.test.ts     # SSRF policy: IP ranges, DNS resolution, DNS-rebinding awareness
│   ├── zap-client.test.ts        # HttpZapClient against a mocked fetch
│   ├── zap-scan-executor.test.ts # Full execution lifecycle against a fake ZapClient
│   └── health.test.ts            # /health and /health/zap tests
├── .dockerignore
├── .env.example
├── .gitignore
├── Dockerfile                # Multi-stage production build
├── eslint.config.js
├── Jenkinsfile               # Declarative CI pipeline
├── package.json
├── README.md
├── tsconfig.json             # Strict TypeScript configuration
└── vitest.config.ts
```

---

## Prerequisites
- **Node.js**: v20.x or v22.x LTS (v24 compatible)
- **npm**: v10.x or higher
- **Docker**: v24+ (optional for containerized runtime)

---

## Environment Variables
Create a local `.env` file by copying the template:

```bash
cp .env.example .env
```

### Supported Variables
| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `PORT` | Listening port for the API server | `4000` |
| `DATABASE_URL` | Neon PostgreSQL database connection string | `postgresql://user:pass@ep-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require` |
| `JWT_SECRET` | **Required.** Signing key for session JWTs, minimum 32 characters | *(no default — generate one)* |
| `JWT_EXPIRES_IN` | Session token lifetime, in `jsonwebtoken` duration syntax | `1d` |
| `AUTH_COOKIE_NAME` | Name of the HttpOnly session cookie | `sentinelscan_token` |
| `WEB_APP_URL` | Browser origin of the web app; CORS allowlist and post-OAuth redirect target | `http://localhost:3000` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 client ID *(optional, must be set with the two below)* | *(unset)* |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 client secret *(optional)* | *(unset)* |
| `GOOGLE_CALLBACK_URL` | Authorized redirect URI registered with Google *(optional)* | `http://localhost:4000/auth/google/callback` |
| `EMAIL_PROVIDER` | `development` (logs the link) or `resend` (real delivery) | `development` |
| `EMAIL_FROM` | From address used for outgoing verification email | `SentinelScan <noreply@sentinelscan.io>` |
| `RESEND_API_KEY` | Resend API key *(required only when `EMAIL_PROVIDER=resend`)* | *(unset)* |
| `ZAP_BASE_URL` | **Required.** Base URL of the ZAP daemon's JSON API | `http://owasp-zap:8090` in Docker; `http://localhost:8090` locally |
| `ZAP_API_KEY` | ZAP API key *(optional — only if ZAP's own API-key auth is enabled)* | *(unset)* |
| `ZAP_HTTP_TIMEOUT_MS` | Per-HTTP-call timeout against ZAP | `10000` |
| `ZAP_CRAWL_TIMEOUT_MS` | Ceiling on the spider phase | `300000` (5 min) |
| `ZAP_ACTIVE_SCAN_TIMEOUT_MS` | Ceiling on the active-scan phase | `1800000` (30 min) |
| `ZAP_OVERALL_SCAN_TIMEOUT_MS` | Ceiling across the whole execution, independent of the two phase timeouts | `2400000` (40 min) |
| `ZAP_POLL_INTERVAL_MS` | How often the executor polls ZAP for spider/active-scan progress | `2000` |

Generate a signing key with:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

The three `GOOGLE_*` variables must be supplied together or omitted together; a partial set fails startup validation. See [Google OAuth / OIDC](#google-oauth--oidc) for the deferred setup steps.

> **Security Rule**: Environment variables are strictly validated on startup using Zod. If required variables are missing, the server fails fast with clear errors while never leaking secrets or connection strings in logs. No credential is ever hardcoded, and `.env` is git-ignored.

---

## Installation & Local Development

1. **Clone the repository**:
   ```bash
   git clone <repository-url> sentinelscan-api
   cd sentinelscan-api
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Generate Prisma client**:
   ```bash
   npm run prisma:generate
   ```

   Apply the schema to your database (creates the `users` table; additive, no data loss):
   ```bash
   npm run prisma:deploy
   ```
   Use `npm run prisma:migrate` instead when authoring a new migration during development.

4. **Run tests**:
   ```bash
   npm test
   ```

5. **Lint and typecheck**:
   ```bash
   npm run lint
   npm run typecheck
   ```

6. **Start development server**:
   ```bash
   npm run dev
   ```

7. **Verify health endpoint**:
   ```bash
   curl http://localhost:4000/health
   # Response: {"status":"ok"}
   ```

8. **Build and run production server**:
   ```bash
   npm run build
   npm start
   ```

---

## Data Model

### `User` (table `users`)

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `email` | `String` | Unique; always stored trimmed and lower-cased |
| `name` | `String` | Display name |
| `passwordHash` | `String?` | bcrypt hash; `null` for Google-only accounts |
| `googleId` | `String?` | Unique Google `sub` claim; `null` until a Google identity is linked |
| `emailVerified` | `Boolean` | `true` once the account's email address has been confirmed |
| `lastLoginAt` | `DateTime?` | Updated on every successful sign-in |
| `createdAt` | `DateTime` | Account creation timestamp |
| `updatedAt` | `DateTime` | Auto-maintained update timestamp |

Nullable `passwordHash` is what lets an email/password user and a Google user share one model.

### `Target` (table `targets`)

An authorized web application a user has registered for future security assessment. Stage 2 is registration and management only — creating or updating a `Target` never makes a network request to its `url`, resolves DNS, crawls it, or invokes any scanner.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `ownerId` | `String` | Foreign key to `User.id`, `onDelete: Cascade`; always derived from the authenticated session, never from client input |
| `name` | `String` | 1–120 characters |
| `url` | `String` | Absolute `http(s)` URL, normalized on write (see [Target validation](#target-validation)) |
| `description` | `String?` | Up to 1000 characters |
| `status` | `TargetStatus` | `"active"` (default) or `"inactive"` |
| `createdAt` | `DateTime` | Registration timestamp |
| `updatedAt` | `DateTime` | Auto-maintained update timestamp |

Indexed on `ownerId` for the "list my targets" query, with a unique constraint on `(ownerId, url)`: one user cannot register the same URL twice, but two different users can each register the same URL — e.g. a shared staging environment both are separately authorized to test.

A target with scan history (any `Scan` row referencing it) **cannot be deleted** — `DELETE /targets/:id` returns `409 TARGET_HAS_SCANS`. See `Scan`'s delete-behavior note below for why.

### `Scan` (table `scans`)

One requested (or completed, failed, cancelled) execution of a security assessment against a `Target`. **Stage 3 is orchestration and persistence only** — creating a `Scan` never makes a network request, resolves DNS, crawls, or invokes OWASP ZAP or any other scanner. See [Scan lifecycle](#scan-lifecycle) for exactly what does and does not happen to a scan's `status` in this stage.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `targetId` | `String` | Foreign key to `Target.id`, `onDelete: Restrict` |
| `requestedById` | `String` | Foreign key to `User.id`, `onDelete: Restrict`; always derived from the authenticated session, never from client input |
| `status` | `ScanStatus` | `"queued"` (default) · `"running"` · `"completed"` · `"failed"` · `"cancelled"` |
| `startedAt` | `DateTime?` | Set when the scan transitions to `running`; `null` until then |
| `completedAt` | `DateTime?` | Set when the scan reaches any terminal state (`completed`/`failed`/`cancelled`) |
| `errorMessage` | `String?` | Set when a scan fails; otherwise `null` |
| `createdAt` | `DateTime` | When the scan was requested |
| `updatedAt` | `DateTime` | Auto-maintained update timestamp |

Indexed on `targetId`, `requestedById`, and `status` individually, plus a composite `(requestedById, createdAt)` index supporting the actual "my scans, newest first" query `GET /scans` runs.

**Delete behavior — deliberately `Restrict` on both foreign keys, not `Cascade`:** a `Scan` is the historical record of an assessment that was requested (and possibly ran), so cascading it away whenever its `Target` or requesting `User` is deleted would silently destroy that audit trail. A target with any scan history cannot be deleted (`409 TARGET_HAS_SCANS`) until an explicit archival/retention story exists in a later stage. There is no account-deletion endpoint anywhere in this codebase yet, so the `requestedById` side of this cannot currently be exercised through the API — it is set deliberately rather than left to a default, so that whenever account deletion is built, deleting a user with scan history fails loudly instead of silently erasing who requested what.

Later stages will hang `Finding → AiAnalysis → Report` off `Scan`; none of those models exist yet.

Persistence for all three models is reached through a repository interface (`UserRepository`, `TargetRepository`, `ScanRepository`) rather than Prisma directly, so route handlers stay database-agnostic and the test suite can run against an in-memory implementation with no PostgreSQL instance. `ScanRepository`'s status-transition method is a compare-and-swap (`UPDATE ... WHERE status = $expected`, via Prisma's `updateMany`), which is what makes two simultaneous requests to cancel (or otherwise transition) the same scan resolve safely — see [Scan lifecycle](#scan-lifecycle).

---

## Authentication

### Mechanism

Sessions are **stateless JWTs delivered in an HttpOnly cookie**.

- The token is signed with `JWT_SECRET` (HS256) and expires after `JWT_EXPIRES_IN`. Both come from the environment; neither is hardcoded.
- The cookie is `HttpOnly` (unreachable from client-side JavaScript, so an XSS bug cannot exfiltrate a session), `SameSite=Lax`, `Path=/`, and `Secure` whenever `NODE_ENV=production`.
- An `Authorization: Bearer <token>` header is also accepted, so non-browser clients (CI, future CLI tooling) can authenticate without a cookie jar. The header takes precedence when both are present.
- Because CORS must allow credentialed requests, the allowed origin is the explicit `WEB_APP_URL` rather than a wildcard.

This was chosen over server-side sessions because it needs no Redis or session table — no extra infrastructure — while still keeping the token out of JavaScript's reach. Every authenticated request re-reads the user from the database, so a deleted or changed account stops being usable before its token expires.

### Protecting a route

`fastify.authenticate` is a reusable preHandler. It rejects unauthenticated requests and populates `request.currentUser`:

```ts
fastify.get("/targets", { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const user = request.currentUser;   // UserRecord
  // ...
});
```

Or, for a whole route group like `/targets` where every route needs it, once per plugin:

```ts
fastify.addHook("preHandler", fastify.authenticate);
```

Authentication (who you are) is deliberately kept separate from authorization (what you may touch). There is still no role-based access control — `Target` ownership is enforced by scoping every query to `request.currentUser.id`, not by a permissions/roles system.

---

## API Reference

All request and response bodies are JSON. Password hashes and signing secrets are never present in any response.

### `GET /health`

Liveness probe. Returns `200 {"status":"ok"}`.

### `GET /health/zap`

Application-level ZAP connectivity check — not a proxy for ZAP's own administration API, which is never exposed through this API. Public, unauthenticated, matching `/health`.

- `200` — `{ "reachable": true, "version": "2.14.0" }`
- `503` — `{ "reachable": false, "error": "..." }` — a safe, non-sensitive description of the failure; never an API key, and never ZAP's raw response

### `POST /auth/register`

Creates a local email/password account.

```json
{ "email": "analyst@example.com", "name": "Security Analyst", "password": "Str0ngPassphrase" }
```

Password policy: 10–128 characters, with at least one lowercase letter, one uppercase letter and one digit.

- `201` — `{ "user": { ... }, "message": "Registration successful. Please check your email to verify your account." }`
- `400` `VALIDATION_ERROR` — invalid body, email or password (with per-field `details`)
- `409` `EMAIL_ALREADY_REGISTERED` — the email is already in use

Registration does **not** start a session and sets `emailVerified: false`. A verification email containing a single-use token link (`/verify-email?token=<token>`) is dispatched.

### `POST /auth/verify-email`

Verifies an account using the token sent via email.

```json
{ "token": "a1b2c3d4e5..." }
```

- `200` — `{ "user": { ... }, "message": "Email verified successfully." }` plus session cookie
- `400` `INVALID_TOKEN` — token not found
- `400` `TOKEN_EXPIRED` — token has expired (lifetime: 24h)
- `400` `TOKEN_ALREADY_USED` — token has already been redeemed

Upon success, sets `emailVerified: true` and automatically issues an authenticated session cookie.

### `POST /auth/resend-verification`

Resends the verification email for an unverified account.

```json
{ "email": "analyst@example.com" }
```

- `200` — `{ "message": "If an unverified account with that email exists, a verification link has been sent." }`
- `429` `RATE_LIMITED` — resend requested within the 60-second cooldown window

Always returns a generic `200` response for unknown or already-verified emails to prevent email enumeration.

### `POST /auth/login`

```json
{ "email": "analyst@example.com", "password": "Str0ngPassphrase" }
```

- `200` — `{ "user": { ... } }` plus a `Set-Cookie` carrying the session token (for verified accounts)
- `400` `VALIDATION_ERROR` — malformed body
- `401` `INVALID_CREDENTIALS` — wrong password, unknown email, or a Google-only account
- `403` `EMAIL_NOT_VERIFIED` — valid password, but email verification is pending

The `401` response and its timing are identical for wrong passwords and unknown emails, so login never discloses whether an unregistered email exists. Only when the correct password is submitted for an unverified account does `403 EMAIL_NOT_VERIFIED` guide the user to verify.

### `GET /auth/me`

Requires authentication.

- `200` — `{ "user": { ... } }`
- `401` `UNAUTHORIZED` — no credentials presented
- `401` `INVALID_TOKEN` — malformed, tampered, or orphaned token
- `401` `TOKEN_EXPIRED` — the session has expired

### `POST /auth/logout`

Clears the session cookie. Public and idempotent, so it succeeds even with an expired or absent session.

- `200` — `{ "success": true }`

### `GET /auth/google`

Starts the Google authorization-code flow by redirecting to Google.

- `302` — redirect to Google's consent screen
- `503` `GOOGLE_OAUTH_NOT_CONFIGURED` — the `GOOGLE_*` variables are unset

### `GET /auth/google/callback`

Google's redirect target. Exchanges the code, verifies the ID token, signs the user in and sets the session cookie.

- `302` — redirect to `WEB_APP_URL` (or `200 { "user": { ... } }` when the request sends `Accept: application/json`)
- `401` `GOOGLE_AUTH_FAILED` / `GOOGLE_EMAIL_UNVERIFIED` — the identity could not be verified
- `503` `GOOGLE_OAUTH_NOT_CONFIGURED` — the `GOOGLE_*` variables are unset

### Safe user representation

Every endpoint that returns a user returns exactly this shape:

```json
{
  "id": "0f5b...",
  "email": "analyst@example.com",
  "name": "Security Analyst",
  "emailVerified": false,
  "hasPassword": true,
  "googleLinked": false,
  "createdAt": "2026-09-09T10:00:00.000Z",
  "updatedAt": "2026-09-09T10:00:00.000Z"
}
```

Callers learn *whether* a credential exists, never what it is.

### Targets

Every `/targets` route requires authentication (the same session cookie / bearer token as everything else) and is scoped entirely to `request.currentUser.id`: the owner is always derived from the session, never accepted from the request body, and a target belonging to another user is treated identically to a target that does not exist. None of these endpoints make a network request to the target's `url` — no crawling, scanning, or DNS resolution happens anywhere in this codebase.

#### `POST /targets`

```json
{ "name": "Acme Staging", "url": "https://staging.acme.example.com/app", "description": "Pre-production, authorized for testing." }
```

- `201` — `{ "target": { ... } }`
- `400` `VALIDATION_ERROR` — missing/blank name, or `url` is not an absolute `http://`/`https://` address (a `javascript:`, `file:`, `data:`, relative, bare-hostname, or credentialed URL is rejected, not "handled")
- `409` `TARGET_ALREADY_EXISTS` — this user has already registered this exact (normalized) URL

`status` always starts `"active"`; it cannot be set on creation, only via `PATCH`.

#### `GET /targets`

- `200` — `{ "targets": [ { ... }, ... ] }`, newest first, containing only targets owned by the caller

#### `GET /targets/:id`

- `200` — `{ "target": { ... } }`
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `404` `TARGET_NOT_FOUND` — no such target, *or* it belongs to a different user

#### `PATCH /targets/:id`

Any subset of `name`, `url`, `description`, `status`. Omitted fields are left unchanged; `description` explicitly set to `null` clears it (as opposed to omitting it, which leaves it as-is).

```json
{ "status": "inactive" }
```

- `200` — `{ "target": { ... } }`
- `400` `VALIDATION_ERROR` — an included field fails its own rule (same URL/name rules as creation; `status` must be `"active"` or `"inactive"`)
- `404` `TARGET_NOT_FOUND` — no such target, *or* it belongs to a different user
- `409` `TARGET_ALREADY_EXISTS` — the new `url` collides with another of this user's targets

#### `DELETE /targets/:id`

- `204` — no body
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `404` `TARGET_NOT_FOUND` — no such target, *or* it belongs to a different user
- `409` `TARGET_HAS_SCANS` — this target has scan history and cannot be deleted (Stage 3; see the `Scan` delete-behavior note in [Data Model](#scan-table-scans))

#### `POST /targets/:targetId/scans`

Creates a scan for this target. See [Scans](#scans) below — this is the scan-creation endpoint, nested here because it is fundamentally "create a scan *for this target*" and reuses this module's own ownership-scoped target lookup.

- `201` — `{ "scan": { ... } }`, `status: "queued"`
- `400` `VALIDATION_ERROR` — `:targetId` is not a well-formed UUID
- `404` `TARGET_NOT_FOUND` — no such target, *or* it belongs to a different user
- `409` `TARGET_NOT_ACTIVE` — the target's `status` is `"inactive"`

#### Safe target representation

```json
{
  "id": "6f1e...",
  "name": "Acme Staging",
  "url": "https://staging.acme.example.com/app",
  "description": "Pre-production, authorized for testing.",
  "status": "active",
  "createdAt": "2026-09-10T09:00:00.000Z",
  "updatedAt": "2026-09-10T09:00:00.000Z"
}
```

`ownerId` is never included — the caller already knows every target returned here is theirs.

#### Target validation

- **Name**: required, trimmed, 1–120 characters.
- **URL**: required, 1–2048 characters before normalization, must parse as an absolute `http:`/`https:` URL with no embedded username/password. Normalized via the WHATWG `URL` parser's own serialization (`new URL(input).href`) — lower-cased scheme/host, default ports dropped, root path filled in — so the same target registered twice in a different-but-equivalent form is recognized as a duplicate.
- **Description**: optional, up to 1000 characters.
- **Status**: `"active"` or `"inactive"` only.

### Scans

`POST /targets/:targetId/scans` persists a `Scan` row with `status: "queued"` and returns immediately (it does not wait for the scan to run — see [OWASP ZAP Integration](#owasp-zap-integration)). Execution then happens in the background: the target is checked against the SSRF/target-safety policy, a scan-scoped ZAP context is created, the target is crawled, then active-scanned, and the scan reaches a terminal state. Nothing here builds a findings database, normalizes results, or runs AI analysis — see [OWASP ZAP Integration](#owasp-zap-integration) for exactly what Stage 4 does and does not do.

Every `/scans` route requires authentication and is scoped entirely to `request.currentUser.id` as the *requester* — the same non-enumerable-404 rule as targets applies: a scan belonging to another user is indistinguishable from one that does not exist.

#### Scan lifecycle

```
queued ──┬──> running ──┬──> completed
         │              ├──> failed
         └──> cancelled ┴──> cancelled
```

| From | May transition to |
| :--- | :--- |
| `queued` | `running`, `cancelled` |
| `running` | `completed`, `failed`, `cancelled` |
| `completed` / `failed` / `cancelled` | *(terminal — nothing)* |

This table (`VALID_TRANSITIONS` in `scan.service.ts`) is the single source of truth for every transition check in this codebase; there is no second, separately-maintained list anywhere else. Every transition is applied as an atomic compare-and-swap (`UPDATE ... WHERE status = $expected`) at the database layer, not just checked in application code — so two simultaneous requests to transition the same scan (e.g. two `POST /scans/:id/cancel` calls racing each other) can never both succeed: exactly one wins, the other receives a clean `409 INVALID_SCAN_TRANSITION` rather than a corrupted or double-applied state.

`queued → running`, `running → completed`, and `running → failed` are **not reachable through any HTTP endpoint** — they exist as internal functions in `scan.service.ts` (`startScan`, `completeScan`, `failScan`) that only `ZapScanExecutor` calls, as a real scan actually progresses. `POST /scans/:id/cancel` (below) is the only user-facing transition, and it only ever moves a scan into `cancelled`.

#### `GET /scans`

Query parameters (all optional):

| Parameter | Notes |
| :--- | :--- |
| `status` | One of `queued`, `running`, `completed`, `failed`, `cancelled` |
| `targetId` | Must be a well-formed UUID |
| `limit` | 1–100, default 20 |
| `offset` | ≥ 0, default 0 |

There is no established pagination convention elsewhere in this API (`GET /targets` returns everything unpaged), so this is a plain, unopinionated `limit`/`offset` scheme rather than an attempt to match a precedent that doesn't exist.

- `200` — `{ "scans": [ { ... }, ... ], "limit": 20, "offset": 0, "hasMore": false }`, newest first, containing only scans requested by the caller
- `400` `VALIDATION_ERROR` — an invalid filter value, or `limit`/`offset` out of range

#### `GET /scans/:id`

- `200` — `{ "scan": { ... } }`
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `404` `SCAN_NOT_FOUND` — no such scan, *or* it was requested by a different user

#### `POST /scans/:id/cancel`

Valid only from `queued` or `running`. If the scan had already started, `startedAt` is left untouched (cancelling does not rewrite history); `completedAt` is set either way, since `cancelled` is terminal. No scanner-result fields are set — there is nothing to fabricate.

- `200` — `{ "scan": { ... } }`, `status: "cancelled"`
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `404` `SCAN_NOT_FOUND` — no such scan, *or* it was requested by a different user
- `409` `INVALID_SCAN_TRANSITION` — the scan is already `completed`, `failed`, or `cancelled`

#### Safe scan representation

```json
{
  "id": "9c2a...",
  "targetId": "6f1e...",
  "status": "queued",
  "startedAt": null,
  "completedAt": null,
  "errorMessage": null,
  "createdAt": "2026-09-11T10:00:00.000Z",
  "updatedAt": "2026-09-11T10:00:00.000Z"
}
```

`requestedById` is never included — the caller already knows every scan returned here is theirs.

### Error format

```json
{
  "statusCode": 400,
  "error": "ValidationError",
  "code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "details": [{ "field": "email", "message": "Email must be a valid email address" }]
}
```

`code` is the stable, machine-readable identifier. Unexpected failures are reported as a generic `500 Internal Server Error` so internal details never leak.

---

## Google OAuth / OIDC

The provider boundary is fully implemented — authorization-code flow via `@fastify/oauth2`, ID-token verification via `google-auth-library`, and account resolution — but it is **inactive until credentials are supplied**, because obtaining them requires a Google Cloud project that is not available in this environment or in CI.

To activate it:

1. In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials), create an **OAuth client ID** of type *Web application*.
2. Add `http://localhost:4000/auth/google/callback` (and the deployed equivalent) as an **Authorized redirect URI**.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_CALLBACK_URL` in `.env`.
4. Restart the API. `/auth/google` now redirects to Google instead of returning `503`.

Account resolution avoids duplicates: a Google sign-in first matches on `googleId`, then on the verified email — in which case the Google identity is **linked** to the existing account rather than creating a second one. An unverified Google email is rejected outright, since accepting one would let an attacker claim someone else's address. Only the Google `sub`, email, display name and verification flag are stored; no Google access or refresh tokens are persisted.

Automated tests never contact Google: account resolution is exercised directly with a verified identity, and the HTTP routes are tested in their unconfigured `503` state.

---

## OWASP ZAP Integration

**Stage 4 wires a real ZAP daemon into scan execution.** This section covers the architecture, the SSRF/scope safety boundary, timeouts, cancellation, and concurrency model — and, just as importantly, what this stage deliberately does *not* do. There is no SentinelScan-native discovery engine or scanner (ZAP is the only scan engine so far), no finding normalization or correlation, and no AI analysis. Raw ZAP results are summarized (counts per risk level) for a log line and then discarded — nothing is persisted beyond the `Scan` row's own lifecycle fields.

### Architecture

```
Next.js  →  Fastify API  →  ScanExecutor (ZapScanExecutor)  →  ZapClient  →  OWASP ZAP daemon  →  authorized target
```

- **`ZapClient`** (`lib/zap-client.ts`) is a thin interface over ZAP's JSON HTTP API (`/JSON/<component>/<view|action>/<name>/`) — context management, spider, active scan, and an alert summary. Nothing outside this file constructs a ZAP request URL or parses a ZAP response body.
- **`ZapScanExecutor`** (`modules/scans/zap-scan-executor.ts`) is the real `ScanExecutor` implementation: target-safety check → scoped ZAP context → crawl → active scan → result summary → terminal state, calling `scan.service.ts`'s existing atomic lifecycle functions (`startScan`/`completeScan`/`failScan`) at each step. `NotImplementedScanExecutor` (`scan-executor.ts`) still exists and still throws rather than faking success — it simply is not the default anymore.
- The API talks to ZAP only over the internal Docker network (`ZAP_BASE_URL=http://owasp-zap:8090` in `docker-compose.yml`). ZAP's administration API port is never published to the host in that configuration — see [Docker](#docker) below.

### Triggering execution — in-process, non-blocking

`POST /targets/:targetId/scans` creates the `Scan` row and returns `201` immediately; it does not wait for the scan to run. `scan.service.ts`'s `createScan` fires `scanExecutor.execute(...)` in the background (`void executor.execute(...).catch(...)`) rather than awaiting it — a real crawl-plus-active-scan can run for the better part of an hour, and the HTTP request must not block for that.

This is an **in-process executor**: it runs inside the same Node process as the rest of the API, with no queue, worker process, or external job system. That is a deliberate, minimal choice suited to this stage and to a single-instance deployment — it is *not* durable across a process restart (a scan that was `running` when the process dies stays `running` forever unless something later reconciles it — nothing in this codebase does that yet) and it does not scale execution across multiple API instances. A durable job queue/worker (e.g. BullMQ, or a dedicated worker process) is the natural next step if and when the API needs to run horizontally — deliberately not introduced yet, per this stage's scope.

### Concurrency & isolation

ZAP is a single shared daemon process. Running two scans through it at the same time risks their spider state, active-scan state, session cookies, or scope bleeding into each other. Rather than pretend the current implementation isolates concurrent ZAP scans safely, `ZapScanExecutor` serializes them: an in-process mutex limits actual ZAP execution to **one scan at a time**, regardless of how many `POST /targets/:targetId/scans` requests arrive concurrently (each still returns `201` immediately; only the background execution is queued). Correctness over throughput, exactly as this stage calls for.

Within that single execution slot, each scan gets its own ZAP context named `sentinelscan-scan-<scanId>`, scoped to the target's origin (see below) and removed in a `finally` block once the scan reaches any terminal state — success, failure, or cancellation — so no scan-specific ZAP state (context, scope, spider/active-scan ids) survives to the next one.

### Target safety policy (SSRF)

Implemented in `lib/target-safety.ts`, and run **only at scan execution time** — never during target creation or update, which remain pure database operations with no network I/O of any kind. A target URL is rejected outright, before any ZAP call, when:

- it doesn't parse, or isn't `http:`/`https:`, or carries embedded credentials (the same rules Stage 2 already enforces at creation, re-checked here defensively);
- the hostname is `localhost` or `*.localhost`;
- the hostname (or, for a non-IP hostname, *every* address it resolves to — not just the first) does not classify as ordinary public "unicast" per [`ipaddr.js`](https://www.npmjs.com/package/ipaddr.js)'s range classification. This is an **allow-list, not a deny-list**: loopback, RFC1918 private ranges, link-local (which is what the `169.254.169.254` cloud metadata endpoint falls under — no special case needed), multicast, reserved/unspecified/broadcast, IPv6 unique-local, and IPv6 transition mechanisms that embed an IPv4 address (`ipv4Mapped`, `6to4`, `teredo` — exactly the kind of address that could otherwise smuggle a private IPv4 target past a naive check) are all rejected because they are not "unicast", not because someone enumerated them individually.

**What this cannot guarantee — DNS rebinding.** The address(es) validated here are not necessarily the address ZAP itself connects to: ZAP performs its own independent DNS resolution moments later, in a separate process. A hostname with a very short DNS TTL could legitimately resolve to a public address at check time and to a private address by the time ZAP connects. Closing that gap fully would require routing all of ZAP's outbound traffic through an address-filtering forward proxy (or sharing a resolver between this check and ZAP), which this stage deliberately does not introduce. This is therefore a strong, fail-closed filter against the common cases — literal private/loopback/link-local addresses, static malicious DNS records, IPv4-in-IPv6 smuggling — and an honest, *not* airtight, defense against an attacker who controls DNS specifically to rebind between this check and ZAP's connection.

### Scope policy — conservative same-origin

A `Target`'s authorized scope is exactly its normalized origin (scheme + hostname + effective port, via `URL.origin` — `buildOriginScopeRegex` in `lib/url.ts`). For `https://example.com`, that means `https://example.com/`, `https://example.com/login`, `https://example.com/api/users` are in scope; `https://evil-example.com`, `https://example.com.evil.com`, and `https://sub.example.com` (an unregistered subdomain) are not — scope is never silently broadened to a whole domain or its subdomains.

This regex is handed to ZAP's own `context.includeInContext` action, so scope is enforced by ZAP itself while spidering and active-scanning — not re-implemented by intercepting ZAP's traffic. That also means redirect handling is exactly whatever ZAP's own context-scoping does with out-of-scope redirect targets (it does not queue them for further spidering/scanning); this codebase does not separately inspect or block redirects. Spidering is scoped by `contextName`; the active scan is additionally scoped by `contextId` — scope is not left to the spider alone.

### Scan execution flow

```
queued
  → target-safety check (lib/target-safety.ts)
  → create scan-scoped ZAP context, set origin scope
  → spider (crawl) the target, polling until 100% or timeout
  → active scan the target, polling until 100% or timeout
  → collect a per-risk-level alert count (logged, not persisted)
  → completed
  → (finally) remove the ZAP context
```

A failure at any step — target-safety rejection, ZAP unreachable, a malformed ZAP response, a phase timeout — moves the scan to `failed` with a safe (never-raw) message in `Scan.errorMessage` via `failScan`, and still runs the context-removal cleanup. A scan is marked `completed` only when the active scan itself actually reached 100%, never earlier.

### Cancellation

`POST /scans/:id/cancel` (already implemented in Stage 3) is checked for by the executor at several points: before creating the ZAP context, before starting each phase, and on every poll iteration while a phase is in progress (roughly every `ZAP_POLL_INTERVAL_MS`). When a cancellation is observed mid-phase, the executor attempts to stop the corresponding ZAP operation (`spider/action/stop` or `ascan/action/stop`) **best-effort**: ZAP does not guarantee immediate termination, and a failure to stop it is logged and otherwise ignored, never escalated into a scan failure. The ZAP context is still removed in `finally` either way.

**The race this matters for**: ZAP finishing at the same moment a user cancels. Every lifecycle write goes through `scan.service.ts`'s existing atomic compare-and-swap (`UPDATE ... WHERE status = $expected`) — this executor never writes `Scan.status` directly. If `POST /scans/:id/cancel` wins that race, the executor's later `completeScan` call simply fails its own CAS (the row is no longer `running`) and is treated as "already terminal, nothing to do", not as an error — `cancelled` is never overwritten by a late `completed`.

### Timeouts

Four independent ceilings, all configurable (see [Environment Variables](#supported-variables)), none hardcoded: a per-HTTP-call timeout against ZAP (`ZAP_HTTP_TIMEOUT_MS`), a crawl-phase timeout (`ZAP_CRAWL_TIMEOUT_MS`), an active-scan-phase timeout (`ZAP_ACTIVE_SCAN_TIMEOUT_MS`), and an overall ceiling across the whole execution (`ZAP_OVERALL_SCAN_TIMEOUT_MS`), independent of the two phase timeouts. A scan can never run forever: exceeding any timeout is treated the same as a cancellation-triggered stop (best-effort ZAP stop, then `failed`).

### Logging

The executor logs (via `console.info`/`console.error`, the same convention `auth.service.ts` already uses for background side effects outside any Fastify request) execution start, crawl start/complete, active-scan start/complete, the result summary, and completion/failure/cancellation — each tagged with `scanId` and `targetId`. It never logs API keys, cookies, authorization headers, target credentials, or a raw ZAP response body; `ZapClient`'s own error messages are built from the request's endpoint name only, never the full URL (which may carry `apikey` as a query parameter).

### What is not implemented

No SentinelScan-native discovery/crawling engine — ZAP's own spider is the only crawler. No SentinelScan-native scanner — ZAP's active scan is the only scan engine. No finding normalization, deduplication, or correlation. No vulnerability database model (raw results are summarized for a log line and discarded, not persisted). No AI analysis. No queue/worker infrastructure (Redis, Kafka, RabbitMQ, BullMQ) — see "Triggering execution" above for what that means in practice.

---

## Docker

### Build the Image
```bash
docker build -t sentinelscan-api .
```

### Run the Container
```bash
docker run -p 4000:4000 \
  -e DATABASE_URL="postgresql://user:pass@ep-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require" \
  -e JWT_SECRET="<a long random value>" \
  -e ZAP_BASE_URL="http://owasp-zap:8090" \
  sentinelscan-api
```
This assumes `sentinelscan-api` and an `owasp-zap` container share a Docker network (see `docker-compose.yml` at the workspace root, which wires this up directly rather than needing manual flags).

---

## CI/CD Pipeline
GitHub Actions is the primary CI system for this repository (`.github/workflows/ci.yml`), automatically triggered on pushes and pull requests targeting the `main` branch. The repository also retains the declarative `Jenkinsfile` as an alternative CI pipeline.

### GitHub Actions (Primary CI)
The workflow runs on `ubuntu-latest` and executes the following steps:
1. **Checkout repository**: Checks out the source code (`actions/checkout@v4`).
2. **Set up Node.js 22**: Configures Node.js LTS v22 with npm dependency caching (`actions/setup-node@v4`).
3. **Install dependencies**: Runs clean package installation via `npm ci`.
4. **Generate Prisma Client**: Generates the Prisma Client artifacts (`npx prisma generate`).
5. **Lint**: Validates coding standards and formatting via `npm run lint`.
6. **Typecheck**: Verifies TypeScript strict compilation (`npm run typecheck`).
7. **Test**: Executes Vitest test suite (`npm test`).
8. **Build**: Compiles TypeScript to JavaScript (`npm run build`).
9. **Docker Build**: Builds container image tagged `sentinelscan-api:ci` using multi-stage `Dockerfile` (no push).

### Jenkins Pipeline (Alternative)
The repository also includes a declarative `Jenkinsfile` with the following stages:
1. **Checkout**: Checks out source code from Git.
2. **Install Dependencies**: Runs `npm ci`.
3. **Generate Prisma Client**: Runs `npx prisma generate`.
4. **Lint**: Validates formatting and standards via `npm run lint`.
5. **Typecheck**: Validates strict TypeScript compilation (`npm run typecheck`).
6. **Test**: Executes test suite (`npm test`).
7. **Build**: Compiles TypeScript to JavaScript (`npm run build`).
8. **Security Scan**: Placeholder stage for SAST and dependency vulnerability audits.
9. **Container Scan**: Placeholder stage for container image security scanning.
10. **Docker Build**: Packages container image using multi-stage `Dockerfile`.

#### GitHub → Jenkins Webhook Integration (Future Setup)
1. Navigate to **Repository Settings** > **Webhooks** in GitHub.
2. Set Payload URL: `https://<jenkins-host>/github-webhook/`.
3. Set Content Type to `application/json`.
4. Select `push` and `pull_request` events.
5. In Jenkins, check **GitHub hook trigger for GITScm polling**.

---

## Git Workflow & Two-Developer Collaboration
- `main`: Protected production-ready branch.
- Feature branches: Branch off `main` (e.g., `feature/zap-service-client`).
- Workflow:
  1. `git checkout main && git pull origin main`
  2. `git checkout -b feature/<feature-name>`
  3. Make code changes, run `npm test`, `npm run lint`, and `npm run typecheck`.
  4. Commit changes with clear messages.
  5. Push branch and open a Pull Request.

### Adding GitHub Remote
To link this local repository to a remote repository on GitHub:
```bash
git remote add origin https://github.com/<org-or-user>/sentinelscan-api.git
git branch -M main
git push -u origin main
```

---

## Future Deployment Architecture
- `sentinelscan-api` will be deployed as a container to a Docker-compatible host (e.g., AWS ECS, Render, Railway, or Kubernetes).
- Connected to a managed Neon PostgreSQL instance via `DATABASE_URL`.
- Communicates directly with an `owasp-zap` daemon over a private network via `ZAP_BASE_URL` — see [OWASP ZAP Integration](#owasp-zap-integration).
