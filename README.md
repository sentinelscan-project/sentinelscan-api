# SentinelScan API (`sentinelscan-api`)

## Overview
`sentinelscan-api` is the backend API service for **SentinelScan**. Built with Fastify and TypeScript, it provides the core API foundation, environment configuration validation with Zod, PostgreSQL persistence using Prisma, identity and authentication, authorized target management, centralized logging and error handling, and container packaging.

> **Stage 2 Notice**: This repository currently implements the backend foundation (Stage 0), identity and authentication (Stage 1), and target registration/management (Stage 2). Domain features beyond that — endpoint discovery, the SentinelScan scanner engine, OWASP ZAP integration, finding normalization and correlation, AI security analysis, and reporting — are deliberately not implemented yet. Registering a target does **not** trigger any network request, DNS resolution, crawl, or scan; a `Target` row is purely a record of an authorized assessment subject until later stages act on it. `User` and `Target` are the only domain models so far; later stages will attach scans, findings, analyses and reports to `Target`.

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
│   └── schema.prisma         # Datasource, generator, User and Target models
├── src/
│   ├── app.ts                # Fastify app factory with middleware & error handling
│   ├── config.ts             # Zod environment validation & startup check
│   ├── server.ts             # Server entrypoint with graceful shutdown
│   ├── db/
│   │   └── prisma.ts         # Lazy Prisma client singleton
│   ├── lib/
│   │   ├── email-service.ts  # Verification email delivery (development / Resend)
│   │   ├── email.ts          # Email normalization
│   │   ├── errors.ts         # AppError hierarchy with HTTP status codes
│   │   ├── password.ts       # bcrypt hashing / verification
│   │   ├── prisma-errors.ts  # Unique-constraint detection
│   │   ├── url.ts            # Target URL validation & normalization
│   │   └── validation.ts     # Zod → 400 ValidationError bridge
│   ├── modules/
│   │   ├── auth/
│   │   │   ├── auth.routes.ts    # /auth/register, /login, /verify-email, /me, /logout, ...
│   │   │   ├── auth.schemas.ts   # Zod request schemas & password policy
│   │   │   ├── auth.service.ts   # Registration, login, verification, Google account resolution
│   │   │   └── google.routes.ts  # /auth/google, /auth/google/callback
│   │   └── targets/
│   │       ├── target.routes.ts  # /targets CRUD, all requiring authentication
│   │       ├── target.schemas.ts # Zod request schemas & URL normalization wiring
│   │       └── target.service.ts # Ownership-enforced create/list/get/update/delete
│   ├── plugins/
│   │   └── authentication.ts # JWT + cookie session, `authenticate` preHandler
│   ├── repositories/
│   │   ├── user.repository.ts          # UserRepository interface & PublicUser
│   │   ├── prisma-user.repository.ts   # Prisma implementation
│   │   ├── token.repository.ts         # Email verification token repository
│   │   ├── target.repository.ts        # TargetRepository interface & PublicTarget
│   │   └── prisma-target.repository.ts # Prisma implementation (ownership-scoped queries)
│   ├── routes/
│   │   └── health.ts         # GET /health endpoint
│   └── types/
│       └── fastify.d.ts      # Fastify/JWT type augmentation
├── tests/
│   ├── helpers/
│   │   ├── in-memory-user.repository.ts   # Database-free User/token/email test doubles
│   │   └── in-memory-target.repository.ts # Database-free TargetRepository for tests
│   ├── auth.test.ts          # Registration, verification, login, session, logout tests
│   ├── google-auth.test.ts   # Google identity & unconfigured-provider tests
│   ├── targets.test.ts       # Target CRUD, ownership isolation, validation tests
│   └── health.test.ts        # Vitest integration test
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
| `ZAP_SERVICE_URL` | Base URL of the internal `sentinelscan-zap` service | `http://localhost:8080` |
| `JWT_SECRET` | **Required.** Signing key for session JWTs, minimum 32 characters | *(no default — generate one)* |
| `JWT_EXPIRES_IN` | Session token lifetime, in `jsonwebtoken` duration syntax | `1d` |
| `AUTH_COOKIE_NAME` | Name of the HttpOnly session cookie | `sentinelscan_token` |
| `WEB_APP_URL` | Browser origin of the web app; CORS allowlist and post-OAuth redirect target | `http://localhost:3000` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 client ID *(optional)* | *(unset)* |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 client secret *(optional)* | *(unset)* |
| `GOOGLE_CALLBACK_URL` | Authorized redirect URI registered with Google *(optional)* | `http://localhost:4000/auth/google/callback` |

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

Later stages will hang `Scan → Finding → AiAnalysis → Report` off `Target`; none of those models exist yet.

Persistence for both models is reached through a repository interface (`UserRepository`, `TargetRepository`) rather than Prisma directly, so route handlers stay database-agnostic and the test suite can run against an in-memory implementation with no PostgreSQL instance.

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

Every `/targets` route requires authentication (the same session cookie / bearer token as everything else) and is scoped entirely to `request.currentUser.id`: the owner is always derived from the session, never accepted from the request body, and a target belonging to another user is treated identically to a target that does not exist. None of these endpoints make a network request to the target's `url` — no crawling, scanning, or DNS resolution happens in Stage 2.

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

## Docker

### Build the Image
```bash
docker build -t sentinelscan-api .
```

### Run the Container
```bash
docker run -p 4000:4000 \
  -e DATABASE_URL="postgresql://user:pass@ep-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require" \
  -e ZAP_SERVICE_URL="http://sentinelscan-zap:8080" \
  sentinelscan-api
```

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
- Communicates internally with `sentinelscan-zap` over private network via `ZAP_SERVICE_URL`.
