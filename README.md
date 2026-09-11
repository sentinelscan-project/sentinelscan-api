# SentinelScan API (`sentinelscan-api`)

## Overview
`sentinelscan-api` is the backend API service for **SentinelScan**. Built with Fastify and TypeScript, it provides the core API foundation, environment configuration validation with Zod, PostgreSQL persistence using Prisma, identity and authentication, authorized target management, scan orchestration backed by a real OWASP ZAP integration, vendor-neutral finding normalization and persistence, an AI-assisted security analysis layer, centralized logging and error handling, and container packaging.

> **Stage 6 & 7 Notice**: This repository currently implements the backend foundation (Stage 0), identity and authentication (Stage 1), target registration/management (Stage 2), scan orchestration (Stage 3), real OWASP ZAP execution (Stage 4), findings & vulnerability normalization (Stage 5), and **the AI Security Analyst (Stage 6 & 7)**. A completed scan's persisted findings can now be sent to an AI provider (Google Gemini) for structured, validated security analysis — correlation, prioritization, false-positive likelihood, and remediation guidance — persisted as `SecurityAnalysis`/`FindingAssessment`/`FindingCorrelation` rows. See [AI Security Analyst](#ai-security-analyst) below for the full architecture, and read its "What This Is Not" subsection first: **AI analysis is advisory only** — it never replaces the scanner, never proves exploitability beyond what the supplied evidence shows, and never independently verifies a vulnerability; the original scanner findings remain the source of truth. What Stage 6 & 7 deliberately do **not** do: no autonomous agents, no vector database or embeddings, no cross-scan memory, no SentinelScan-native discovery engine or scanner, no automated remediation execution. `User`, `Target`, `Scan`, `Finding`, `FindingInstance`, `SecurityAnalysis`, `FindingAssessment` and `FindingCorrelation` are the only domain models.

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
- **AI Security Analysis**: Google Gemini via `@google/genai` (structured JSON output via responseSchema), behind a provider-neutral `SecurityAnalysisModel` interface
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
│   └── schema.prisma         # Datasource, generator, and every domain model through Stage 6
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
│   │   ├── scans/
│   │   │   ├── scan.routes.ts        # GET /scans, GET /scans/:id, POST /scans/:id/cancel, GET /scans/:id/findings
│   │   │   ├── scan.schemas.ts       # Zod request schemas, list-query pagination
│   │   │   ├── scan.service.ts       # Lifecycle state machine, ownership-enforced operations
│   │   │   ├── scan-executor.ts      # ScanExecutor interface + inert NotImplementedScanExecutor
│   │   │   └── zap-scan-executor.ts  # ZapClient-driven executor; now also normalizes + persists findings (Stage 5)
│   │   └── findings/
│   │       ├── finding-category.ts       # FINDING_CATEGORIES closed list & FindingCategory type
│   │       ├── normalized-finding.ts     # Vendor-neutral NormalizedFinding/NormalizedFindingInstance contract
│   │       ├── finding.schemas.ts        # Zod request schemas (filters, pagination)
│   │       ├── finding.service.ts        # Ownership-enforced finding read operations
│   │       ├── finding.routes.ts         # GET /findings/:id
│   │       └── zap/
│   │           ├── zap-alert.ts               # Raw ZAP alert shape + defensive parsing helpers
│   │           ├── zap-severity-mapping.ts     # ZAP risk → FindingSeverity (centralized, documented fallback)
│   │           ├── zap-confidence-mapping.ts   # ZAP confidence → FindingConfidence (centralized, documented fallback)
│   │           ├── zap-category-mapping.ts     # ZAP pluginId → FindingCategory (centralized, documented fallback)
│   │           └── zap-alert-normalizer.ts     # ZapRawAlert[] → NormalizedFinding[] (grouping, dedup, sanitization)
│   │   └── analysis/
│   │       ├── analysis-enums.ts             # AnalysisStatus/OverallRisk/AssessmentPriority/... closed lists
│   │       ├── security-analysis-input.ts    # Deterministic, provider-neutral SecurityAnalysisInput contract
│   │       ├── analysis-preprocessing.ts     # Loads/sorts/bounds/re-sanitizes findings into that input (Stage 6 §8–9)
│   │       ├── security-analysis-output.schema.ts # Zod contract every provider's output must satisfy
│   │       ├── security-analysis-model.ts    # SecurityAnalysisModel provider interface + AiProviderError
│   │       ├── analysis-prompt.ts            # Versioned system prompt (SECURITY_ANALYSIS_PROMPT_VERSION)
│   │       ├── analysis-executor.ts          # AnalysisExecutor interface (mirrors scan-executor.ts)
│   │       ├── security-analysis-executor.ts # Real executor: input → model → validate → persist → terminal state
│   │       ├── analysis.schemas.ts           # Zod request schemas
│   │       ├── analysis.service.ts           # Lifecycle state machine, ownership-enforced operations
│   │       ├── analysis.routes.ts            # GET /analysis/:id
│   │       └── providers/
│   │           └── gemini-security-analysis-model.ts # The implemented provider (Google Gemini, responseSchema)
│   ├── plugins/
│   │   └── authentication.ts # JWT + cookie session, `authenticate` preHandler
│   ├── repositories/
│   │   ├── user.repository.ts          # UserRepository interface & PublicUser
│   │   ├── prisma-user.repository.ts   # Prisma implementation
│   │   ├── token.repository.ts         # Email verification token repository
│   │   ├── target.repository.ts        # TargetRepository interface & PublicTarget
│   │   ├── prisma-target.repository.ts # Prisma implementation (ownership-scoped queries)
│   │   ├── scan.repository.ts          # ScanRepository interface & PublicScan
│   │   ├── prisma-scan.repository.ts   # Prisma implementation (atomic CAS transitions)
│   │   ├── finding.repository.ts       # FindingRepository interface & PublicFinding
│   │   ├── prisma-finding.repository.ts # Prisma implementation (transaction-wrapped createMany)
│   │   ├── analysis.repository.ts      # AnalysisRepository interface & PublicSecurityAnalysis
│   │   └── prisma-analysis.repository.ts # Prisma implementation (transaction-wrapped completeAnalysis)
│   ├── routes/
│   │   └── health.ts         # GET /health, GET /health/zap
│   └── types/
│       └── fastify.d.ts      # Fastify/JWT type augmentation
├── tests/
│   ├── helpers/
│   │   ├── in-memory-user.repository.ts   # Database-free User/token/email test doubles
│   │   ├── in-memory-target.repository.ts # Database-free TargetRepository for tests
│   │   ├── in-memory-scan.repository.ts   # Database-free ScanRepository (reproduces CAS semantics)
│   │   ├── in-memory-finding.repository.ts # Database-free FindingRepository (reproduces transaction/failure semantics)
│   │   ├── in-memory-analysis.repository.ts # Database-free AnalysisRepository (reproduces CAS/transaction semantics)
│   │   ├── fake-zap-client.ts             # Scriptable ZapClient test double (no real HTTP)
│   │   ├── fake-scan-executor.ts          # No-op ScanExecutor so orchestration tests don't touch ZAP
│   │   ├── fake-security-analysis-model.ts # Scriptable SecurityAnalysisModel test double (no real AI provider)
│   │   └── fake-analysis-executor.ts      # No-op AnalysisExecutor so orchestration tests don't touch the AI provider
│   ├── auth.test.ts              # Registration, verification, login, session, logout tests
│   ├── google-auth.test.ts       # Google identity & unconfigured-provider tests
│   ├── targets.test.ts           # Target CRUD, ownership isolation, validation tests
│   ├── scans.test.ts             # Scan orchestration, lifecycle, ownership isolation tests
│   ├── findings.test.ts          # Findings API: filtering, counts, pagination, ownership isolation
│   ├── analysis.test.ts          # Analysis API: lifecycle, authorization, duplicate-prevention
│   ├── target-safety.test.ts     # SSRF policy: IP ranges, DNS resolution, DNS-rebinding awareness
│   ├── zap-client.test.ts        # HttpZapClient against a mocked fetch
│   ├── zap-scan-executor.test.ts # Full execution lifecycle incl. finding persistence, against a fake ZapClient
│   ├── zap-alert-normalizer.test.ts # Severity/confidence/category mapping, grouping, dedup, sanitization
│   ├── sanitize-text.test.ts     # Credential redaction & length-capping rules
│   ├── analysis-preprocessing.test.ts # Deterministic input building: ordering, limits, re-sanitization
│   ├── security-analysis-executor.test.ts # Full analysis execution lifecycle against a fake model
│   ├── gemini-security-analysis-model.test.ts # Provider adapter against a mocked Gemini client
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
| `DATABASE_URL` | Neon PostgreSQL database connection string. **In production**, must not be the example/mock placeholder shipped in this repo — rejected at startup | `postgresql://user:pass@ep-pooler.us-east-2.aws.neon.tech/sentinelscan?sslmode=require` |
| `JWT_SECRET` | **Required.** Signing key for session JWTs, minimum 32 characters. **In production**, must not be a known development/placeholder value (including the `docker-compose.yml`/`.env.example` defaults) — rejected at startup | *(no default — generate one)* |
| `JWT_EXPIRES_IN` | Session token lifetime, in `jsonwebtoken` duration syntax | `1d` |
| `AUTH_COOKIE_NAME` | Name of the HttpOnly session cookie | `sentinelscan_token` |
| `WEB_APP_URL` | Browser origin of the web app; CORS allowlist and post-OAuth redirect target. **In production**, must be `https://` — rejected at startup otherwise | `http://localhost:3000` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 client ID *(optional, must be set with the two below)* | *(unset)* |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 client secret *(optional)* | *(unset)* |
| `GOOGLE_CALLBACK_URL` | Authorized redirect URI registered with Google *(optional)* | `http://localhost:4000/auth/google/callback` |
| `EMAIL_PROVIDER` | `development` (logs the link) or `resend` (real delivery) | `development` |
| `EMAIL_FROM` | From address used for outgoing verification email | `SentinelScan <noreply@sentinelscan.io>` |
| `RESEND_API_KEY` | Resend API key *(required only when `EMAIL_PROVIDER=resend`)* | *(unset)* |
| `ZAP_BASE_URL` | **Required.** Canonical base URL of the ZAP daemon's JSON API | `http://owasp-zap:8090` in Docker; `http://localhost:8090` locally |
| `ZAP_SERVICE_URL` | Legacy alias for `ZAP_BASE_URL` from Stage 0, kept only for backward compatibility — set `ZAP_BASE_URL` directly in new configuration | *(unset)* |
| `ZAP_API_KEY` | ZAP API key. Optional in local development (`api.disablekey=true`); **required in production** — the process still boots without it (this value can't be independently verified against the separately-deployed ZAP daemon), but logs a startup warning. Never logged, never sent to the browser | *(unset)* |
| `ZAP_HTTP_TIMEOUT_MS` | Per-HTTP-call timeout against ZAP | `10000` |
| `ZAP_CRAWL_TIMEOUT_MS` | Ceiling on the spider phase | `300000` (5 min) |
| `ZAP_ACTIVE_SCAN_TIMEOUT_MS` | Ceiling on the active-scan phase | `1800000` (30 min) |
| `ZAP_OVERALL_SCAN_TIMEOUT_MS` | Ceiling across the whole execution, independent of the two phase timeouts | `2400000` (40 min) |
| `ZAP_POLL_INTERVAL_MS` | How often the executor polls ZAP for spider/active-scan progress | `2000` |
| `AI_PROVIDER` | AI Security Analyst provider | `gemini` |
| `AI_MODEL` | Which Gemini model performs security analysis | `gemini-2.5-flash` |
| `GEMINI_API_KEY` | Google Gemini API key *(optional — see [AI Security Analyst](#ai-security-analyst) for what happens without one)* | *(unset)* |
| `ANALYSIS_TIMEOUT_MS` | Per-analysis timeout for the AI provider call itself | `120000` (2 min) |
| `ANALYSIS_MAX_OUTPUT_TOKENS` | Ceiling on the model's own output size for one analysis | `8000` |

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

### `Finding` (table `findings`)

One normalized vulnerability/security issue identified during a `Scan` — *one logical vulnerability/rule for that scan*, not a specific occurrence (that's `FindingInstance`, below). This model deliberately does **not** mirror any scanner's raw schema; `source`/`sourceRuleId` are the only scanner-specific fields, kept purely for traceability. See [Findings & Vulnerability Normalization](#findings--vulnerability-normalization) for the full normalization architecture.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `scanId` | `String` | Foreign key to `Scan.id`, `onDelete: Restrict` |
| `title` | `String` | Sanitized, length-capped |
| `description` | `String` | Sanitized, length-capped |
| `severity` | `FindingSeverity` | `critical` \| `high` \| `medium` \| `low` \| `informational` |
| `confidence` | `FindingConfidence` | `high` \| `medium` \| `low` \| `unknown` |
| `category` | `String` | One of `FINDING_CATEGORIES` (`modules/findings/finding-category.ts`) — a plain `String` column, not a Prisma `enum`; see the comment above `FindingSeverity` in `schema.prisma` for why (Prisma enum *values* can't be hyphenated, and this category set's wire format intentionally is) |
| `cweId` | `Int?` | Common Weakness Enumeration id, when the source provides one |
| `wascId` | `Int?` | Web Application Security Consortium id, when the source provides one |
| `remediation` | `String?` | Sanitized, length-capped |
| `references` | `Json?` | An array of sanitized, length-capped reference URL strings |
| `source` | `String` | Which scanner produced this finding, e.g. `"zap"` — a plain string, not an enum, so a new scanner source never requires a migration |
| `sourceRuleId` | `String?` | The source's own stable rule identifier (ZAP's `pluginId`, e.g. `"40018"`); never just the human-readable name |
| `createdAt` / `updatedAt` | `DateTime` | Standard timestamps |

Unique on `(scanId, source, sourceRuleId)` — see [Deduplication Strategy](#deduplication-strategy). Indexed on `scanId` and `(scanId, severity)`. **Delete behavior**: `Restrict`, matching `Scan`'s own relations — a `Scan` cannot currently be deleted through any endpoint at all, so this is a consistent, defensive choice.

### `FindingInstance` (table `finding_instances`)

One location where a `Finding`'s rule was actually observed — a specific URL, and where applicable the HTTP method, parameter, attack payload, and a short evidence snippet.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `findingId` | `String` | Foreign key to `Finding.id`, `onDelete: Cascade` |
| `url` | `String` | Sanitized, length-capped |
| `method` | `String?` | e.g. `"GET"` |
| `parameter` | `String?` | Sanitized, length-capped |
| `attack` | `String?` | Sanitized, length-capped attack payload snippet |
| `evidence` | `String?` | Sanitized, length-capped evidence snippet — **never** a raw HTTP request/response body |
| `createdAt` | `DateTime` | Standard timestamp |

Indexed on `findingId`. **Delete behavior**: `Cascade` — a `FindingInstance` has no independent identity or historical significance apart from the `Finding` it belongs to, unlike `Finding` itself relative to `Scan`.

### `SecurityAnalysis` (table `security_analyses`)

One AI-generated security analysis of a completed `Scan`'s findings — see [AI Security Analyst](#ai-security-analyst) for the full architecture.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `scanId` | `String` | Foreign key to `Scan.id`, `onDelete: Restrict`, **`@unique`** — see the uniqueness-strategy note below |
| `status` | `AnalysisStatus` | `"queued"` (default) · `"running"` · `"completed"` · `"failed"` |
| `model` | `String?` | Which AI model produced this analysis (e.g. `"claude-sonnet-5"`); set only once completed |
| `promptVersion` | `String` | Which version of the system prompt produced this analysis; set at creation |
| `overallRisk` | `OverallRisk?` | `critical` \| `high` \| `medium` \| `low` \| `informational`; set only once completed |
| `executiveSummary` | `String?` | Set only once completed |
| `methodologySummary` | `String?` | The AI's own description of its approach, when provided |
| `limitations` | `String?` | The AI's own caveats about this analysis (e.g. truncated findings) |
| `createdAt` / `updatedAt` | `DateTime` | Standard timestamps |
| `completedAt` | `DateTime?` | Set on `completed` or `failed` |
| `errorMessage` | `String?` | Set only on `failed`; a safe, never-raw-provider-error message |

**Uniqueness strategy (Stage 6 decision):** `scanId` is `@unique` — at most one `SecurityAnalysis` ever exists per scan in this stage, in any status. `AnalysisStatus` has no transition back out of `failed`, so a failed analysis is not retryable in place, and a completed one is never silently overwritten by a rerun: `POST /scans/:scanId/analyze` simply refuses with `409 ANALYSIS_ALREADY_EXISTS` once any row exists for that scan. See [Analysis Re-runs](#analysis-re-runs) for why this is deliberate, not an oversight, and what relaxing it later would look like.

### `FindingAssessment` (table `finding_assessments`)

The AI's structured assessment of one `Finding` within one `SecurityAnalysis`.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `analysisId` | `String` | Foreign key to `SecurityAnalysis.id`, `onDelete: Cascade` |
| `findingId` | `String` | Foreign key to `Finding.id`, `onDelete: Restrict` |
| `priority` | `AssessmentPriority` | The AI's own priority judgment — **never** `Finding.severity` itself; see [Prioritization Logic](#prioritization-logic) |
| `riskAssessment` | `String` | The AI's explanation of the risk this finding poses |
| `confidence` | `FindingConfidence` | The AI's confidence in its *own* assessment (reuses the same scale `Finding.confidence` uses) |
| `reasoning` | `String` | Why the AI reached this priority/assessment — required whenever `priority` differs from `Finding.severity` |
| `businessImpact` / `technicalImpact` | `String?` | Optional, more specific impact framing |
| `remediationPriority` | `AssessmentPriority` | How urgently this finding's remediation should be scheduled — may differ from `priority` itself |
| `falsePositiveLikelihood` | `FalsePositiveLikelihood` | `low` \| `medium` \| `high` \| `unknown` — never used to delete or suppress a finding |
| `createdAt` / `updatedAt` | `DateTime` | Standard timestamps |

At most one assessment per `(analysisId, findingId)` — `@@unique([analysisId, findingId])`. **Delete behavior**: `analysis` cascades; `finding` is `Restrict` (consistent with every other relation to `Finding`).

### `FindingCorrelation` (table `finding_correlations`)

A relationship the AI identified between two findings within one `SecurityAnalysis`.

| Column | Type | Notes |
| :--- | :--- | :--- |
| `id` | `String` (uuid) | Primary key |
| `analysisId` | `String` | Foreign key to `SecurityAnalysis.id`, `onDelete: Cascade` |
| `findingAId` / `findingBId` | `String` | Foreign keys to `Finding.id`, both `onDelete: Restrict`; canonicalized to lexicographic order before persistence, so the same pair is never stored twice reversed |
| `relationship` | `String` | One of `CORRELATION_RELATIONSHIPS` (`related`, `duplicate-symptom`, `attack-chain`, `shared-root-cause`, `amplifies-risk`) — a closed, application-validated list, the same reasoning as `Finding.category` (some values are hyphenated) |
| `confidence` | `FindingConfidence` | The AI's confidence in this specific correlation claim |
| `explanation` | `String` | Grounded in the supplied evidence — see [Correlation Logic](#correlation-logic) |
| `createdAt` | `DateTime` | Standard timestamp |

At most one row per `(analysisId, findingAId, findingBId)` — `@@unique`. **Delete behavior**: `analysis` cascades; both finding relations are `Restrict`.

Later stages will hang `Report` off `Scan`/`SecurityAnalysis`; that model does not exist yet.

Persistence for all eight models is reached through a repository interface (`UserRepository`, `TargetRepository`, `ScanRepository`, `FindingRepository`, `AnalysisRepository`) rather than Prisma directly, so route handlers stay database-agnostic and the test suite can run against an in-memory implementation with no PostgreSQL instance. `ScanRepository`'s status-transition method is a compare-and-swap (`UPDATE ... WHERE status = $expected`, via Prisma's `updateMany`), which is what makes two simultaneous requests to cancel (or otherwise transition) the same scan resolve safely — see [Scan lifecycle](#scan-lifecycle). `FindingRepository.createMany` wraps every `Finding`/`FindingInstance` write for one scan in a single Prisma `$transaction` — see [Persistence Lifecycle](#persistence-lifecycle--transaction-behavior). `AnalysisRepository.completeAnalysis` does the same for every `FindingAssessment`/`FindingCorrelation` write, guarded by the same CAS pattern — see [AI Security Analyst → Persistence & Transactions](#persistence--transactions).

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

### Findings

Every route requires authentication. See [Findings & Vulnerability Normalization](#findings--vulnerability-normalization) for the normalization/persistence architecture behind these endpoints.

#### `GET /scans/:scanId/findings`

Findings for one scan — only when the caller owns it (same non-enumerable-404 rule as everywhere else: another user's scan and a nonexistent one are indistinguishable). Query parameters (all optional):

| Parameter | Notes |
| :--- | :--- |
| `severity` | One of `critical`, `high`, `medium`, `low`, `informational` |
| `confidence` | One of `high`, `medium`, `low`, `unknown` |
| `category` | One of `FINDING_CATEGORIES` (see below) |
| `source` | Free text, e.g. `zap` |
| `limit` | 1–100, default 20 |
| `offset` | ≥ 0, default 0 |

- `200` — `{ "findings": [ { ... }, ... ], "counts": { "critical": 0, "high": 2, "medium": 1, "low": 0, "informational": 3, "total": 6 }, "limit": 20, "offset": 0, "hasMore": false }`
  - `counts` is always the scan's **full, unfiltered** severity breakdown, derived live from the persisted `Finding` rows — never from ZAP's own alert-summary log, and never affected by `severity`/`confidence`/`category`/`source` filters applied to `findings` itself.
- `400` `VALIDATION_ERROR` — an invalid filter value, or `limit`/`offset` out of range
- `401` `UNAUTHORIZED` — no valid session
- `404` `SCAN_NOT_FOUND` — no such scan, *or* it was requested by a different user

#### `GET /findings/:id`

A single finding with its instances — only when it belongs to a scan the caller owns (via a join through `Finding.scan.requestedById`, since there is no `scanId` in this URL to pre-validate ownership through).

- `200` — `{ "finding": { ... } }`
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `401` `UNAUTHORIZED` — no valid session
- `404` `FINDING_NOT_FOUND` — no such finding, *or* its scan belongs to a different user

#### Safe finding representation

```json
{
  "id": "a1b2...",
  "scanId": "9c2a...",
  "title": "X-Frame-Options Header Not Set",
  "description": "X-Frame-Options header is not included in the HTTP response...",
  "severity": "medium",
  "confidence": "medium",
  "category": "security-header",
  "cweId": 1021,
  "wascId": 15,
  "remediation": "Most modern Web browsers support the Content-Security-Policy...",
  "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
  "source": "zap",
  "sourceRuleId": "10020",
  "createdAt": "2026-09-10T09:05:00.000Z",
  "updatedAt": "2026-09-10T09:05:00.000Z",
  "instances": [
    {
      "id": "c3d4...",
      "url": "https://staging.acme.example.com/",
      "method": "GET",
      "parameter": null,
      "attack": null,
      "evidence": null,
      "createdAt": "2026-09-10T09:05:00.000Z"
    }
  ]
}
```

No raw ZAP response, no internal Prisma field, and no secret ever crosses this boundary — see [Sanitization](#sanitization).

### AI Security Analysis

Every route requires authentication. See [AI Security Analyst](#ai-security-analyst) for the full architecture behind these endpoints — the analysis lifecycle, provider abstraction, structured output contract, and why AI analysis is advisory only.

#### `POST /scans/:scanId/analyze`

Requests a new AI security analysis of a completed scan the caller owns. Creates a `SecurityAnalysis` row (`status: "queued"`) and returns immediately — analysis runs in the background, the same fire-and-forget shape scan execution itself uses (see [Asynchronous Execution](#asynchronous-execution)).

- `202` — `{ "analysis": { ... } }`, `status: "queued"`
- `400` `VALIDATION_ERROR` — `:scanId` is not a well-formed UUID
- `401` `UNAUTHORIZED` — no valid session
- `404` `SCAN_NOT_FOUND` — no such scan, *or* it was requested by a different user
- `409` `SCAN_NOT_COMPLETED` — the scan exists but hasn't finished (`status` isn't `"completed"`)
- `409` `ANALYSIS_ALREADY_EXISTS` — an analysis already exists for this scan (any status) — see [Analysis Re-runs](#analysis-re-runs) and [Concurrency & Duplicate Prevention](#concurrency--duplicate-prevention)

#### `GET /scans/:scanId/analysis`

The current analysis for one scan the caller owns.

- `200` — `{ "analysis": { ... } }`
- `401` `UNAUTHORIZED` — no valid session
- `404` `SCAN_NOT_FOUND` — no such scan, *or* it was requested by a different user
- `404` `ANALYSIS_NOT_FOUND` — the scan exists and is owned by the caller, but no analysis has been requested for it yet (a legitimate, common state — this is a singular sub-resource, so its absence is reported as `404`, not an empty list)

#### `GET /analysis/:id`

A single analysis by id — only when it belongs to a scan the caller owns.

- `200` — `{ "analysis": { ... } }`
- `400` `VALIDATION_ERROR` — `:id` is not a well-formed UUID
- `401` `UNAUTHORIZED` — no valid session
- `404` `ANALYSIS_NOT_FOUND` — no such analysis, *or* its scan belongs to a different user

#### Safe analysis representation

```json
{
  "id": "d4e5...",
  "scanId": "9c2a...",
  "status": "completed",
  "model": "claude-sonnet-5",
  "promptVersion": "1.0",
  "overallRisk": "high",
  "executiveSummary": "One high-severity, exploitable reflected XSS finding was identified on the search endpoint...",
  "methodologySummary": "Findings were reviewed for evidence quality, correlated by affected endpoint, and prioritized by combined impact.",
  "limitations": null,
  "createdAt": "2026-09-13T09:00:00.000Z",
  "updatedAt": "2026-09-13T09:00:12.000Z",
  "completedAt": "2026-09-13T09:00:12.000Z",
  "errorMessage": null,
  "assessments": [
    {
      "id": "e6f7...",
      "findingId": "a1b2...",
      "priority": "high",
      "riskAssessment": "Exploitable reflected XSS on a search endpoint that echoes user input without encoding.",
      "confidence": "high",
      "reasoning": "The supplied evidence directly demonstrates script reflection in the response body.",
      "businessImpact": "Could be used to hijack an authenticated user's session on this page.",
      "technicalImpact": "Arbitrary script execution in the victim's browser context.",
      "remediationPriority": "high",
      "falsePositiveLikelihood": "low",
      "createdAt": "2026-09-13T09:00:12.000Z",
      "updatedAt": "2026-09-13T09:00:12.000Z"
    }
  ],
  "correlations": []
}
```

No raw provider response, no API key, no internal prompt (unless a future stage explicitly decides to expose one), and no internal Prisma field ever crosses this boundary.

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

**Stage 4 wires a real ZAP daemon into scan execution.** This section covers the architecture, the SSRF/scope safety boundary, timeouts, cancellation, and concurrency model. As of Stage 5, a successful ZAP run's raw alerts are normalized and persisted as `Finding`/`FindingInstance` rows before the scan is reported `completed` — see [Findings & Vulnerability Normalization](#findings--vulnerability-normalization) for that part of the pipeline. There is still no SentinelScan-native discovery engine or scanner (ZAP is the only scan engine) and no AI analysis.

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
  → fetch raw ZAP alerts (ZapClient.alerts)
  → normalize into NormalizedFinding[] (zap-alert-normalizer.ts)
  → persist Finding + FindingInstance rows (FindingRepository.createMany, one transaction)
  → completed
  → (finally) remove the ZAP context
```

A failure at any step — target-safety rejection, ZAP unreachable, a malformed ZAP response, a phase timeout, or a finding-persistence failure — moves the scan to `failed` with a safe (never-raw) message in `Scan.errorMessage` via `failScan`, and still runs the context-removal cleanup. A scan is marked `completed` only when the active scan itself reached 100% **and** its findings were successfully normalized and persisted — never earlier, and never when persistence fails silently. See [Persistence Lifecycle & Transaction Behavior](#persistence-lifecycle--transaction-behavior).

### Cancellation

`POST /scans/:id/cancel` (already implemented in Stage 3) is checked for by the executor at several points: before creating the ZAP context, before starting each phase, and on every poll iteration while a phase is in progress (roughly every `ZAP_POLL_INTERVAL_MS`). When a cancellation is observed mid-phase, the executor attempts to stop the corresponding ZAP operation (`spider/action/stop` or `ascan/action/stop`) **best-effort**: ZAP does not guarantee immediate termination, and a failure to stop it is logged and otherwise ignored, never escalated into a scan failure. The ZAP context is still removed in `finally` either way.

**The race this matters for**: ZAP finishing at the same moment a user cancels. Every lifecycle write goes through `scan.service.ts`'s existing atomic compare-and-swap (`UPDATE ... WHERE status = $expected`) — this executor never writes `Scan.status` directly. If `POST /scans/:id/cancel` wins that race, the executor's later `completeScan` call simply fails its own CAS (the row is no longer `running`) and is treated as "already terminal, nothing to do", not as an error — `cancelled` is never overwritten by a late `completed`.

### Timeouts

Four independent ceilings, all configurable (see [Environment Variables](#supported-variables)), none hardcoded: a per-HTTP-call timeout against ZAP (`ZAP_HTTP_TIMEOUT_MS`), a crawl-phase timeout (`ZAP_CRAWL_TIMEOUT_MS`), an active-scan-phase timeout (`ZAP_ACTIVE_SCAN_TIMEOUT_MS`), and an overall ceiling across the whole execution (`ZAP_OVERALL_SCAN_TIMEOUT_MS`), independent of the two phase timeouts. A scan can never run forever: exceeding any timeout is treated the same as a cancellation-triggered stop (best-effort ZAP stop, then `failed`).

### Logging

The executor logs (via `console.info`/`console.error`, the same convention `auth.service.ts` already uses for background side effects outside any Fastify request) execution start, crawl start/complete, active-scan start/complete, the result summary, and completion/failure/cancellation — each tagged with `scanId` and `targetId`. It never logs API keys, cookies, authorization headers, target credentials, or a raw ZAP response body; `ZapClient`'s own error messages are built from the request's endpoint name only, never the full URL (which may carry `apikey` as a query parameter).

### What is not implemented

No SentinelScan-native discovery/crawling engine — ZAP's own spider is the only crawler. No SentinelScan-native scanner — ZAP's active scan is the only scan engine. No AI analysis or automated remediation. No queue/worker infrastructure (Redis, Kafka, RabbitMQ, BullMQ) — see "Triggering execution" above for what that means in practice. (Finding normalization, deduplication, and persistence *are* implemented as of Stage 5 — see below.)

---

## Findings & Vulnerability Normalization

**Stage 5 gives SentinelScan its own normalized vulnerability model**, independent of any one scanner's schema, and persists it to PostgreSQL. The flow, end to end:

```
ZAP raw alerts → ZapClient.alerts() → normalizeZapAlerts() → NormalizedFinding[]
  → FindingRepository.createMany() → Finding + FindingInstance rows in PostgreSQL
  → (a future stage) AI Security Analyst
```

### Architectural principle: vendor-neutral, not a ZAP wrapper

`modules/findings/normalized-finding.ts` defines `NormalizedFinding`/`NormalizedFindingInstance` — the *only* contract between a scanner adapter and everything downstream (persistence, the API, a future AI analyst). `modules/findings/zap/zap-alert-normalizer.ts` is the **only** file in the codebase that knows what a raw ZAP alert looks like; it consumes ZAP's shape and produces `NormalizedFinding[]`. A future scanner source would have its own adapter consuming its own raw shape, but producing this exact same type. The persisted `Finding`/`FindingInstance` schema does not mirror ZAP's own field names or terminology anywhere except `source`/`sourceRuleId`, which exist purely for traceability back to where a finding came from.

### Extending `ZapClient` for individual alerts

Stage 4's `ZapClient.alertSummary()` only ever called ZAP's `/JSON/alert/view/alertsSummary/` — a per-risk-level **count**, not individual alerts. Stage 5 adds `ZapClient.alerts(baseUrl)`, calling `/JSON/core/view/alerts/`, ZAP's endpoint for individual raw alert occurrences. Its response shape was confirmed empirically against a live ZAP 2.17.0 daemon (a full spider + active-scan cycle against a controlled local nginx target), not guessed — see `modules/findings/zap/zap-alert.ts`'s `ZapRawAlert` type for the confirmed field list and the quirks worth knowing (`cweid`/`wascid` are strings where `"0"` means "not set"; `reference` is one newline-delimited string, not an array; `pluginId`, not `alertRef`, is the stable rule identifier).

### Severity mapping

`modules/findings/zap/zap-severity-mapping.ts` centralizes ZAP's `risk` string → `FindingSeverity` (`critical` / `high` / `medium` / `low` / `informational`) in one lookup table, matched case-insensitively: `High→high`, `Medium→medium`, `Low→low`, `Informational→informational` (`Critical→critical` is wired in for a future ZAP risk tier, though ZAP does not currently emit one). An unrecognized or missing value never crashes a scan — it falls back to the documented, conservative `FALLBACK_SEVERITY = "medium"` (not `informational`, which would risk understating a real vulnerability; not `critical`/`high`, which would risk overstating one for a merely-unrecognized label).

### Confidence mapping

`modules/findings/zap/zap-confidence-mapping.ts` maps ZAP's `confidence` string → `FindingConfidence` (`high` / `medium` / `low` / `unknown`): `High→high`, `Medium→medium`, `Low→low`, `Confirmed→high`, and ZAP's `False Positive` label → `unknown` (a false-positive marking is a claim the finding is *wrong*, not merely uncertain — SentinelScan's confidence scale has no matching tier, so it becomes `unknown` rather than being silently folded into `low`). Confidence information is never discarded; an unrecognized or missing value becomes the documented `FALLBACK_CONFIDENCE = "unknown"`.

### Category mapping

`modules/findings/zap/zap-category-mapping.ts` maps ZAP's stable `pluginId` (never the human-readable alert name — names have changed across ZAP versions) to one of `FINDING_CATEGORIES` (`modules/findings/finding-category.ts`): `injection`, `authentication`, `authorization`, `cryptography`, `security-misconfiguration`, `sensitive-data-exposure`, `security-header`, `client-side`, `server-side`, `information-disclosure`, `other`. This is a curated, deliberately incomplete mapping of ZAP's common default rules — not an attempt to enumerate every rule ZAP ships. An unmapped `pluginId` becomes `"other"`, and the finding's `sourceRuleId` (the same `pluginId`) is always preserved, so no rule's origin is ever lost even when its category isn't yet known. Extending the table for a newly-encountered `pluginId` is a one-line addition.

### Deduplication strategy

A `Finding` is **one logical vulnerability/rule for one scan** — not one occurrence. Raw alerts are grouped by `pluginId` (falling back to the alert's own name, with a `null sourceRuleId`, on the rare malformed alert missing even that) before normalization; each group becomes exactly one `NormalizedFinding`, carrying one `FindingInstance` per distinct occurrence (URL/method/parameter/attack/evidence combination) within that group. Exact-duplicate raw alert entries (ZAP occasionally reports the identical occurrence twice) collapse into a single instance. When a group's raw alerts disagree on risk/confidence (not expected in practice, but never assumed), the group's overall severity/confidence is the **worst-case** (highest-ranked) value seen, so a real elevated-severity occurrence can never be silently hidden behind a lower one.

Two rules distinct findings must never violate:
- **Same rule, same scan → one `Finding`.** The database backstops this with `@@unique([scanId, source, sourceRuleId])` on `Finding` — defensive, not the primary correctness mechanism (that's the grouping above), since `createMany` only ever runs once per scan in normal operation.
- **Same rule, different scans → separate `Finding` rows, always.** Findings are never deduplicated globally across scans; each scan is its own historical record of what was true when it ran. Distinct rules that merely share a similar name (e.g. ZAP's several separate `SQL Injection - <database>` variants) are never merged — grouping is by `pluginId`, never by string-matching on the name.

### Sanitization

`lib/sanitize-text.ts` sanitizes every free-text field a `Finding`/`FindingInstance` stores, applied by the normalizer before anything is persisted — never applied again at read time, since the frontend is expected to render these fields as plain text, never as HTML (scanner output is untrusted data, not markup). Two rules, in order:

1. **Redact credential-like content**, preferring redaction over truncation (a truncated secret can still leak enough to be useful). Covers `Authorization`/`Cookie`/`Set-Cookie`/`Proxy-Authorization` headers (the header name stays visible, only the value is redacted) and generic `key=value` / `key: "value"` / `"key": "value"` pairs for api-key/access-key/secret/token/bearer/password/passwd/pwd/session-id-shaped keys, wherever they appear in a string (a URL query string, a JSON-looking evidence blob, not just at a line start).
2. **Cap length**, applied *after* redaction — so a would-be-secret sitting right at the truncation boundary is still fully redacted rather than half-truncated into something that looks safe but isn't.

Reference lists are additionally bounded in count (so a hostile/malformed scanner response can't produce an unbounded array) and each entry is length-capped and blank-filtered. Nothing raw is ever stored: no full HTTP request/response bodies, no cookies, no Authorization headers, no passwords, tokens, or session identifiers — and, per the "no giant speculative raw storage" decision, the complete raw ZAP alert JSON is **not** persisted anywhere either; the normalized model is the only stored representation.

### Persistence lifecycle & transaction behavior

A `Scan` now reaches `completed` only once **both** of these have happened: the ZAP active scan itself reached 100%, **and** its findings were successfully normalized and persisted. A scan that finished ZAP execution successfully but failed to persist its findings is reported `failed`, never `completed` with findings silently missing — `ZapScanExecutor` calls `FindingRepository.createMany` strictly before `completeScan`, and lets any persistence error fall through to the same failure-handling path as a ZAP error.

`FindingRepository.createMany` wraps every `Finding` (and its `FindingInstance` rows) for one scan in a single Prisma `$transaction`: either all of a scan's findings land, or none do — there is no scenario where a scan ends up with a partial, inconsistent set of findings. This transaction covers only the persistence/finalization phase; it is never held open across ZAP execution itself (the crawl and active scan, which can run for minutes to hours, happen entirely before this call). An empty `rawAlerts` result (a clean scan) normalizes to `[]` and persists zero rows — a legitimate, successful outcome, not an error.

### Finding counts

`GET /scans/:scanId/findings` returns a `counts` object (`critical`/`high`/`medium`/`low`/`informational`/`total`) computed live from the persisted `Finding` table via `FindingRepository.countsForScan` — never from ZAP's own alert-summary log (which Stage 5 no longer calls at all), and never duplicated as denormalized state on the `Scan` row itself. `counts` is always the scan's full, unfiltered breakdown, independent of any `severity`/`confidence`/`category`/`source` filter applied to the `findings` list in the same response.

### What is not implemented

No endpoint-discovery engine, no SentinelScan-native vulnerability scanner. ZAP remains the only scan/finding source; the normalized model above is what makes adding a second source later a matter of writing one more adapter, not a schema change. AI analysis of these findings is Stage 6's job — see [AI Security Analyst](#ai-security-analyst) below.

---

## AI Security Analyst

**Stage 6 adds AI-assisted analysis on top of Stage 5's normalized findings.** The AI is not the scanner: it never makes network requests, crawls, executes code, or takes any action against a target. It receives already-collected, already-persisted `Finding`/`FindingInstance` rows and produces a structured, independently-validated security assessment.

```
Finding rows (Stage 5)
  → deterministic preprocessing (sort, bound, re-sanitize)
  → SecurityAnalysisInput
  → SecurityAnalysisModel (provider adapter)
  → SecurityAnalysisOutput (schema-validated)
  → id cross-reference check
  → transactional persistence
  → SecurityAnalysis + FindingAssessment + FindingCorrelation rows
```

### What this is not

SentinelScan does not become `ZAP → LLM → rewritten ZAP report`. The AI adds reasoning that cannot be obtained by simply displaying the scanner findings — correlating related findings, prioritizing remediation, explaining likely impact, flagging possible false positives with explicit uncertainty — but it never invents a vulnerability, an affected endpoint, or evidence that wasn't already in the supplied findings.

**AI analysis is advisory.** It does not replace the scanner: `Finding.severity`/`Finding.confidence` are never altered by an analysis, ever (see [Prioritization Logic](#prioritization-logic)). It does not prove exploitability beyond what the supplied evidence already shows — an analysis may describe something as *potentially* exploitable, never assert exploitation occurred unless the evidence itself proves it. It does not independently verify a vulnerability: a possible-false-positive judgment is exactly that, a judgment with a stated likelihood, never an automatic deletion or suppression of the underlying `Finding`. The original scanner findings remain the source of truth; a `SecurityAnalysis` is an opinion layered on top of them, not a replacement for them.

### Architecture: provider abstraction

```
AnalysisService → SecurityAnalysisExecutor → SecurityAnalysisModel → provider adapter → AI provider
```

- **`SecurityAnalysisModel`** (`modules/analysis/security-analysis-model.ts`) is the provider-neutral interface — one method, `analyzeSecurityFindings(input) → SecurityAnalysisOutput`. Nothing outside a concrete provider adapter constructs a provider API request or parses a provider response body, mirroring `ZapClient`'s role for ZAP.
- **`GeminiSecurityAnalysisModel`** (`modules/analysis/providers/gemini-security-analysis-model.ts`) is the initial implemented provider: Google Gemini via `@google/genai`. A future second provider would be a new class implementing the same interface — no change required anywhere else in the codebase. The abstraction exists so adding or swapping providers doesn't require touching `AnalysisService`, the executor, the prompt, or the output schema.
- **`SecurityAnalysisExecutor`** (`modules/analysis/security-analysis-executor.ts`) is the real executor: `queued` → deterministic input → model call → schema + id-reference validation → transactional persistence → terminal state, calling `analysis.service.ts`'s existing atomic lifecycle functions (`startAnalysis`/`completeAnalysis`/`failAnalysis`) at each step — it never writes `SecurityAnalysis.status` directly.

Unlike `ZapScanExecutor`, there is no concurrency-limiting mutex: an AI provider call has no shared mutable daemon state to serialize around (each call is an independent HTTP request), so analyses for *different* scans may run concurrently without restriction. Duplicate analysis of the *same* scan is prevented earlier, at creation time — see [Concurrency & Duplicate Prevention](#concurrency--duplicate-prevention).

### AI provider configuration

Server-side environment variables only (see [Environment Variables](#supported-variables)) — `GEMINI_API_KEY` is never exposed to the browser (there is no `NEXT_PUBLIC_*` equivalent anywhere in this codebase) and never logged. `GEMINI_API_KEY` is deliberately optional: the API still boots and every other feature keeps working without it. A `POST /scans/:scanId/analyze` request made without one is accepted (the `SecurityAnalysis` row is created, `202`), but the analysis itself finishes `failed` with a safe, generic error message the first time the executor actually calls the provider — exactly the same failure path as a real provider outage, no special-casing. `AI_PROVIDER`, `AI_MODEL`, `ANALYSIS_TIMEOUT_MS`, and `ANALYSIS_MAX_OUTPUT_TOKENS` round out the configuration (provider selection, model selection, provider-call timeout, output size ceiling).

### Structured output contract — never free-form text

The AI's free-form reasoning is never trusted or stored directly. `securityAnalysisOutputSchema` (`modules/analysis/security-analysis-output.schema.ts`, Zod) is the actual gate every provider's output must pass before anything is persisted:

```
{
  overallRisk, executiveSummary, methodologySummary?,
  keyRisks: string[],
  findingAssessments: [{ findingId, priority, riskAssessment, confidence, reasoning,
                          businessImpact?, technicalImpact?, remediationPriority,
                          falsePositiveLikelihood }],
  correlations: [{ findingAId, findingBId, relationship, confidence, explanation }],
  remediationPriorities: string[],
  limitations: string[],
}
```

`GeminiSecurityAnalysisModel` gets Gemini to emit this shape via **structured schema generation** (`responseMimeType: "application/json"` with `responseSchema` constrained to the analysis schema) — and the response is validated against `securityAnalysisOutputSchema` independently before persistence. If the response is malformed, has an invalid enum value, or is missing a required field, the schema rejects it and the whole analysis is marked `failed` — never partially persisted.

**Referential integrity beyond the schema:** every `findingId`/`findingAId`/`findingBId` in the output must be one of the ids actually present in that analysis's `SecurityAnalysisInput` — checked separately, after schema validation, by `assertKnownFindingIds` (`security-analysis-executor.ts`). An id the schema itself can't catch (a syntactically valid UUID that simply wasn't supplied) is treated as the AI having invented a reference, and rejects the analysis the same way a schema failure does.

### AI input contract — deterministic and sanitized

`SecurityAnalysisInput` (`modules/analysis/security-analysis-input.ts`) is built once per analysis, by `buildSecurityAnalysisInput` (`analysis-preprocessing.ts`), from already-persisted findings — never assembled ad hoc:

```
{
  scan: { id, targetName, targetOrigin },
  findingCounts: { critical, high, medium, low, informational, total },
  findings: [{ id, title, description, severity, confidence, category, cweId, wascId,
               remediation, references, instances: [{ url, method, parameter, attack, evidence }] }],
  truncatedFindingsCount,
}
```

Never sent: passwords, cookies, Authorization headers, API keys, session tokens, database credentials, unrelated user data, or raw ZAP API credentials — none of these ever exist on a `Finding`/`FindingInstance` row to begin with (see [Sanitization](#sanitization) in the Findings section), and every text field is sanitized a **second** time here regardless (defense in depth — "deterministic preprocessing" means the AI input is never simply whatever is in the database right now with no independent bound of its own). `findingCounts` is computed by the application from the persisted `Finding` table, never left for the AI to (re)count.

Deterministic preprocessing, in order: load findings for the scan (ownership already verified by `analysis.service.ts` before this ever runs) → re-sanitize every text field (`lib/sanitize-text.ts`, the same redaction rules Stage 5 uses) → sort findings by severity (highest first), tie-broken by `id` for full determinism (`createdAt` is not used for the primary sort — Stage 5 persists every finding for a scan in one transaction, so rows from the same scan commonly share an identical `createdAt`, which would make ordering by it effectively unstable) → bound the finding/instance counts and every string length → report how many findings were truncated, if any.

### Input size / token safety — explicit, documented limits

| Limit | Value |
| :--- | :--- |
| Findings per analysis | 40 (highest severity kept first; `truncatedFindingsCount` reports the rest) |
| Instances per finding | 5 |
| Title length | 300 chars |
| Description length | 1,500 chars |
| Remediation length | 1,500 chars |
| URL length | 1,000 chars |
| Parameter length | 200 chars |
| Attack payload length | 500 chars |
| Evidence length | 500 chars |
| References per finding | 10, 300 chars each |

Every cap uses `lib/sanitize-text.ts`'s redact-then-truncate ordering: redaction always runs *before* length-capping, so a would-be-secret sitting right at the truncation boundary is still fully redacted rather than half-truncated into something that looks safe but isn't (the same rule Stage 5 documents in [Sanitization](#sanitization)).

### Prompt versioning

`SECURITY_ANALYSIS_PROMPT_VERSION` (`modules/analysis/analysis-prompt.ts`, currently `"1.0"`) is recorded on every `SecurityAnalysis` row at creation time — before the model is ever called, so it's always present even if the analysis later fails. Bumping the prompt's meaning should always bump this string, so a later prompt change never silently reinterprets what an older, already-completed analysis actually reasoned from.

The system prompt establishes: reason only from supplied evidence; every finding/correlation id must be copied exactly from the input, never invented; never claim exploitation occurred unless the evidence proves it; never claim an `attack-chain` relationship unless the evidence for both findings actually supports it (prefer `related` with an explanation when uncertain); the scanner's own severity/confidence are fixed facts the model never restates or contradicts; a possible false positive is reported as a likelihood with reasoning, never asserted as fact; remediation must be specific and actionable, not generic.

### Prioritization logic

`FindingAssessment.priority` (and `.remediationPriority`) are **deliberately separate columns from `Finding.severity`**, and no code path anywhere ever writes one from the other. The AI may rank a finding's priority above or below its scanner-assigned severity when the supplied evidence or its correlation with other findings justifies that — e.g. a `medium`-severity header finding whose priority is elevated to `high` because it combines with another finding to expose a sensitive workflow — but `Finding.severity` itself never changes, and the prompt requires `reasoning` to explain any such divergence. A frontend (a later stage) is expected to display both values side by side, never one in place of the other.

### False-positive handling

`FindingAssessment.falsePositiveLikelihood` (`low`/`medium`/`high`/`unknown`) is a likelihood judgment with accompanying `reasoning`/`riskAssessment` text — never a verdict, and never wired to delete, hide, or otherwise suppress the underlying `Finding` or `FindingInstance` anywhere in this codebase. Human review remains authoritative; nothing in Stage 6 automates acting on a false-positive judgment.

### Correlation logic

`FindingCorrelation.relationship` is a closed, controlled list (`CORRELATION_RELATIONSHIPS` in `modules/analysis/analysis-enums.ts`): `related`, `duplicate-symptom`, `attack-chain`, `shared-root-cause`, `amplifies-risk` — the AI can never invent an arbitrary relationship label; an output using any other string fails schema validation. Every correlation must include both participating finding ids, a relationship type, a confidence level, and a concrete `explanation` grounded in the supplied evidence — the prompt explicitly instructs the model to prefer `related` with a hedged explanation over an unsupported `attack-chain` claim. Correlation pairs are canonicalized to lexicographic `(findingAId, findingBId)` order and deduplicated before persistence (`canonicalizeCorrelations`, `security-analysis-executor.ts`), so the model reporting the same pair twice (or in reversed order) never produces two rows.

### Persistence & transactions

`SecurityAnalysis` reaches `completed` only once the model's output has been schema-validated **and** every id it references has been confirmed to exist in the input — never before. `AnalysisRepository.completeAnalysis` wraps the `running → completed` compare-and-swap update together with every `FindingAssessment`/`FindingCorrelation` insert in one Prisma `$transaction`: either the whole result lands, or none of it does. This transaction is never held open during the AI provider call itself — it covers only the short persistence/finalization phase, after the model has already responded and been validated. If persistence fails for any reason (a rolled-back transaction, an unexpected constraint violation), the analysis is reported `failed` with a safe message, never presented as a successful analysis with some of its assessments or correlations silently missing.

### Analysis lifecycle

```
queued ──> running ──┬──> completed
                      └──> failed
```

| From | May transition to |
| :--- | :--- |
| `queued` | `running` |
| `running` | `completed`, `failed` |
| `completed` / `failed` | *(terminal — nothing)* |

Both `completed` and `failed` are terminal — there is no transition back out of `failed`. That is a deliberate consequence of the uniqueness strategy below, not a separate decision: since a scan may have at most one `SecurityAnalysis` row, a failed analysis simply cannot be retried in place within Stage 6.

### Asynchronous execution

`POST /scans/:scanId/analyze` creates the `SecurityAnalysis` row and returns `202` immediately — it does not wait for the AI provider call to finish. `analysis.service.ts`'s `requestAnalysis` fires `analysisExecutor.execute(...)` in the background (`void executor.execute(...).catch(...)`), the identical fire-and-forget shape `scan.service.ts`'s `createScan` uses for `ZapScanExecutor`. A real provider call can take tens of seconds; the HTTP request must not block for that.

### Concurrency & duplicate prevention

Stage 6 does not add rate-limiting infrastructure — that is documented here as explicit future production hardening, not implemented yet. What Stage 6 *does* prevent is an **accidental duplicate concurrent analysis job for the same scan**: `SecurityAnalysis.scanId` carries a real database `@unique` constraint, and `requestAnalysis` attempts `AnalysisRepository.create` directly rather than a separate check-then-create step — a unique-constraint violation (P2002) is translated into a clean `409 ANALYSIS_ALREADY_EXISTS`. This is what makes two concurrent `POST /scans/:scanId/analyze` requests for the same scan resolve safely: exactly one `create` call can ever succeed, at the database level, regardless of request timing.

### Analysis re-runs

**Stage 6 decision: at most one `SecurityAnalysis` per scan, full stop.** `POST /scans/:scanId/analyze` refuses with `409 ANALYSIS_ALREADY_EXISTS` once any row exists for a scan, in any status — including `failed`. This is deliberately conservative, not an oversight: real multi-version analysis (re-running with a new prompt version or model while keeping prior results, the way a scan's own history is kept) is explicit future work. Introducing it later means relaxing `SecurityAnalysis.scanId`'s constraint (e.g. to `@@unique([scanId, promptVersion])`) or introducing an explicit "current analysis" pointer alongside a full history table — not changing anything else about this model's shape or the analysis pipeline itself. A completed analysis is therefore never silently overwritten by a rerun today, and a failed one is not automatically retryable in place; recovering from a failed analysis in Stage 6 requires operator intervention (e.g. deleting the row), which is intentionally out of scope for the HTTP API itself.

### Auditability

Every `SecurityAnalysis` row records `model`, `promptVersion`, `createdAt`, `scanId`, and `status` — enough to understand how an analysis was produced without storing anything sensitive. No API key, no provider request/response body, and no raw prompt/input are ever persisted; only the validated structured result (`overallRisk`, `executiveSummary`, and the child `FindingAssessment`/`FindingCorrelation` rows) is stored.

### No AI memory, no autonomous action

No vector database, no embeddings, no long-term AI memory — every analysis reasons over exactly one scan's current findings, nothing more. No cross-scan intelligence exists yet; that is explicitly left to a future, separately-designed stage. The AI never executes commands, makes arbitrary network requests, launches scans, calls ZAP directly, generates or executes exploits, or modifies a target application, infrastructure, or credentials — it is an analyst, never an autonomous agent.

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

### Opt-in local live-test access

The normal Compose topology deliberately keeps ZAP port `8090` off the host.
For the Stage 8 live test only, a developer may start Compose with the
untracked-secret-safe override at the workspace root:

```bash
docker compose -f docker-compose.yml -f docker-compose.live-test.yml up -d --build
```

That override binds ZAP to `127.0.0.1:8090` only; it does not publish the
daemon to a LAN interface or the public internet. Put `GEMINI_API_KEY`, the
real/disposable `DATABASE_URL`, and an explicitly authorized public
`LIVE_TARGET_URL` in the ignored local `.env`.

**A plain `npm test` never makes a real external call in
`tests/live-integration.test.ts`, even if `LIVE_TARGET_URL` and
`GEMINI_API_KEY` are both sitting in your local `.env`.** Those secrets being
present is necessary but never sufficient on their own — both of the file's
real-network checks additionally require the same explicit, separate opt-in:
`RUN_LIVE_INTEGRATION_TEST=true`.

- **"3. Gemini AI Provider Live Verification"** makes one real, billed call to
  Gemini to confirm the provider adapter works end to end. Without the opt-in
  flag, it runs a local fail-close check instead (no network call).
- **"4. End-to-End Pipeline Execution"** runs the full real
  `Target → Scan → ZapScanExecutor → ZAP → Findings → Gemini →
  SecurityAnalysis` pipeline against `LIVE_TARGET_URL`. Without the opt-in
  flag, it is skipped entirely.

This exists specifically so that having live-test secrets configured locally
— for instance while working on the Gemini adapter, without meaning to run
a live scan — can never cause an ordinary test run to silently make a real
provider call or kick off a real scan against `LIVE_TARGET_URL`. To actually
run the full live pipeline:

```bash
RUN_LIVE_INTEGRATION_TEST=true ZAP_BASE_URL=http://127.0.0.1:8090 npm test -- --run tests/live-integration.test.ts
```

Each real-network check remains skipped (in favor of its safe, local
fallback) unless `RUN_LIVE_INTEGRATION_TEST=true` **and** its own required
secret(s) (`GEMINI_API_KEY`, and for the full pipeline also `LIVE_TARGET_URL`)
are all present — missing any one of them skips it; the flag alone, without
real prerequisites, is never enough to trigger a real scan. It does not
invent a target, bypass target safety, or treat a scan-only run as a full
validation.

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

## Production Deployment (Render + Vercel)

The intended production topology:

```
Vercel                          Render                         Neon
┌────────────────────┐          ┌───────────────────────┐      ┌──────────────┐
│  sentinelscan-web   │  HTTPS   │  sentinelscan-api      │      │  PostgreSQL  │
│  (Next.js frontend) │ ───────▶ │  (this repo, Dockerfile)│────▶│              │
└────────────────────┘          │                         │      └──────────────┘
                                 │  private network only   │
                                 │           │              │
                                 │           ▼              │
                                 │  sentinelscan-zap        │
                                 │  (private Render service,│
                                 │   ZAP API key required)  │
                                 └───────────────────────┘
```

`sentinelscan-web` is a static/SSR Next.js app on Vercel; every request it needs served goes to `sentinelscan-api` on Render over HTTPS with credentials (cookies). `sentinelscan-api` is the only thing that ever talks to Neon or to the ZAP daemon — neither is reachable from the browser, from Vercel, or from the public internet.

### LOCAL vs PRODUCTION — the two configurations are deliberately different

| | LOCAL (`docker-compose.yml`, or `npm run dev`) | PRODUCTION (Render + Vercel) |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | `production` (set by Render) |
| ZAP reachability | Internal Docker network (`owasp-zap:8090`), or `http://localhost:8090` for `npm run dev` | Render **private service** (`sentinelscan-zap:8090`) — no public port |
| ZAP authentication | `api.disablekey=true` (no key required) | `ZAP_API_KEY` **required** — ZAP configured with `-config api.key=<value>`, never `api.disablekey=true` |
| `JWT_SECRET` | The committed dev-only compose default, or any 32+ char local value | A real, randomly generated secret — see [Environment Variables](#supported-variables). `config.ts` refuses to boot in production with a known development/placeholder value |
| Session cookie | `secure: false`, `SameSite=Lax` (works over plain `http://localhost`) | `secure: true`, `SameSite=None` (required for the cross-origin Vercel ↔ Render cookie flow) — see [Authentication → Mechanism](#mechanism) |
| `WEB_APP_URL` | `http://localhost:3000` | The real Vercel `https://` origin — `config.ts` refuses a non-`https://` value in production |
| `DATABASE_URL` | Local/disposable Postgres, or a Neon dev branch | The production Neon connection string — `config.ts` refuses the example/mock placeholder values in production |

This is enforced, not just documented: `parseEnv()` (`src/config.ts`) runs a **production-only** validation pass whenever `NODE_ENV=production` and refuses to start the process if `JWT_SECRET` matches a known development/placeholder value, `WEB_APP_URL` isn't `https://`, or `DATABASE_URL` looks like one of the example/mock values shipped in this repo (`.env.example`, `docker-compose.yml`). It also logs a startup warning (not a hard failure, since it can't verify the separately-deployed ZAP daemon's own configuration) if `ZAP_API_KEY` is unset in production. None of these checks run in `development`/`test`, so local work and CI are unaffected.

### What must be configured manually in Render

1. **`sentinelscan-api` web service** — deploy from this repo's `Dockerfile`. Set every required variable from [Environment Variables](#supported-variables) in Render's dashboard: `DATABASE_URL` (the Neon connection string), `JWT_SECRET` (freshly generated, never the compose/example value), `WEB_APP_URL` (the Vercel deployment's `https://` origin), `ZAP_BASE_URL=http://sentinelscan-zap:8090`, `ZAP_API_KEY` (a real value, matching what the ZAP service is configured with), and `GEMINI_API_KEY` if AI analysis is enabled. Do **not** set `LIVE_TARGET_URL` or `RUN_LIVE_INTEGRATION_TEST` — see [Opt-in local live-test access](#opt-in-local-live-test-access); they belong to `tests/live-integration.test.ts` alone and are never read by the application.
2. **`sentinelscan-zap` private service** — deploy the ZAP image (`ghcr.io/zaproxy/zaproxy:stable`) as a **private** Render service (no public URL) on the same private network as `sentinelscan-api`, with a start command that requires a key: `zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=<the same value as ZAP_API_KEY above> -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true`. Never give this service a public Render URL, and never set `api.disablekey=true` here.
3. **Neon PostgreSQL** — a production Neon project/branch, with `DATABASE_URL` pointing at it. `npx prisma migrate deploy` (already the Dockerfile's `CMD`) applies pending migrations on every deploy; it never resets data.
4. Confirm Render's health check is pointed at `GET /health` (not `/health/zap`, which reflects ZAP's own reachability and would make the whole API service look unhealthy during a transient ZAP restart).

### What must be configured manually in Vercel

1. Deploy `sentinelscan-web` from its own repository.
2. Set the frontend's API base URL environment variable to the Render `sentinelscan-api` service's `https://` URL.
3. No secrets belong in Vercel's environment for this app: `sentinelscan-web` never holds `JWT_SECRET`, `GEMINI_API_KEY`, `ZAP_API_KEY`, or `DATABASE_URL` — every one of those stays server-side on Render, and the frontend talks to `sentinelscan-api` only over plain HTTPS with credentialed cookies.

### Known limitations that don't change for production

Scan execution is still the in-process executor described in [Triggering execution](#triggering-execution--in-process-non-blocking) and [Concurrency & isolation](#concurrency--isolation): it isn't backed by a durable queue, a process restart mid-scan leaves that scan stuck `running` with nothing to reconcile it, and it doesn't scale across multiple `sentinelscan-api` instances. This is an accepted, documented limitation for a single-instance Render deployment — introducing a queue (Redis/BullMQ/etc.) is explicitly out of scope until a concrete requirement (horizontal scaling, or automatic recovery of interrupted scans) makes it necessary.
