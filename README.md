# SentinelScan API (`sentinelscan-api`)

## Overview
`sentinelscan-api` is the backend API service for **SentinelScan**. Built with Fastify and TypeScript, it provides the core API foundation, environment configuration validation with Zod, PostgreSQL database connection setup using Prisma, centralized logging and error handling, and container packaging.

> **Stage 0 Notice**: Application business features (authentication, Google OAuth, JWT, user management, targets, scans, AI analysis, vulnerability processing, and reports) are deliberately not implemented at this stage. This repository contains only the minimal backend foundation.

---

## Technology Stack
- **Runtime**: Node.js v22 LTS
- **Framework**: Fastify 5
- **Language**: TypeScript (Strict mode enabled)
- **Database ORM**: Prisma 6 (configured for Neon PostgreSQL)
- **Validation**: Zod
- **Testing**: Vitest
- **Linting**: ESLint
- **Containerization**: Docker (multi-stage)
- **CI/CD**: Jenkins

---

## Project Structure
```
sentinelscan-api/
├── prisma/
│   └── schema.prisma         # Minimal Prisma datasource configuration
├── src/
│   ├── app.ts                # Fastify app factory with middleware & error handling
│   ├── config.ts             # Zod environment validation & startup check
│   ├── server.ts             # Server entrypoint with graceful shutdown
│   └── routes/
│       └── health.ts         # GET /health endpoint
├── tests/
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

> **Security Rule**: Environment variables are strictly validated on startup using Zod. If required variables are missing, the server fails fast with clear errors while never leaking secrets or connection strings in logs.

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

## CI/CD Pipeline (Jenkins)
The repository includes a declarative `Jenkinsfile` with the following stages:
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

### GitHub → Jenkins Webhook Integration (Future Setup)
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
