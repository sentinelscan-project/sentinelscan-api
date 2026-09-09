-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');

-- CreateTable
CREATE TABLE "scans" (
    "id" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "requestedById" TEXT NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'queued',
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "scans_targetId_idx" ON "scans"("targetId");

-- CreateIndex
CREATE INDEX "scans_requestedById_idx" ON "scans"("requestedById");

-- CreateIndex
CREATE INDEX "scans_status_idx" ON "scans"("status");

-- CreateIndex
CREATE INDEX "scans_requestedById_createdAt_idx" ON "scans"("requestedById", "createdAt");

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "targets"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

