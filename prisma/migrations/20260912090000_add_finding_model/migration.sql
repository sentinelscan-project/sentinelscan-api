-- CreateEnum
CREATE TYPE "FindingSeverity" AS ENUM ('critical', 'high', 'medium', 'low', 'informational');

-- CreateEnum
CREATE TYPE "FindingConfidence" AS ENUM ('high', 'medium', 'low', 'unknown');

-- CreateTable
CREATE TABLE "findings" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "FindingSeverity" NOT NULL,
    "confidence" "FindingConfidence" NOT NULL,
    "category" TEXT NOT NULL,
    "cweId" INTEGER,
    "wascId" INTEGER,
    "remediation" TEXT,
    "references" JSONB,
    "source" TEXT NOT NULL,
    "sourceRuleId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_instances" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "method" TEXT,
    "parameter" TEXT,
    "attack" TEXT,
    "evidence" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_instances_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "findings_scanId_idx" ON "findings"("scanId");

-- CreateIndex
CREATE INDEX "findings_scanId_severity_idx" ON "findings"("scanId", "severity");

-- CreateIndex
CREATE UNIQUE INDEX "findings_scanId_source_sourceRuleId_key" ON "findings"("scanId", "source", "sourceRuleId");

-- CreateIndex
CREATE INDEX "finding_instances_findingId_idx" ON "finding_instances"("findingId");

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_instances" ADD CONSTRAINT "finding_instances_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

