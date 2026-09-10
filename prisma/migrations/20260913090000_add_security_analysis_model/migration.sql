-- CreateEnum
CREATE TYPE "AnalysisStatus" AS ENUM ('queued', 'running', 'completed', 'failed');

-- CreateEnum
CREATE TYPE "OverallRisk" AS ENUM ('critical', 'high', 'medium', 'low', 'informational');

-- CreateEnum
CREATE TYPE "AssessmentPriority" AS ENUM ('critical', 'high', 'medium', 'low', 'informational');

-- CreateEnum
CREATE TYPE "FalsePositiveLikelihood" AS ENUM ('low', 'medium', 'high', 'unknown');

-- CreateTable
CREATE TABLE "security_analyses" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "status" "AnalysisStatus" NOT NULL DEFAULT 'queued',
    "model" TEXT,
    "promptVersion" TEXT NOT NULL,
    "overallRisk" "OverallRisk",
    "executiveSummary" TEXT,
    "methodologySummary" TEXT,
    "limitations" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),
    "errorMessage" TEXT,

    CONSTRAINT "security_analyses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_assessments" (
    "id" TEXT NOT NULL,
    "analysisId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "priority" "AssessmentPriority" NOT NULL,
    "riskAssessment" TEXT NOT NULL,
    "confidence" "FindingConfidence" NOT NULL,
    "reasoning" TEXT NOT NULL,
    "businessImpact" TEXT,
    "technicalImpact" TEXT,
    "remediationPriority" "AssessmentPriority" NOT NULL,
    "falsePositiveLikelihood" "FalsePositiveLikelihood" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "finding_assessments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_correlations" (
    "id" TEXT NOT NULL,
    "analysisId" TEXT NOT NULL,
    "findingAId" TEXT NOT NULL,
    "findingBId" TEXT NOT NULL,
    "relationship" TEXT NOT NULL,
    "confidence" "FindingConfidence" NOT NULL,
    "explanation" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_correlations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "security_analyses_scanId_key" ON "security_analyses"("scanId");

-- CreateIndex
CREATE INDEX "security_analyses_scanId_idx" ON "security_analyses"("scanId");

-- CreateIndex
CREATE INDEX "security_analyses_status_idx" ON "security_analyses"("status");

-- CreateIndex
CREATE INDEX "finding_assessments_analysisId_idx" ON "finding_assessments"("analysisId");

-- CreateIndex
CREATE INDEX "finding_assessments_findingId_idx" ON "finding_assessments"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "finding_assessments_analysisId_findingId_key" ON "finding_assessments"("analysisId", "findingId");

-- CreateIndex
CREATE INDEX "finding_correlations_analysisId_idx" ON "finding_correlations"("analysisId");

-- CreateIndex
CREATE INDEX "finding_correlations_findingAId_idx" ON "finding_correlations"("findingAId");

-- CreateIndex
CREATE INDEX "finding_correlations_findingBId_idx" ON "finding_correlations"("findingBId");

-- CreateIndex
CREATE UNIQUE INDEX "finding_correlations_analysisId_findingAId_findingBId_key" ON "finding_correlations"("analysisId", "findingAId", "findingBId");

-- AddForeignKey
ALTER TABLE "security_analyses" ADD CONSTRAINT "security_analyses_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_assessments" ADD CONSTRAINT "finding_assessments_analysisId_fkey" FOREIGN KEY ("analysisId") REFERENCES "security_analyses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_assessments" ADD CONSTRAINT "finding_assessments_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_correlations" ADD CONSTRAINT "finding_correlations_analysisId_fkey" FOREIGN KEY ("analysisId") REFERENCES "security_analyses"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_correlations" ADD CONSTRAINT "finding_correlations_findingAId_fkey" FOREIGN KEY ("findingAId") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_correlations" ADD CONSTRAINT "finding_correlations_findingBId_fkey" FOREIGN KEY ("findingBId") REFERENCES "findings"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

