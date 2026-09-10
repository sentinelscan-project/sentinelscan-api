import { z } from "zod";
import {
  ANALYSIS_CONFIDENCE_LEVELS,
  ASSESSMENT_PRIORITIES,
  CORRELATION_RELATIONSHIPS,
  FALSE_POSITIVE_LIKELIHOODS,
  OVERALL_RISK_LEVELS,
} from "./analysis-enums.js";

/**
 * The strict schema every `SecurityAnalysisModel` provider's output must
 * satisfy before anything is persisted. This is the primary application
 * contract — the AI's free-form reasoning is never trusted or stored
 * directly; only a response that validates against this schema is accepted.
 * A provider adapter is responsible for getting the model to emit this shape
 * (e.g. via schema-constrained/tool-use output), but this schema is the
 * actual gate, independent of how any one provider tries to comply with it.
 *
 * Referential integrity (every `findingId`/`findingAId`/`findingBId` here
 * must be one of the ids actually supplied in the `SecurityAnalysisInput`)
 * is deliberately NOT checked here — this schema has no access to that
 * context. That check happens separately, in
 * `security-analysis-executor.ts`'s `assertKnownFindingIds`, immediately
 * after this schema validates the shape.
 */

const overallRiskSchema = z.enum(OVERALL_RISK_LEVELS);
const assessmentPrioritySchema = z.enum(ASSESSMENT_PRIORITIES);
const confidenceSchema = z.enum(ANALYSIS_CONFIDENCE_LEVELS);
const falsePositiveLikelihoodSchema = z.enum(FALSE_POSITIVE_LIKELIHOODS);
const relationshipSchema = z.enum(CORRELATION_RELATIONSHIPS);

const MAX_ASSESSMENTS = 60;
const MAX_CORRELATIONS = 60;
const MAX_LIST_ITEMS = 25;

const findingAssessmentOutputSchema = z.object({
  findingId: z.string().uuid(),
  priority: assessmentPrioritySchema,
  riskAssessment: z.string().trim().min(1).max(2000),
  confidence: confidenceSchema,
  reasoning: z.string().trim().min(1).max(2000),
  businessImpact: z.string().trim().min(1).max(1000).optional(),
  technicalImpact: z.string().trim().min(1).max(1000).optional(),
  remediationPriority: assessmentPrioritySchema,
  falsePositiveLikelihood: falsePositiveLikelihoodSchema,
});

const findingCorrelationOutputSchema = z
  .object({
    findingAId: z.string().uuid(),
    findingBId: z.string().uuid(),
    relationship: relationshipSchema,
    confidence: confidenceSchema,
    explanation: z.string().trim().min(1).max(1000),
  })
  .refine((value) => value.findingAId !== value.findingBId, {
    message: "A correlation cannot relate a finding to itself",
    path: ["findingBId"],
  });

export const securityAnalysisOutputSchema = z.object({
  overallRisk: overallRiskSchema,
  executiveSummary: z.string().trim().min(1).max(4000),
  methodologySummary: z.string().trim().min(1).max(2000).optional(),
  keyRisks: z.array(z.string().trim().min(1).max(500)).max(MAX_LIST_ITEMS),
  findingAssessments: z.array(findingAssessmentOutputSchema).max(MAX_ASSESSMENTS),
  correlations: z.array(findingCorrelationOutputSchema).max(MAX_CORRELATIONS),
  remediationPriorities: z.array(z.string().trim().min(1).max(500)).max(MAX_LIST_ITEMS),
  limitations: z.array(z.string().trim().min(1).max(500)).max(MAX_LIST_ITEMS),
});

export type SecurityAnalysisOutput = z.infer<typeof securityAnalysisOutputSchema>;
export type FindingAssessmentOutput = z.infer<typeof findingAssessmentOutputSchema>;
export type FindingCorrelationOutput = z.infer<typeof findingCorrelationOutputSchema>;
