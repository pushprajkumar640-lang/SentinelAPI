export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnerabilityCategory =
  | 'BOLA_IDOR'
  | 'EXCESSIVE_DATA_EXPOSURE'
  | 'WEAK_RATE_LIMITING'
  | 'AUTH_MISCONFIGURATION'
  | 'SECURITY_HEADERS'
  | 'INPUT_VALIDATION';

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: Severity;
  category: VulnerabilityCategory;
  owaspCategory: string; // e.g. 'API1:2023 - Broken Object Level Authorization'
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  description: string;
  evidence: string;
  impact: string;
  reproduction: {
    summary: string;
    request1?: {
      description: string;
      raw: string;
      expectedStatus: number;
      actualStatus: number;
      sampleResponse: string;
    };
    request2?: {
      description: string;
      raw: string;
      expectedStatus: number;
      actualStatus: number;
      sampleResponse: string;
    };
  };
  remediation: {
    summary: string;
    codeSnippet: string;
    language: string;
    bestPractices: string[];
  };
  status: 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'IN_REVIEW';
  detectedAt: string;
  aiExplanation?: string;
  aiRemediationGuidance?: string;
}

export interface ApiEndpoint {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  summary: string;
  description?: string;
  requiresAuth: boolean;
  authType?: string;
  riskLevel: Severity;
  parameters: Array<{
    name: string;
    in: 'path' | 'query' | 'header' | 'body';
    required: boolean;
    type: string;
    description?: string;
  }>;
  requestBodySchema?: string;
  responseSchema?: string;
  findingsCount: number;
  lastScanned?: string;
  status: 'SCANNED' | 'TESTED' | 'UNTESTED';
}

export interface ApiSpecification {
  id: string;
  name: string;
  version: string;
  baseUrl: string;
  description: string;
  authTypes: string[];
  totalEndpoints: number;
  methodsCount: Record<string, number>;
  rawSpec: string;
  format: 'json' | 'yaml';
}

export interface SecurityScoreBreakdown {
  currentScore: number;
  baseScore: number;
  deductions: {
    criticalCount: number;
    criticalDeduction: number;
    highCount: number;
    highDeduction: number;
    mediumCount: number;
    mediumDeduction: number;
    lowCount: number;
    lowDeduction: number;
  };
  authCoveragePercentage: number;
  ratingGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface ScanProgressStage {
  id: string;
  label: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  detail?: string;
  durationMs?: number;
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  apiName: string;
  apiVersion: string;
  baseUrl: string;
  targetScope: 'LOCAL_SANDBOX' | 'AUTHORIZED_TEST';
  totalEndpoints: number;
  endpoints: ApiEndpoint[];
  findings: VulnerabilityFinding[];
  score: SecurityScoreBreakdown;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    resolved: number;
  };
  durationSeconds: number;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
  codeSnippet?: string;
  relatedFindingId?: string;
}
