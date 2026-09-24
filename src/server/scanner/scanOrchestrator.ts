import { ScanResult, VulnerabilityFinding, ApiEndpoint } from '../../types/security';
import { parseOpenApiSpec, OpenApiParseError } from './openapiParser';
import { discoverEndpoints } from './endpointDiscovery';
import { scanAuthorization } from './authorizationScanner';
import { scanDataExposure } from './dataExposureScanner';
import { scanRateLimiting } from './rateLimitScanner';
import { scanAuthentication } from './authenticationScanner';
import { deduplicateFindings, correlateEndpointsWithFindings } from './findingEngine';
import { calculateSecurityScore } from './scoringEngine';
import { FOOD_DELIVERY_OPENAPI_SPEC } from '../../data/foodDeliverySpec';

export interface ScanExecutionOptions {
  specContent?: string | object;
  isDemoSandbox?: boolean;
  targetBaseUrl?: string;
  isAuthorized?: boolean;
  onStageProgress?: (stageIndex: number, stageName: string, detail: string) => void;
}

export interface ScanStageInfo {
  index: number;
  name: string;
  detail: string;
}

// Security Scope Guardrail Validator
export function validateTargetScope(url: string, isDemoSandbox = false): boolean {
  if (isDemoSandbox) return true;
  if (!url) return true; // defaults to local sandbox

  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();

    // Allowed local sandbox and authorized loopback domains
    const isLocal =
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host.endsWith('.internal.test') ||
      host.endsWith('.local') ||
      host.includes('run.app'); // AI Studio container dev preview

    return isLocal;
  } catch {
    // Relative path or invalid URL fallback to local
    return url.startsWith('/') || url.startsWith('http://127.0.0.1');
  }
}

export async function orchestrateScan(options: ScanExecutionOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const stages: ScanStageInfo[] = [];

  const logStage = (index: number, name: string, detail: string) => {
    stages.push({ index, name, detail });
    if (options.onStageProgress) {
      options.onStageProgress(index, name, detail);
    }
  };

  // STAGE 1: Parsing OpenAPI / Swagger Specification
  logStage(0, 'Parsing OpenAPI Specification', 'Parsing OpenAPI 3.x / Swagger 2.0 contract...');
  let rawSpecInput = options.specContent;
  if (options.isDemoSandbox || !rawSpecInput) {
    rawSpecInput = FOOD_DELIVERY_OPENAPI_SPEC;
  }

  let parsedSpec;
  try {
    parsedSpec = parseOpenApiSpec(rawSpecInput);
    logStage(0, 'Parsing OpenAPI Specification', `[✓] Successfully parsed ${parsedSpec.format.toUpperCase()} specification: "${parsedSpec.title}" (v${parsedSpec.version})`);
  } catch (err: any) {
    if (err instanceof OpenApiParseError) {
      throw err;
    }
    throw new OpenApiParseError(`Failed to parse specification: ${err.message}`);
  }

  // Target Scope Validation
  const effectiveBaseUrl =
    options.targetBaseUrl || parsedSpec.baseUrl || 'http://127.0.0.1:3000/api/sandbox';

  if (!validateTargetScope(effectiveBaseUrl, options.isDemoSandbox)) {
    throw new Error(
      `Target host "${effectiveBaseUrl}" is not an authorized test environment. SentinelAPI defensive engine strictly prohibits scanning unauthorized external hosts.`
    );
  }

  // STAGE 2: Discovering Endpoints
  logStage(1, 'Discovering Endpoints', 'Enumerating routes, HTTP methods, and parameter schemas...');
  const discoveredEndpoints = discoverEndpoints(parsedSpec);
  logStage(1, 'Discovering Endpoints', `[✓] Discovered ${discoveredEndpoints.length} endpoints across API surface`);

  const scanTarget = {
    baseUrl: effectiveBaseUrl,
    isSandbox: Boolean(options.isDemoSandbox || effectiveBaseUrl.includes('127.0.0.1') || effectiveBaseUrl.includes('localhost'))
  };

  // STAGE 3: Authentication Configuration Analysis
  logStage(2, 'Analyzing Authentication', 'Evaluating security definitions, scopes, and route policies...');
  const authFindings = await scanAuthentication(discoveredEndpoints, scanTarget);
  logStage(2, 'Analyzing Authentication', `[✓] Completed authentication audit (${authFindings.length} issue(s) identified)`);

  // STAGE 4: Testing Authorization Boundaries (BOLA / IDOR)
  logStage(3, 'Testing Authorization Boundaries', 'Testing cross-tenant object ownership permissions between sandbox identities...');
  const bolaFindings = await scanAuthorization(discoveredEndpoints, scanTarget);
  logStage(3, 'Testing Authorization Boundaries', `[✓] Completed authorization testing (${bolaFindings.length} BOLA finding(s) verified)`);

  // STAGE 5: Checking Response Data Exposure
  logStage(4, 'Checking Response Exposure', 'Inspecting response payloads and schemas for sensitive credentials/PII...');
  const exposureFindings = await scanDataExposure(discoveredEndpoints, scanTarget);
  logStage(4, 'Checking Response Exposure', `[✓] Completed data exposure analysis (${exposureFindings.length} schema leak(s) detected)`);

  // STAGE 6: Checking Rate Limiting
  logStage(5, 'Checking Rate Limiting', 'Executing safe bounded probe bursts to check throttling headers...');
  const rateFindings = await scanRateLimiting(discoveredEndpoints, scanTarget);
  logStage(5, 'Checking Rate Limiting', `[✓] Completed rate limiting checks (${rateFindings.length} weak endpoint(s) flagged)`);

  // STAGE 7: Generating Findings
  logStage(6, 'Generating Findings', 'Correlating and deduplicating defensive vulnerability findings...');
  const rawFindings: VulnerabilityFinding[] = [
    ...bolaFindings,
    ...exposureFindings,
    ...rateFindings,
    ...authFindings
  ];
  const findings = deduplicateFindings(rawFindings);
  const endpoints = correlateEndpointsWithFindings(discoveredEndpoints, findings);
  logStage(6, 'Generating Findings', `[✓] Compiled ${findings.length} validated vulnerability finding(s)`);

  // STAGE 8: Calculating Security Score
  logStage(7, 'Calculating Security Score', 'Computing transparent deduction-based defensive score...');
  const score = calculateSecurityScore(findings, endpoints);
  logStage(7, 'Calculating Security Score', `[✓] Final Security Score: ${score.currentScore}/100 (Grade ${score.ratingGrade})`);

  logStage(8, 'Scan Complete', `Scan completed successfully in ${Math.max(1, Math.round((Date.now() - startTime) / 1000))}s.`);

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH' && f.status === 'OPEN').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM' && f.status === 'OPEN').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW' && f.status === 'OPEN').length;
  const infoCount = findings.filter((f) => f.severity === 'INFO' && f.status === 'OPEN').length;

  return {
    scanId: `SCN-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    apiName: parsedSpec.title,
    apiVersion: parsedSpec.version,
    baseUrl: effectiveBaseUrl,
    targetScope: options.isDemoSandbox ? 'LOCAL_SANDBOX' : 'AUTHORIZED_TEST',
    totalEndpoints: endpoints.length,
    endpoints,
    findings,
    score,
    summary: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      info: infoCount,
      resolved: 0
    },
    durationSeconds: Math.max(1, Math.round((Date.now() - startTime) / 1000))
  };
}
