import { parseOpenApiSpec, OpenApiParseError } from '../scanner/openapiParser';
import { discoverEndpoints } from '../scanner/endpointDiscovery';
import { scanAuthorization } from '../scanner/authorizationScanner';
import { scanDataExposure } from '../scanner/dataExposureScanner';
import { scanRateLimiting } from '../scanner/rateLimitScanner';
import { scanAuthentication } from '../scanner/authenticationScanner';
import { calculateSecurityScore } from '../scanner/scoringEngine';
import { orchestrateScan } from '../scanner/scanOrchestrator';
import { updateSandboxConfig, resetSandboxConfig } from '../sandboxService';
import { FOOD_DELIVERY_OPENAPI_SPEC } from '../../data/foodDeliverySpec';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✓ ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName} ${detail ? `(${detail})` : ''}`);
    failed++;
  }
}

async function runTests() {
  console.log('\n========================================');
  console.log('SENTINELAPI DEFENSIVE SCANNER TEST SUITE');
  console.log('========================================\n');

  // TEST 1: OpenAPI JSON Parsing
  console.log('[1] Testing OpenAPI JSON Parsing...');
  const sampleJson = JSON.stringify({
    openapi: '3.0.0',
    info: { title: 'Test Payment API', version: '2.1.0' },
    servers: [{ url: 'http://127.0.0.1:3000/api/sandbox' }],
    paths: {
      '/payments': {
        get: { summary: 'List payments', responses: { '200': { description: 'OK' } } }
      }
    }
  });

  const parsedJson = parseOpenApiSpec(sampleJson);
  assert(parsedJson.title === 'Test Payment API', 'Extracts API title from JSON');
  assert(parsedJson.version === '2.1.0', 'Extracts API version from JSON');
  assert(parsedJson.format === 'json', 'Identifies JSON format');
  assert(Boolean(parsedJson.paths['/payments']), 'Parses JSON paths');

  // TEST 2: OpenAPI YAML Parsing
  console.log('\n[2] Testing OpenAPI YAML Parsing...');
  const sampleYaml = `
openapi: "3.0.0"
info:
  title: "Test Shipping API"
  version: "1.4.0"
servers:
  - url: "http://127.0.0.1:3000/api/sandbox"
paths:
  /shipments/{id}:
    get:
      summary: "Get shipment tracking"
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: "Tracking info"
`;

  const parsedYaml = parseOpenApiSpec(sampleYaml);
  assert(parsedYaml.title === 'Test Shipping API', 'Extracts API title from YAML');
  assert(parsedYaml.version === '1.4.0', 'Extracts API version from YAML');
  assert(parsedYaml.format === 'yaml', 'Identifies YAML format');
  assert(Boolean(parsedYaml.paths['/shipments/{id}']), 'Parses YAML paths');

  // Test error handling on invalid spec
  let caughtError = false;
  try {
    parseOpenApiSpec('INVALID_NOT_JSON_OR_YAML: {{{');
  } catch (err: any) {
    caughtError = err instanceof OpenApiParseError;
  }
  assert(caughtError, 'Catches and rejects malformed specification with OpenApiParseError');

  // TEST 3: Endpoint Discovery
  console.log('\n[3] Testing Endpoint Discovery...');
  const sandboxParsed = parseOpenApiSpec(FOOD_DELIVERY_OPENAPI_SPEC);
  const discovered = discoverEndpoints(sandboxParsed);
  assert(discovered.length >= 10, `Discovered ${discovered.length} endpoints from specification`);
  const orderEndpoint = discovered.find((e) => e.path === '/orders/{orderId}');
  assert(Boolean(orderEndpoint), 'Discovered /orders/{orderId} route');
  assert(orderEndpoint?.method === 'GET', 'Correctly identified GET method');

  // TEST 4: Real BOLA / IDOR Detection using Sandbox
  console.log('\n[4] Testing BOLA / IDOR Detection against Sandbox...');
  resetSandboxConfig(); // Start with vulnerable sandbox state
  const authTarget = { baseUrl: 'http://127.0.0.1:3000/api/sandbox', isSandbox: true };
  const bolaFindings = await scanAuthorization(discovered, authTarget);
  assert(bolaFindings.length > 0, 'Detects BOLA/IDOR vulnerability in vulnerable sandbox');
  assert(bolaFindings[0].severity === 'CRITICAL', 'BOLA finding is ranked CRITICAL');
  assert(bolaFindings[0].category === 'BOLA_IDOR', 'Category is BOLA_IDOR');
  assert(bolaFindings[0].evidence.includes('User A'), 'Evidence details User A cross-tenant access');

  // TEST 5: Excessive Data Exposure Detection
  console.log('\n[5] Testing Excessive Data Exposure Detection...');
  const exposureFindings = await scanDataExposure(discovered, authTarget);
  assert(exposureFindings.length > 0, 'Detects Excessive Data Exposure in user endpoint');
  assert(exposureFindings[0].severity === 'HIGH', 'Exposure finding is ranked HIGH');
  assert(
    exposureFindings[0].evidence.toLowerCase().includes('passwordhash') ||
    exposureFindings[0].evidence.toLowerCase().includes('internalnotes'),
    'Evidence specifies exposed sensitive fields'
  );

  // TEST 6: Rate Limiting Detection
  console.log('\n[6] Testing Rate Limiting Detection...');
  const rateFindings = await scanRateLimiting(discovered, authTarget);
  assert(rateFindings.length > 0, 'Detects Weak/Missing Rate Limiting on public search');
  assert(rateFindings[0].severity === 'MEDIUM', 'Rate limiting finding is ranked MEDIUM');
  assert(rateFindings[0].evidence.includes('HTTP 200 OK'), 'Evidence reflects observed probe results');

  // TEST 7: Authentication Analysis
  console.log('\n[7] Testing Authentication Analysis...');
  const authFindings = await scanAuthentication(discovered, authTarget);
  assert(authFindings.length > 0, 'Detects Authentication Configuration issues');
  const adminAuthFinding = authFindings.find((f) => f.endpoint.includes('/admin'));
  assert(Boolean(adminAuthFinding), 'Flags missing authentication on administrative route');

  // TEST 8: Finding Severity & Deduplication
  console.log('\n[8] Testing Finding Properties and Severity...');
  const allFindings = [...bolaFindings, ...exposureFindings, ...rateFindings, ...authFindings];
  assert(allFindings.every((f) => Boolean(f.id && f.title && f.evidence && f.reproduction)), 'All findings contain required evidence & reproduction objects');

  // TEST 9: Security Score Calculation
  console.log('\n[9] Testing Real Security Score Calculation...');
  // 1 Critical (-30), 2 High (-20 each), 1 Medium (-10), 1 Low (-5)
  const calculatedScore = calculateSecurityScore(allFindings, discovered);
  assert(typeof calculatedScore.currentScore === 'number', 'Returns numeric security score');
  assert(calculatedScore.currentScore >= 0 && calculatedScore.currentScore <= 100, 'Score is bounded between 0 and 100');
  assert(calculatedScore.deductions.criticalDeduction === calculatedScore.deductions.criticalCount * 30, 'Calculates Critical = -30');
  assert(calculatedScore.deductions.highDeduction === calculatedScore.deductions.highCount * 20, 'Calculates High = -20');
  assert(calculatedScore.deductions.mediumDeduction === calculatedScore.deductions.mediumCount * 10, 'Calculates Medium = -10');
  assert(calculateSecurityScore([], discovered).currentScore === 100, 'Zero findings score 100');

  // TEST 10: Full Integration Test - Run Demo Scan
  console.log('\n[10] Running Full Integration Test (Demo Scan Pipeline)...');
  const fullScanResult = await orchestrateScan({ isDemoSandbox: true });
  assert(fullScanResult.totalEndpoints > 0, 'Returns total endpoints count');
  assert(fullScanResult.findings.length > 0, 'Generates defensive vulnerability findings');
  assert(fullScanResult.score.currentScore >= 0, 'Calculates security score');
  assert(Boolean(fullScanResult.scanId), 'Assigns unique scan ID');

  // TEST 11: Dynamic Sandbox Fix Acceptance Test
  console.log('\n[11] Testing Sandbox Vulnerability Fix Acceptance Test...');
  console.log('    --> Activating BOLA / IDOR fix in sandbox: enforceBolaCheck = true');
  updateSandboxConfig({ enforceBolaCheck: true });
  const fixedScanResult = await orchestrateScan({ isDemoSandbox: true });

  const hasBolaAfterFix = fixedScanResult.findings.some((f) => f.category === 'BOLA_IDOR');
  assert(!hasBolaAfterFix, 'BOLA finding completely disappears when fix is applied to sandbox');
  assert(
    fixedScanResult.score.currentScore > fullScanResult.score.currentScore,
    `Security score increases after fix (Before: ${fullScanResult.score.currentScore}, After: ${fixedScanResult.score.currentScore})`
  );
  console.log(`    --> Score improved by ${fixedScanResult.score.currentScore - fullScanResult.score.currentScore} points!`);

  // Reset sandbox after test
  resetSandboxConfig();

  console.log('\n========================================');
  console.log(`RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
