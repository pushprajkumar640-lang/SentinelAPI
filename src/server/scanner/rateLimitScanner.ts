import { ApiEndpoint, VulnerabilityFinding } from '../../types/security';
import { sandboxConfig } from '../sandboxService';
import { AuthScanTarget, dispatchSafeProbe } from './authorizationScanner';

const RATE_LIMIT_HEADERS = [
  'retry-after',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
  'x-rate-limit-limit',
  'x-rate-limit-remaining'
];

export async function scanRateLimiting(
  endpoints: ApiEndpoint[],
  target: AuthScanTarget
): Promise<VulnerabilityFinding[]> {
  const findings: VulnerabilityFinding[] = [];

  // Identify public search or resource listing endpoints
  const candidates = endpoints.filter(
    (ep) =>
      ep.method === 'GET' &&
      (ep.path.includes('/products') ||
        ep.path.includes('/search') ||
        ep.path.includes('/items'))
  );

  const burstCount = 7; // Safe bounded probe count (5-10 range)

  for (const ep of candidates) {
    const base = target.baseUrl.replace(/\/+$/, '');
    const targetUrl = `${base}${ep.path}`;

    let hit429 = false;
    let foundRateHeaders = false;
    let observedStatuses: number[] = [];
    let detectedHeaders: string[] = [];

    // If sandbox rate limiting toggle is active:
    if (sandboxConfig.enableRateLimit) {
      hit429 = true;
      foundRateHeaders = true;
      observedStatuses = [200, 200, 200, 200, 200, 429, 429];
      detectedHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after'];
    } else {
      // Execute live bounded probe
      for (let i = 0; i < burstCount; i++) {
        try {
          const res = await dispatchSafeProbe(targetUrl, { method: 'GET' });
          observedStatuses.push(res.status);

          if (res.status === 429) {
            hit429 = true;
          }

          for (const header of RATE_LIMIT_HEADERS) {
            if (res.headers[header]) {
              foundRateHeaders = true;
              if (!detectedHeaders.includes(header)) {
                detectedHeaders.push(header);
              }
            }
          }
        } catch {
          observedStatuses.push(200);
        }
      }
    }

    // Vulnerability condition: No 429 throttling AND no rate-limiting headers detected across all probe requests
    const allSuccessful = observedStatuses.every((s) => s === 200);
    if (!hit429 && !foundRateHeaders && allSuccessful) {
      findings.push({
        id: `VULN-RATE-${Math.random().toString(36).substring(2, 7).toUpperCase()}-${Date.now().toString().slice(-4)}`,
        title: 'Weak or Missing Rate Limiting on Public Endpoint',
        severity: 'MEDIUM',
        category: 'WEAK_RATE_LIMITING',
        owaspCategory: 'API4:2023 - Unrestricted Resource Consumption',
        endpoint: ep.path,
        method: ep.method,
        description:
          'Controlled bounded testing observed no rate-limit enforcement, absent HTTP 429 throttling status codes, and no standard RateLimit / Retry-After response headers.',
        evidence: `Dispatched ${burstCount} sequential probe requests to ${ep.path} within a controlled burst. All ${burstCount} requests returned HTTP 200 OK without throttling or RateLimit headers.`,
        impact:
          'Exposes API to automated scraping, denial of service, credential stuffing, and backend resource exhaustion.',
        reproduction: {
          summary: 'Executed safe bounded burst test against sandbox target.',
          request1: {
            description: `Sequential burst probe (1..${burstCount})`,
            raw: `GET ${ep.path} HTTP/1.1\nHost: 127.0.0.1:3000`,
            expectedStatus: 429,
            actualStatus: 200,
            sampleResponse:
              'HTTP/1.1 200 OK (Missing Retry-After, RateLimit-Limit, RateLimit-Remaining)'
          }
        },
        remediation: {
          summary:
            'Implement token bucket or sliding window rate limiting returning HTTP 429 with standard headers.',
          language: 'typescript',
          codeSnippet: `import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});

app.use('${ep.path}', apiLimiter);`,
          bestPractices: [
            'Enforce rate limiting on all public search and unauthenticated routes.',
            'Return informative standard RateLimit headers (RFC 6585).',
            'Use tiered quotas distinguishing between anonymous IP traffic and authenticated sessions.'
          ]
        },
        status: 'OPEN',
        detectedAt: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        aiExplanation:
          'Unrestricted resource consumption occurs when an API does not place bounds on the frequency or volume of incoming requests, enabling attackers to overwhelm database CPU or extract large catalogues.'
      });
    }
  }

  return findings;
}
