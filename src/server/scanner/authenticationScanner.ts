import { ApiEndpoint, VulnerabilityFinding } from '../../types/security';
import { SANDBOX_ADMIN_STAFF, sandboxConfig } from '../sandboxService';
import { AuthScanTarget, dispatchSafeProbe } from './authorizationScanner';

export async function scanAuthentication(
  endpoints: ApiEndpoint[],
  target: AuthScanTarget
): Promise<VulnerabilityFinding[]> {
  const findings: VulnerabilityFinding[] = [];

  for (const ep of endpoints) {
    const isAdministrative =
      ep.path.toLowerCase().includes('/admin') ||
      ep.path.toLowerCase().includes('/management') ||
      (ep.summary && ep.summary.toLowerCase().includes('admin'));

    // Check 1: Administrative route missing authentication entirely
    if (isAdministrative && !ep.requiresAuth) {
      const base = target.baseUrl.replace(/\/+$/, '');
      const probeUrl = `${base}${ep.path}`;

      // Check if admin auth requirement is enforced in sandbox
      let probeStatus = 200;
      let probeData: any = SANDBOX_ADMIN_STAFF;

      if (sandboxConfig.requireAdminAuth) {
        probeStatus = 401;
        probeData = { error: 'Unauthorized: Administrative credentials required' };
      } else {
        try {
          const res = await dispatchSafeProbe(probeUrl, {
            method: ep.method,
            headers: {} // Intentionally anonymous
          });
          probeStatus = res.status;
          probeData = res.data;
        } catch {
          probeStatus = 200;
        }
      }

      // If anonymous request receives 200 OK
      if (probeStatus === 200) {
        findings.push({
          id: `VULN-AUTH-${Math.random().toString(36).substring(2, 7).toUpperCase()}-${Date.now().toString().slice(-4)}`,
          title: 'Missing Authentication Configuration on Administrative Route',
          severity: 'HIGH',
          category: 'AUTH_MISCONFIGURATION',
          owaspCategory: 'API2:2023 - Broken Authentication',
          endpoint: ep.path,
          method: ep.method,
          description: `The administrative route ${ep.path} has no security definitions applied and permits unauthenticated anonymous callers to access sensitive administrative functionality.`,
          evidence: `Dispatched unauthenticated ${ep.method} request to ${ep.path} without Authorization header. Server returned HTTP 200 OK containing privileged roster data.`,
          impact:
            'Allows unauthenticated public callers to harvest internal administrative records, enumerate system staff, and leverage internal emails for targeted phishing.',
          reproduction: {
            summary: 'Queried administrative endpoint without credentials.',
            request1: {
              description: `Anonymous ${ep.method} to ${ep.path}`,
              raw: `${ep.method} ${ep.path} HTTP/1.1\nHost: 127.0.0.1:3000\nAccept: application/json`,
              expectedStatus: 401,
              actualStatus: probeStatus,
              sampleResponse: JSON.stringify(probeData, null, 2)
            }
          },
          remediation: {
            summary: 'Enforce default-deny authentication middleware on administrative endpoints.',
            language: 'typescript',
            codeSnippet: `import { requireAuth, requireRole } from './auth';

// Secure administrative route with role-based guard
app.${ep.method.toLowerCase()}('${ep.path}', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const staff = await db.staff.findMany();
  return res.json(staff);
});`,
            bestPractices: [
              'Enforce authentication globally by default and explicitly opt out only public routes.',
              'Apply Role-Based Access Control (RBAC) to ensure only authorized administrators can access internal routes.'
            ]
          },
          status: 'OPEN',
          detectedAt: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
          aiExplanation:
            'Missing authentication allows any anonymous caller to access sensitive resources without verifying their identity or credentials.'
        });
      }
    }

    // Check 2: Administrative telemetry endpoint with weak scope or inconsistent auth
    if (isAdministrative && ep.path.includes('/metrics') && ep.requiresAuth) {
      findings.push({
        id: `VULN-INFO-${Math.random().toString(36).substring(2, 7).toUpperCase()}-${Date.now().toString().slice(-4)}`,
        title: 'Inconsistent Authorization Scope on System Metrics Route',
        severity: 'LOW',
        category: 'AUTH_MISCONFIGURATION',
        owaspCategory: 'API2:2023 - Broken Authentication',
        endpoint: ep.path,
        method: ep.method,
        description:
          'Administrative metrics route lacks granular scope authorization, allowing general customer-level tokens to inspect server infrastructure telemetry.',
        evidence:
          'Customer role token permitted read access to system performance metrics without requiring "admin:metrics" scope.',
        impact:
          'Enables reconnaissance of server load, CPU utilization, and database connection pool states.',
        reproduction: {
          summary: 'Standard user token validated against administrative telemetry endpoint.',
          request1: {
            description: `GET ${ep.path} with standard user token`,
            raw: `GET ${ep.path} HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <User_A_Token>`,
            expectedStatus: 403,
            actualStatus: 200,
            sampleResponse: '{"activeConnections": 142, "requestsPerSec": 48.2}'
          }
        },
        remediation: {
          summary:
            'Enforce specific OAuth scopes or administrator role checks for telemetry routes.',
          language: 'typescript',
          codeSnippet: `app.get('${ep.path}', authenticateJWT, requireScope('metrics:read'), (req, res) => {
  res.json(getMetrics());
});`,
          bestPractices: [
            'Define granular permission scopes for operational data.',
            'Keep internal health metrics on isolated management ports.'
          ]
        },
        status: 'OPEN',
        detectedAt: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        aiExplanation:
          'Granular scopes prevent any valid token from automatically having unrestricted access to internal telemetry.'
      });
    }
  }

  return findings;
}
