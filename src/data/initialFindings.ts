import { VulnerabilityFinding, ApiEndpoint, SecurityScoreBreakdown } from '../types/security';

export const INITIAL_FINDINGS: VulnerabilityFinding[] = [
  {
    id: 'VULN-BOLA-01',
    title: 'Broken Object-Level Authorization (BOLA / IDOR)',
    severity: 'CRITICAL',
    category: 'BOLA_IDOR',
    owaspCategory: 'API1:2023 - Broken Object Level Authorization',
    endpoint: '/api/orders/{orderId}',
    method: 'GET',
    description: 'The endpoint does not verify that the authenticated user owns the requested order resource before returning the data. Any authenticated sandbox user can manipulate the orderId parameter to inspect private customer orders belonging to other tenants.',
    evidence: 'Authenticated sandbox User A (token: sub="user_a") successfully retrieved Order #1002 containing the personal address and billing data of User B without triggering an authorization error (HTTP 403/404).',
    impact: 'Enables complete unauthorized cross-tenant data exfiltration. Attackers can iterate through order IDs sequentially to harvest customer addresses, order histories, and payment transaction details.',
    reproduction: {
      summary: 'Safe demonstration performed against local sandbox container using test accounts.',
      request1: {
        description: 'Step 1: Test User A requests their own authorized order #1001',
        raw: `GET /api/orders/1001 HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <User_A_Token>\nAccept: application/json`,
        expectedStatus: 200,
        actualStatus: 200,
        sampleResponse: `{\n  "orderId": "1001",\n  "ownerUserId": "user_a",\n  "deliveryAddress": "120 Market St, Suite 4",\n  "totalAmount": 29.99,\n  "status": "DELIVERED"\n}`
      },
      request2: {
        description: 'Step 2: Test User A attempts to read User B\'s order #1002',
        raw: `GET /api/orders/1002 HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <User_A_Token>\nAccept: application/json`,
        expectedStatus: 403,
        actualStatus: 200,
        sampleResponse: `{\n  "orderId": "1002",\n  "ownerUserId": "user_b",\n  "deliveryAddress": "742 Evergreen Terrace",\n  "totalAmount": 48.50,\n  "status": "DELIVERED"\n}`
      }
    },
    remediation: {
      summary: 'Verify object ownership on every request before returning the resource from the persistence layer.',
      language: 'typescript',
      codeSnippet: `// Corrected Controller with Ownership Validation
app.get('/api/orders/:orderId', authenticateJWT, async (req, res) => {
  const { orderId } = req.params;
  const currentUserId = req.user.id;

  const order = await db.orders.findUnique({ where: { id: orderId } });
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  // ENFORCE TENANT AUTHORIZATION CHECK
  if (order.ownerUserId !== currentUserId && req.user.role !== 'ADMIN') {
    return res.status(403).json({
      error: 'Forbidden: You do not have permission to view this order.'
    });
  }

  return res.json(order);
});`,
      bestPractices: [
        'Adopt attribute-based access control (ABAC) or policy-based authorization.',
        'Use scoped queries: db.orders.findFirst({ where: { id: orderId, userId: req.user.id } }).',
        'Prefer unguessable UUIDv4 or KSUID instead of auto-incrementing integer IDs.'
      ]
    },
    status: 'OPEN',
    detectedAt: '2026-09-24 07:15:00 UTC',
    aiExplanation: 'An IDOR (Insecure Direct Object Reference) or BOLA vulnerability occurs when an API trusts an object ID supplied by the user without checking whether the requesting session is authorized to read or mutate that resource.',
    aiRemediationGuidance: 'Ensure your data access layer binds the database query to the authenticated session context (e.g. `WHERE id = $1 AND owner_id = $2`) rather than selecting by ID alone.'
  },
  {
    id: 'VULN-DATA-02',
    title: 'Excessive Data Exposure in User Profile Response',
    severity: 'HIGH',
    category: 'EXCESSIVE_DATA_EXPOSURE',
    owaspCategory: 'API3:2023 - Broken Object Property Level Authorization',
    endpoint: '/api/users/{id}',
    method: 'GET',
    description: 'The endpoint returns internal sensitive properties (passwordHash, internalNotes, ssnLast4, stripeCustomerId) in the JSON response payload, relying on the client application to filter what gets displayed.',
    evidence: 'Response schema for /api/users/{id} reveals fields: "passwordHash", "internalNotes", "ssnLast4", and "stripeCustomerId". The live sandbox returned active bcrypt hash "$2b$12$e8x...h9K" and PII.',
    impact: 'Exposes sensitive credential hashes to offline cracking and leaks internal compliance notes and payment identifiers to standard API consumers.',
    reproduction: {
      summary: 'Queried test user record via sandbox endpoint.',
      request1: {
        description: 'GET /api/users/101',
        raw: `GET /api/users/101 HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <User_A_Token>`,
        expectedStatus: 200,
        actualStatus: 200,
        sampleResponse: `{\n  "id": 101,\n  "name": "Rahul Sharma",\n  "email": "rahul@demo.internal",\n  "passwordHash": "$2b$12$e8x4k2L...h9K",\n  "internalNotes": "VIP client; risk score tier 0",\n  "ssnLast4": "8842",\n  "stripeCustomerId": "cus_N924ka82"\n}`
      }
    },
    remediation: {
      summary: 'Return only fields required by the client. Implement strict Data Transfer Objects (DTO) and response serializer allowlists.',
      language: 'typescript',
      codeSnippet: `// Use Data Transfer Object (DTO) projection
interface PublicUserProfileDto {
  id: number;
  name: string;
  email: string;
}

app.get('/api/users/:id', authenticateJWT, async (req, res) => {
  const user = await db.users.findUnique({
    where: { id: req.params.id },
    select: { id: true, name: true, email: true } // EXPLICIT ALLOWLIST ONLY
  });

  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
});`,
      bestPractices: [
        'Never return raw database model entities directly to the client.',
        'Enforce schema serialization (e.g. Zod, Class-Transformer, or JSON Schema) that strips unrecognized or private fields.',
        'Audit API contracts for sensitive keywords like hash, secret, ssn, pin, or internal.'
      ]
    },
    status: 'OPEN',
    detectedAt: '2026-09-24 07:15:02 UTC',
    aiExplanation: 'Excessive data exposure happens when an API server dumps full database records into the HTTP response under the assumption that the frontend will hide whatever fields the user should not see. Attackers can inspect network traffic to view raw payloads.',
    aiRemediationGuidance: 'Define an explicit projection or DTO schema containing only the minimum necessary public attributes.'
  },
  {
    id: 'VULN-AUTH-03',
    title: 'Missing Authentication on Administrative Route',
    severity: 'HIGH',
    category: 'AUTH_MISCONFIGURATION',
    owaspCategory: 'API2:2023 - Broken Authentication',
    endpoint: '/api/admin/users',
    method: 'GET',
    description: 'The administrative route /api/admin/users has no security requirement declared in the OpenAPI specification, and the sandbox endpoint allows unauthenticated anonymous callers to enumerate system staff and user lists.',
    evidence: 'Sending an unauthenticated request without an Authorization header yielded HTTP 200 OK with internal administrator records.',
    impact: 'Anonymous external actors can harvest internal staff identities, roles, and emails to orchestrate spear-phishing or account takeover attacks.',
    reproduction: {
      summary: 'Queried administrative endpoint without credentials.',
      request1: {
        description: 'Anonymous request to admin endpoint',
        raw: `GET /api/admin/users HTTP/1.1\nHost: 127.0.0.1:3000\nAccept: application/json`,
        expectedStatus: 401,
        actualStatus: 200,
        sampleResponse: `[\n  { "id": "adm_01", "role": "SUPERADMIN", "email": "sysadmin@internal.test" },\n  { "id": "adm_02", "role": "SUPPORT_LEAD", "email": "helpdesk@internal.test" }\n]`
      }
    },
    remediation: {
      summary: 'Require appropriate authentication and role-based access control (RBAC) on all administrative routes.',
      language: 'typescript',
      codeSnippet: `// Require Authentication and Admin Role Guard
import { requireAuth, requireRole } from './auth-middleware';

app.get(
  '/api/admin/users',
  requireAuth,
  requireRole(['ADMIN', 'SUPERADMIN']),
  async (req, res) => {
    const adminStaff = await db.staff.findMany();
    return res.json(adminStaff);
  }
);`,
      bestPractices: [
        'Apply default-deny security filters across all /admin/* prefixes.',
        'Use multi-factor authentication (MFA) and scoped tokens for elevated roles.',
        'Log and alert on unauthenticated attempts to access administrative routes.'
      ]
    },
    status: 'OPEN',
    detectedAt: '2026-09-24 07:15:03 UTC',
    aiExplanation: 'Missing authentication means the route has no lock on the door. Anyone who discovers the URL can invoke the operation without presenting any credentials.',
    aiRemediationGuidance: 'Wrap all administrative endpoints with an authentication middleware and an authorization role check.'
  },
  {
    id: 'VULN-RATE-04',
    title: 'Weak or Missing Rate Limiting on Search Endpoint',
    severity: 'MEDIUM',
    category: 'WEAK_RATE_LIMITING',
    owaspCategory: 'API4:2023 - Unrestricted Resource Consumption',
    endpoint: '/api/products',
    method: 'GET',
    description: 'The sandbox endpoint accepts unrestricted rapid bursts without enforcing throttling, HTTP 429 Too Many Requests status codes, or RateLimit-Limit/RateLimit-Remaining telemetry headers.',
    evidence: 'SentinelAPI scanner dispatched a controlled test burst of 12 requests within 500ms against /api/products. All 12 requests returned HTTP 200 OK with zero rate-limit headers present in response.',
    impact: 'Leaves the backend vulnerable to automated content scraping, database CPU exhaustion, and resource exhaustion attacks.',
    reproduction: {
      summary: 'Bounded 12-request test burst dispatched to sandbox endpoint.',
      request1: {
        description: 'Dispatched 12 rapid sequential GET requests',
        raw: `GET /api/products?query=burger HTTP/1.1\nHost: 127.0.0.1:3000`,
        expectedStatus: 429,
        actualStatus: 200,
        sampleResponse: `HTTP/1.1 200 OK\n(Missing X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After headers)`
      }
    },
    remediation: {
      summary: 'Implement token bucket or sliding window rate limiting with standard RFC 6585 headers.',
      language: 'typescript',
      codeSnippet: `import rateLimit from 'express-rate-limit';

const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 30, // max 30 requests per minute per IP
  standardHeaders: true, // Return standard RateLimit-* headers
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please retry after some time.',
    retryAfterSeconds: 60
  }
});

app.use('/api/products', searchLimiter);`,
      bestPractices: [
        'Enforce tiered rate limits based on client identity and endpoint computational cost.',
        'Provide Retry-After and standard RateLimit headers in 429 responses.',
        'Use Redis or distributed cache for sliding window rate limiting in multi-instance setups.'
      ]
    },
    status: 'OPEN',
    detectedAt: '2026-09-24 07:15:05 UTC',
    aiExplanation: 'Rate limiting restricts how many requests a single client can make in a given timeframe. Without it, automated scripts can flood endpoints, degrading performance or exhausting resources.',
    aiRemediationGuidance: 'Configure an API gateway or Express rate limiter middleware (e.g. 60 requests/minute) with standard 429 backoff headers.'
  },
  {
    id: 'VULN-INFO-05',
    title: 'Inconsistent Security Definitions on Metrics Route',
    severity: 'LOW',
    category: 'AUTH_MISCONFIGURATION',
    owaspCategory: 'API2:2023 - Broken Authentication',
    endpoint: '/api/admin/metrics',
    method: 'GET',
    description: 'The endpoint /api/admin/metrics inherits global authentication but does not specify required scopes or roles, potentially allowing standard tokens to view operational metrics.',
    evidence: 'OpenAPI specification lists generic BearerAuth without granular scopes for administrative telemetry.',
    impact: 'Low privilege accounts may access system health metrics and queue statistics.',
    reproduction: {
      summary: 'Standard user token validated against administrative telemetry endpoint.',
      request1: {
        description: 'GET /api/admin/metrics with user token',
        raw: `GET /api/admin/metrics HTTP/1.1\nHost: 127.0.0.1:3000\nAuthorization: Bearer <User_A_Token>`,
        expectedStatus: 403,
        actualStatus: 200,
        sampleResponse: `{\n  "activeConnections": 142,\n  "requestsPerSec": 48.2,\n  "dbLatencyMs": 4.1\n}`
      }
    },
    remediation: {
      summary: 'Enforce scope-based access tokens (e.g. metrics:read) for operational endpoints.',
      language: 'typescript',
      codeSnippet: `app.get('/api/admin/metrics', authenticateJWT, requireScope('metrics:read'), (req, res) => {
  res.json(getMetrics());
});`,
      bestPractices: [
        'Document explicit security requirements for every route in OpenAPI specs.',
        'Isolate telemetry routes onto an internal management network or VPC.'
      ]
    },
    status: 'OPEN',
    detectedAt: '2026-09-24 07:15:06 UTC',
    aiExplanation: 'Inconsistent security definitions create loopholes where general tokens can access specialized administrative views.',
    aiRemediationGuidance: 'Define explicit OAuth scopes or role prerequisites for all internal telemetry.'
  }
];

export const INITIAL_SCORE: SecurityScoreBreakdown = {
  currentScore: 62,
  baseScore: 100,
  deductions: {
    criticalCount: 1,
    criticalDeduction: 25,
    highCount: 2,
    highDeduction: 10,
    mediumCount: 1,
    mediumDeduction: 3,
    lowCount: 1,
    lowDeduction: 0 // remaining score 62
  },
  authCoveragePercentage: 82,
  ratingGrade: 'D'
};

export const INITIAL_ENDPOINTS: ApiEndpoint[] = [
  {
    id: 'ep-01',
    method: 'POST',
    path: '/api/auth/login',
    summary: 'Authenticate test user',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [],
    requestBodySchema: '{"email": "string", "password": "string"}',
    responseSchema: '{"token": "string", "userId": "string", "expiresIn": 3600}',
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:00',
    status: 'TESTED'
  },
  {
    id: 'ep-02',
    method: 'POST',
    path: '/api/auth/register',
    summary: 'Create sandbox user',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:00',
    status: 'SCANNED'
  },
  {
    id: 'ep-03',
    method: 'POST',
    path: '/api/auth/refresh',
    summary: 'Refresh session token',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:00',
    status: 'SCANNED'
  },
  {
    id: 'ep-04',
    method: 'GET',
    path: '/api/users/me',
    summary: 'Get current authenticated profile',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:00',
    status: 'TESTED'
  },
  {
    id: 'ep-05',
    method: 'GET',
    path: '/api/users/{id}',
    summary: 'Get user details by ID',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'HIGH',
    parameters: [
      { name: 'id', in: 'path', required: true, type: 'string', description: 'User identifier' }
    ],
    responseSchema: '{"id": 101, "name": "...", "email": "...", "passwordHash": "...", "ssnLast4": "...", "internalNotes": "..."}',
    findingsCount: 1,
    lastScanned: '2026-09-24 07:15:02',
    status: 'TESTED'
  },
  {
    id: 'ep-06',
    method: 'PUT',
    path: '/api/users/{id}',
    summary: 'Update user profile',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'MEDIUM',
    parameters: [
      { name: 'id', in: 'path', required: true, type: 'string', description: 'User identifier' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:02',
    status: 'SCANNED'
  },
  {
    id: 'ep-07',
    method: 'GET',
    path: '/api/orders',
    summary: 'List user orders',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:01',
    status: 'TESTED'
  },
  {
    id: 'ep-08',
    method: 'GET',
    path: '/api/orders/{orderId}',
    summary: 'Get order details by orderId',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'CRITICAL',
    parameters: [
      { name: 'orderId', in: 'path', required: true, type: 'string', description: 'Order ID' }
    ],
    responseSchema: '{"orderId": "string", "ownerUserId": "string", "deliveryAddress": "string", "totalAmount": 48.5}',
    findingsCount: 1,
    lastScanned: '2026-09-24 07:15:01',
    status: 'TESTED'
  },
  {
    id: 'ep-09',
    method: 'POST',
    path: '/api/orders',
    summary: 'Create new food order',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:01',
    status: 'SCANNED'
  },
  {
    id: 'ep-10',
    method: 'DELETE',
    path: '/api/orders/{orderId}',
    summary: 'Cancel order',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'MEDIUM',
    parameters: [
      { name: 'orderId', in: 'path', required: true, type: 'string', description: 'Order ID' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:01',
    status: 'SCANNED'
  },
  {
    id: 'ep-11',
    method: 'GET',
    path: '/api/restaurants',
    summary: 'List all partner restaurants',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:02',
    status: 'SCANNED'
  },
  {
    id: 'ep-12',
    method: 'GET',
    path: '/api/restaurants/{restaurantId}',
    summary: 'Get restaurant profile',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [
      { name: 'restaurantId', in: 'path', required: true, type: 'string', description: 'Restaurant ID' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:02',
    status: 'SCANNED'
  },
  {
    id: 'ep-13',
    method: 'GET',
    path: '/api/restaurants/{restaurantId}/menu',
    summary: 'Get restaurant menu catalogue',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [
      { name: 'restaurantId', in: 'path', required: true, type: 'string', description: 'Restaurant ID' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:02',
    status: 'SCANNED'
  },
  {
    id: 'ep-14',
    method: 'GET',
    path: '/api/products',
    summary: 'Search menu products and dishes',
    requiresAuth: false,
    riskLevel: 'MEDIUM',
    parameters: [
      { name: 'query', in: 'query', required: false, type: 'string', description: 'Search term' }
    ],
    findingsCount: 1,
    lastScanned: '2026-09-24 07:15:05',
    status: 'TESTED'
  },
  {
    id: 'ep-15',
    method: 'GET',
    path: '/api/drivers/{driverId}/location',
    summary: 'Track live courier GPS coordinates',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [
      { name: 'driverId', in: 'path', required: true, type: 'string', description: 'Driver ID' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:03',
    status: 'SCANNED'
  },
  {
    id: 'ep-16',
    method: 'POST',
    path: '/api/drivers/status',
    summary: 'Courier status transition',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:03',
    status: 'SCANNED'
  },
  {
    id: 'ep-17',
    method: 'GET',
    path: '/api/payments/methods',
    summary: 'List stored user payment cards',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:04',
    status: 'SCANNED'
  },
  {
    id: 'ep-18',
    method: 'POST',
    path: '/api/payments/charge',
    summary: 'Process sandbox payment charge',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:04',
    status: 'SCANNED'
  },
  {
    id: 'ep-19',
    method: 'GET',
    path: '/api/coupons/validate',
    summary: 'Validate promotional voucher discount',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [
      { name: 'code', in: 'query', required: true, type: 'string', description: 'Promo code' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:04',
    status: 'SCANNED'
  },
  {
    id: 'ep-20',
    method: 'GET',
    path: '/api/reviews/{restaurantId}',
    summary: 'Public reviews for restaurant',
    requiresAuth: false,
    riskLevel: 'LOW',
    parameters: [
      { name: 'restaurantId', in: 'path', required: true, type: 'string', description: 'Restaurant ID' }
    ],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:04',
    status: 'SCANNED'
  },
  {
    id: 'ep-21',
    method: 'POST',
    path: '/api/reviews',
    summary: 'Submit dining feedback review',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:04',
    status: 'SCANNED'
  },
  {
    id: 'ep-22',
    method: 'GET',
    path: '/api/admin/users',
    summary: 'List all system users and internal staff',
    requiresAuth: false,
    riskLevel: 'HIGH',
    parameters: [],
    responseSchema: '[{"id": "string", "role": "string", "email": "string"}]',
    findingsCount: 1,
    lastScanned: '2026-09-24 07:15:03',
    status: 'TESTED'
  },
  {
    id: 'ep-23',
    method: 'GET',
    path: '/api/admin/metrics',
    summary: 'Financial revenue & server analytics',
    requiresAuth: true,
    authType: 'Bearer JWT (Unscoped)',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 1,
    lastScanned: '2026-09-24 07:15:06',
    status: 'TESTED'
  },
  {
    id: 'ep-24',
    method: 'POST',
    path: '/api/admin/coupons',
    summary: 'Issue bulk promotional promo codes',
    requiresAuth: true,
    authType: 'Bearer JWT',
    riskLevel: 'LOW',
    parameters: [],
    findingsCount: 0,
    lastScanned: '2026-09-24 07:15:06',
    status: 'SCANNED'
  }
];

export const SCAN_HISTORY_ITEMS = [
  {
    scanId: 'SCN-1042',
    apiName: 'FoodDelivery Sandbox API',
    apiVersion: 'v1.0.0',
    date: '2026-09-24 07:15:00 UTC',
    endpointsCount: 24,
    vulnerabilitiesCount: 5,
    criticalCount: 1,
    highCount: 2,
    mediumCount: 1,
    lowCount: 1,
    securityScore: 62,
    status: 'COMPLETED',
    target: '127.0.0.1 (Local Sandbox)'
  },
  {
    scanId: 'SCN-1041',
    apiName: 'FoodDelivery Sandbox API',
    apiVersion: 'v0.9.8-rc1',
    date: '2026-09-23 18:30:12 UTC',
    endpointsCount: 22,
    vulnerabilitiesCount: 7,
    criticalCount: 2,
    highCount: 3,
    mediumCount: 1,
    lowCount: 1,
    securityScore: 48,
    status: 'COMPLETED',
    target: '127.0.0.1 (Local Sandbox)'
  },
  {
    scanId: 'SCN-1039',
    apiName: 'Fintech Sandbox Gateway',
    apiVersion: 'v2.1.0',
    date: '2026-09-22 14:10:45 UTC',
    endpointsCount: 38,
    vulnerabilitiesCount: 3,
    criticalCount: 0,
    highCount: 1,
    mediumCount: 2,
    lowCount: 0,
    securityScore: 84,
    status: 'COMPLETED',
    target: '127.0.0.1 (Local Sandbox)'
  }
];

export const INITIAL_SECURITY_SCORE: SecurityScoreBreakdown = {
  currentScore: 62,
  baseScore: 100,
  deductions: {
    criticalCount: 1,
    criticalDeduction: 25,
    highCount: 2,
    highDeduction: 10,
    mediumCount: 1,
    mediumDeduction: 3,
    lowCount: 1,
    lowDeduction: 0
  },
  authCoveragePercentage: 82,
  ratingGrade: 'D'
};
