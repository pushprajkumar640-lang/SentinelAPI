import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {
  SANDBOX_ORDERS,
  SANDBOX_USERS,
  SANDBOX_ADMIN_STAFF,
  sandboxConfig,
  getSandboxConfig,
  updateSandboxConfig,
  resetSandboxConfig,
  extractSandboxUserFromToken
} from './sandboxService';
import { parseOpenApiSpec, OpenApiParseError } from './scanner/openapiParser';
import { discoverEndpoints } from './scanner/endpointDiscovery';
import { orchestrateScan } from './scanner/scanOrchestrator';
import { explainFindingOrPrompt } from './geminiService';
import { optionalAuth, requireAuth, AuthRequest } from '../middleware/auth';
import { createLocalUser, createSession, getOrCreateUser, getUserByEmail, revokeSession } from '../db/users';
import {
  getUserProjects,
  createProject,
  getProjectById,
  updateProject,
  deleteProject,
  saveApiSpec,
  getLatestApiSpec,
  saveEndpoints,
  getProjectEndpoints,
  createScanRecord,
  updateScanRecord,
  saveVulnerabilities,
  getProjectScans,
  getProjectVulnerabilities,
  updateVulnerabilityStatus,
  saveReport,
  getProjectReports
  , getDashboardSummary
} from '../db/projectService';
import { RAW_FOOD_DELIVERY_JSON } from '../data/foodDeliverySpec';
import { isExternalPostgresConfigured, verifyDatabase } from '../db';

// Helper to resolve authenticated user or developer user in PostgreSQL
async function resolveUser(req: AuthRequest) {
  if (!req.dbUser) throw new Error('AUTH_REQUIRED');
  return req.dbUser;
}

function issueToken(user: { uid: string; email: string; displayName: string | null }) {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign(
    { uid: user.uid, email: user.email, name: user.displayName || undefined },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

const SESSION_DAYS = 7;

function sessionExpiry() {
  return new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
}

function publicUser(user: { id: number; uid: string; email: string; displayName: string | null; photoUrl?: string | null }) {
  return {
    id: user.id,
    uid: user.uid,
    name: user.displayName,
    displayName: user.displayName,
    email: user.email,
    photoUrl: user.photoUrl || null
  };
}

export function createApiRouter(): Router {
  const router = Router();
  router.use(optionalAuth);

  // 1. Guardrail header check & Health
  router.get('/health', async (_req: Request, res: Response) => {
    const database = await verifyDatabase();
    const ready = database.configured && database.connected && database.usersTable && Boolean(process.env.JWT_SECRET);
    if (!ready) {
      const error = !database.configured
        ? 'Database connection is not configured.'
        : !database.connected
        ? 'Database connection failed.'
        : !database.usersTable
        ? 'Users table does not exist.'
        : 'JWT_SECRET is not configured.';
      const databaseStatus = !database.configured
        ? 'not_configured'
        : !database.connected
        ? 'connection_failed'
        : 'connected';
      return res.status(503).json({ success: false, status: 'unhealthy', database: databaseStatus, error });
    }
    return res.json({ success: true, status: 'healthy', database: 'connected' });
  });

  router.post('/auth/register', async (req: Request, res: Response) => {
    try {
      const { name, email, password } = req.body || {};
      if (!name?.trim() || !email?.trim() || typeof password !== 'string' || password.length < 8) {
        return res.status(422).json({ success: false, error: 'Name, email, and a password of at least 8 characters are required' });
      }
      if (!process.env.DATABASE_URL) return res.status(503).json({ success: false, error: 'Database connection is not configured.' });
      if (!process.env.JWT_SECRET) return res.status(503).json({ success: false, error: 'JWT_SECRET is not configured.' });
      const database = await verifyDatabase();
      if (!database.connected) return res.status(503).json({ success: false, error: 'Database connection failed.' });
      if (!database.usersTable) return res.status(503).json({ success: false, error: 'Users table does not exist. Run the database migration first.' });
      if (await getUserByEmail(email.trim())) return res.status(409).json({ success: false, error: 'Email already exists.' });
      const user = await createLocalUser({
        email: email.trim(),
        displayName: name.trim(),
        passwordHash: await bcrypt.hash(password, 12)
      });
      const token = issueToken(user);
      await createSession(user.id, token, sessionExpiry());
      return res.status(201).json({ success: true, user: publicUser(user), token });
    } catch (err) {
      const code = (err as { code?: string })?.code;
      console.error('Registration error:', code || (err instanceof Error ? err.message : 'unknown error'));
      if (code === '23505') return res.status(409).json({ success: false, error: 'Email already exists.' });
      if (code === '42P01') return res.status(503).json({ success: false, error: 'Users table does not exist. Run the database migration first.' });
      return res.status(500).json({ success: false, error: 'Registration failed because the database could not create the account.' });
    }
  });

  router.post('/auth/login', async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body || {};
      if (!process.env.DATABASE_URL) return res.status(503).json({ success: false, error: 'Database connection is not configured.' });
      if (!process.env.JWT_SECRET) return res.status(503).json({ success: false, error: 'JWT_SECRET is not configured.' });
      const database = await verifyDatabase();
      if (!database.connected) return res.status(503).json({ success: false, error: 'Database connection failed.' });
      if (!database.usersTable) return res.status(503).json({ success: false, error: 'Users table does not exist. Run the database migration first.' });
      const user = typeof email === 'string' ? await getUserByEmail(email.trim()) : null;
      if (!user?.passwordHash || typeof password !== 'string' || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
      }
      const token = issueToken(user);
      await createSession(user.id, token, sessionExpiry());
      return res.json({ success: true, user: publicUser(user), token });
    } catch (err) {
      console.error('Login error:', err instanceof Error ? err.message : 'unknown error');
      return res.status(500).json({ success: false, error: 'Login failed because the database could not verify the account.' });
    }
  });

  router.post('/auth/logout', async (req: Request, res: Response) => {
    const token = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice('Bearer '.length)
      : null;
    if (token) await revokeSession(token).catch(() => {});
    return res.json({ success: true });
  });

  // ==========================================
  // SAAS USER & PROJECTS API (POSTGRESQL)
  // ==========================================

  // Get current user profile
  router.get('/auth/me', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      res.json({ user: publicUser(user), authenticated: true });
    } catch (err: any) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  });

  router.use(requireAuth);

  router.get('/dashboard/summary', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const summary = await getDashboardSummary(user.id);
      return res.json({ summary });
    } catch (err) {
      console.error('Error fetching dashboard summary:', err instanceof Error ? err.message : 'unknown error');
      return res.status(500).json({ error: 'Unable to load dashboard data' });
    }
  });

  // Get user projects
  router.get('/projects', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const userProjects = await getUserProjects(user.id);

      // Enhance project cards with latest scan and endpoints count from PostgreSQL
      const detailedProjects = await Promise.all(
        userProjects.map(async (p) => {
          const endpointsList = await getProjectEndpoints(p.id);
          const scansList = await getProjectScans(p.id);
          const latestScan = scansList[0] || null;

          return {
            ...p,
            totalEndpoints: endpointsList.length,
            scansCount: scansList.length,
            latestScan: latestScan
              ? {
                  scanId: latestScan.scanId,
                  status: latestScan.status,
                  securityScore: latestScan.securityScore,
                  ratingGrade: latestScan.ratingGrade,
                  criticalCount: latestScan.criticalCount,
                  highCount: latestScan.highCount,
                  mediumCount: latestScan.mediumCount,
                  lowCount: latestScan.lowCount,
                  completedAt: latestScan.completedAt || latestScan.startedAt
                }
              : null
          };
        })
      );

      res.json({ projects: detailedProjects });
    } catch (err: any) {
      console.error('Error fetching projects:', err);
      res.status(500).json({ error: err.message || 'Failed to fetch projects' });
    }
  });

  // Create new project
  router.post('/projects', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const { name, description, apiUrl } = req.body || {};

      if (!name || typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ error: 'Project name is required' });
      }
      if (!apiUrl || typeof apiUrl !== 'string' || !apiUrl.trim()) {
        return res.status(422).json({ error: 'API URL is required and must be provided separately from the project name' });
      }

      if (apiUrl && !/^https?:\/\//i.test(apiUrl)) return res.status(422).json({ error: 'API URL must be an http(s) URL' });
      const project = await createProject(user.id, name.trim(), description?.trim() || undefined, apiUrl?.trim());
      res.status(201).json({ project });
    } catch (err: any) {
      console.error('Error creating project:', err);
      res.status(500).json({ error: err.message || 'Failed to create project' });
    }
  });

  // Get single project details
  router.get('/projects/:id', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const spec = await getLatestApiSpec(projectId);
      const endpointsList = await getProjectEndpoints(projectId);
      const scansList = await getProjectScans(projectId);
      const vulnerabilitiesList = await getProjectVulnerabilities(projectId);
      const latestScan = scansList[0] || null;

      res.json({
        project,
        spec: spec
          ? {
              id: spec.id,
              title: spec.title,
              version: spec.version,
              description: spec.description,
              baseUrl: spec.baseUrl,
              format: spec.format,
              createdAt: spec.createdAt
            }
          : null,
        totalEndpoints: endpointsList.length,
        endpoints: endpointsList,
        latestScan,
        vulnerabilities: vulnerabilitiesList,
        scansCount: scansList.length
      });
    } catch (err: any) {
      console.error('Error getting project:', err);
      res.status(500).json({ error: err.message || 'Failed to get project' });
    }
  });

  // Delete project
  router.delete('/projects/:id', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      await deleteProject(projectId, user.id);
      res.json({ message: 'Project deleted successfully' });
    } catch (err: any) {
      console.error('Error deleting project:', err);
      res.status(500).json({ error: err.message || 'Failed to delete project' });
    }
  });

  router.put('/projects/:id', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      const existing = await getProjectById(projectId, user.id);
      if (!existing) return res.status(404).json({ error: 'Project not found' });
      const { name, description, apiUrl } = req.body || {};
      if (apiUrl && !/^https?:\/\//i.test(apiUrl)) return res.status(422).json({ error: 'API URL must be an http(s) URL' });
      const updated = await updateProject(projectId, user.id, { name, description, apiUrl });
      return res.json({ project: updated });
    } catch {
      return res.status(500).json({ error: 'Failed to update project' });
    }
  });

  // Upload and parse OpenAPI / Swagger spec for a project
  router.post('/projects/:id/spec', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const { specContent } = req.body || {};
      if (!specContent || typeof specContent !== 'string') {
        return res.status(400).json({ error: 'Specification content is required' });
      }

      // Parse with dynamic OpenAPI parser
      const parsed = parseOpenApiSpec(specContent);
      const discovered = discoverEndpoints(parsed);

      // Save original spec in PostgreSQL
      const savedSpec = await saveApiSpec(
        projectId,
        parsed.title,
        parsed.version,
        parsed.description,
        parsed.servers[0] || 'http://127.0.0.1:3000/api/sandbox',
        parsed.format,
        specContent
      );

      // Save discovered endpoints into PostgreSQL
      const savedEps = await saveEndpoints(projectId, savedSpec.id, discovered);

      res.status(201).json({
        message: `${discovered.length} endpoints successfully discovered and saved`,
        spec: {
          id: savedSpec.id,
          title: savedSpec.title,
          version: savedSpec.version,
          format: savedSpec.format,
          baseUrl: savedSpec.baseUrl
        },
        totalEndpoints: discovered.length,
        endpoints: discovered
      });
    } catch (err: any) {
      console.error('Error uploading spec:', err);
      res.status(400).json({
        error: err.message || 'Failed to parse and save OpenAPI specification'
      });
    }
  });

  // Get project endpoints
  router.get('/projects/:id/endpoints', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const endpointsList = await getProjectEndpoints(projectId);
      res.json({ endpoints: endpointsList });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch endpoints' });
    }
  });

  // Start real security scan for a project
  router.post('/projects/:id/scan', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const { authorizedConfirmed, targetBaseUrl } = req.body || {};
      if (!authorizedConfirmed && !project.isDemo) {
        return res.status(400).json({
          error: 'Explicit authorization confirmation is required to scan this API'
        });
      }

      // Retrieve spec from PostgreSQL
      const spec = await getLatestApiSpec(projectId);
      if (!spec && !project.isDemo) {
        return res.status(400).json({
          error: 'No API specification found for this project. Please upload an OpenAPI contract first.'
        });
      }

      const specContent = spec ? spec.rawSpec : RAW_FOOD_DELIVERY_JSON;

      // 1. Create scan record with status QUEUED
      const scanRecord = await createScanRecord(projectId, user.id);

      // 2. Update to RUNNING
      await updateScanRecord(scanRecord.id, { status: 'RUNNING' });

      // 3. Run actual defensive scan pipeline
      const scanResult = await orchestrateScan({
        specContent,
        isDemoSandbox: project.isDemo,
        targetBaseUrl: targetBaseUrl || project.apiUrl || spec?.baseUrl || 'http://127.0.0.1:3000/api/sandbox',
        isAuthorized: true
      });

      // 4. Save findings into PostgreSQL
      await saveVulnerabilities(scanRecord.id, projectId, scanResult.findings);

      // 5. Update scan record with score and metrics
      const completedScan = await updateScanRecord(scanRecord.id, {
        status: 'COMPLETED',
        securityScore: scanResult.score.currentScore,
        ratingGrade: scanResult.score.ratingGrade,
        totalEndpoints: scanResult.totalEndpoints,
        endpointsScanned: scanResult.totalEndpoints,
        criticalCount: scanResult.summary.critical,
        highCount: scanResult.summary.high,
        mediumCount: scanResult.summary.medium,
        lowCount: scanResult.summary.low,
        durationSeconds: scanResult.durationSeconds,
        completedAt: new Date()
      });

      // 6. Save audit report to PostgreSQL
      await saveReport(
        projectId,
        scanRecord.id,
        `Defensive Audit Report - ${project.name}`,
        {
          scanId: scanRecord.scanId,
          projectName: project.name,
          apiTitle: spec?.title || 'Sandbox API',
          apiVersion: spec?.version || '1.0.0',
          score: scanResult.score,
          summary: scanResult.summary,
          findings: scanResult.findings,
          totalEndpoints: scanResult.totalEndpoints,
          generatedAt: new Date().toISOString()
        }
      );

      res.json({
        message: 'Security scan completed successfully',
        scan: completedScan,
        score: scanResult.score,
        summary: scanResult.summary,
        findings: scanResult.findings,
        totalEndpoints: scanResult.totalEndpoints,
        durationSeconds: scanResult.durationSeconds
      });
    } catch (err: any) {
      console.error('Error running scan:', err);
      res.status(500).json({ error: err.message || 'Scan execution failed' });
    }
  });

  // Get project scan history
  router.get('/projects/:id/scans', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const scansList = await getProjectScans(projectId);
      res.json({ scans: scansList });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch scans' });
    }
  });

  // Get project vulnerabilities
  router.get('/projects/:id/vulnerabilities', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const scanIdQuery = req.query.scanId ? parseInt(req.query.scanId as string, 10) : undefined;
      const findings = await getProjectVulnerabilities(projectId, scanIdQuery);
      res.json({ vulnerabilities: findings });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch vulnerabilities' });
    }
  });

  // Update vulnerability status (OPEN / RESOLVED)
  router.patch('/vulnerabilities/:vulnId/status', async (req: AuthRequest, res: Response) => {
    try {
      const { vulnId } = req.params;
      const { status } = req.body || {};
      if (status !== 'OPEN' && status !== 'RESOLVED') {
        return res.status(400).json({ error: 'Status must be OPEN or RESOLVED' });
      }

      const user = await resolveUser(req);
      const updated = await updateVulnerabilityStatus(vulnId, status, user.id);
      if (!updated) return res.status(404).json({ error: 'Vulnerability not found' });
      res.json({ message: 'Vulnerability status updated', vulnerability: updated });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update vulnerability status' });
    }
  });

  // Get project reports
  router.get('/projects/:id/reports', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);
      const projectId = parseInt(req.params.id, 10);
      if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

      const project = await getProjectById(projectId, user.id);
      if (!project) return res.status(404).json({ error: 'Project not found' });

      const reportsList = await getProjectReports(projectId);
      res.json({ reports: reportsList });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch reports' });
    }
  });

  // ==========================================
  // DEMO SANDBOX WORKFLOW (EXPLICIT DEMO FOR JUDGES)
  // ==========================================

  // Initialize or retrieve the dedicated Demo Sandbox project in PostgreSQL
  router.post('/demo/setup', async (req: AuthRequest, res: Response) => {
    try {
      const user = await resolveUser(req);

      // Check if user already has a demo sandbox project
      const existingProjects = await getUserProjects(user.id);
      let demoProject = existingProjects.find((p) => p.isDemo);

      if (!demoProject) {
        demoProject = await createProject(
          user.id,
          'SentinelAPI Demo Sandbox',
          'Intentionally vulnerable sandbox environment for live defensive security evaluation',
          'http://127.0.0.1:3000/api/sandbox',
          true
        );
      }

      // Parse and save food delivery spec and endpoints if not yet populated
      const existingSpec = await getLatestApiSpec(demoProject.id);
      if (!existingSpec) {
        const parsed = parseOpenApiSpec(RAW_FOOD_DELIVERY_JSON);
        const discovered = discoverEndpoints(parsed);
        const savedSpec = await saveApiSpec(
          demoProject.id,
          parsed.title,
          parsed.version,
          parsed.description,
          'http://127.0.0.1:3000/api/sandbox',
          'json',
          RAW_FOOD_DELIVERY_JSON
        );
        await saveEndpoints(demoProject.id, savedSpec.id, discovered);
      }

      const endpointsList = await getProjectEndpoints(demoProject.id);
      const scansList = await getProjectScans(demoProject.id);
      const latestScan = scansList[0] || null;
      const vulnerabilitiesList = await getProjectVulnerabilities(demoProject.id);

      res.json({
        message: 'Demo Sandbox initialized in PostgreSQL',
        project: demoProject,
        totalEndpoints: endpointsList.length,
        endpoints: endpointsList,
        latestScan,
        vulnerabilities: vulnerabilitiesList,
        isDemo: true
      });
    } catch (err: any) {
      console.error('Error setting up demo sandbox:', err);
      res.status(500).json({ error: err.message || 'Failed to setup demo sandbox' });
    }
  });

  // ==========================================
  // SANDBOX CONFIG & CONTROLS
  // ==========================================
  router.get('/sandbox/config', (_req: Request, res: Response) => {
    res.json(getSandboxConfig());
  });

  router.post('/sandbox/config', (req: Request, res: Response) => {
    const updated = updateSandboxConfig(req.body || {});
    res.json({ message: 'Sandbox configuration updated', config: updated });
  });

  router.post('/sandbox/reset', (_req: Request, res: Response) => {
    const reset = resetSandboxConfig();
    res.json({ message: 'Sandbox configuration reset to vulnerable defaults', config: reset });
  });

  // ==========================================
  // SPEC VALIDATE & GEMINI EXPLANATION
  // ==========================================
  router.post('/spec/validate', (req: Request, res: Response) => {
    try {
      const { specContent } = req.body || {};
      if (!specContent || typeof specContent !== 'string') {
        return res.status(400).json({ valid: false, error: 'Specification content is required' });
      }

      const parsed = parseOpenApiSpec(specContent);
      const endpoints = discoverEndpoints(parsed);

      const methodsCount: Record<string, number> = {};
      endpoints.forEach((ep) => {
        methodsCount[ep.method] = (methodsCount[ep.method] || 0) + 1;
      });

      res.json({
        valid: true,
        title: parsed.title,
        version: parsed.version,
        description: parsed.description,
        baseUrl: parsed.servers[0] || '',
        authTypes: Object.keys(parsed.securitySchemes || {}),
        totalEndpoints: endpoints.length,
        methodsCount,
        endpoints: endpoints.slice(0, 5)
      });
    } catch (err: any) {
      if (err instanceof OpenApiParseError) {
        return res.status(400).json({ valid: false, error: err.message });
      }
      res.status(400).json({ valid: false, error: err.message || 'Failed to parse specification' });
    }
  });

  router.post('/gemini/explain', async (req: Request, res: Response) => {
    try {
      const { prompt, finding, project, apiUrl, scanId, securityScore, endpointsScanned, findings, severityCounts } = req.body || {};
      const answer = await explainFindingOrPrompt({
        prompt: prompt || 'Explain this API vulnerability and best-practice remediation.',
        findingTitle: finding?.title,
        severity: finding?.severity,
        endpoint: finding?.endpoint,
        codeSnippet: finding?.remediation?.codeSnippet,
        evidence: finding?.evidence,
        project,
        apiUrl,
        scanId,
        securityScore,
        endpointsScanned,
        findings,
        severityCounts
      });
      res.json({ answer });
    } catch (err: any) {
      console.error('Gemini explanation error:', err);
      res.status(500).json({
        error: 'Unable to query AI explanation service',
        fallback:
          'API security vulnerabilities should be mitigated by enforcing strict authentication, object-level ownership checks, and response schema minimization.'
      });
    }
  });

  // ==========================================
  // SANDBOX TESTBED API ROUTES (OWASP API1, API2, API4)
  // ==========================================
  router.post('/sandbox/auth/login', (req: Request, res: Response) => {
    const { email } = req.body || {};
    if (email === 'user_b@demo.internal' || email === 'user_b') {
      return res.json({
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_sandbox_token',
        userId: 'user_b',
        name: 'Elena Rostova (User B)',
        expiresIn: 3600
      });
    }
    if (email === 'admin@demo.internal' || email === 'admin') {
      return res.json({
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_sandbox_token',
        userId: 'admin_1',
        name: 'System Admin',
        expiresIn: 3600
      });
    }
    return res.json({
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_sandbox_token',
      userId: 'user_a',
      name: 'Rahul Sharma (User A)',
      expiresIn: 3600
    });
  });

  router.get('/sandbox/orders/:orderId', (req: Request, res: Response) => {
    const orderId = req.params.orderId;
    const order = SANDBOX_ORDERS[orderId];
    if (!order) return res.status(404).json({ error: 'Order not found' });

    if (sandboxConfig.enforceBolaCheck) {
      const authHeader = req.headers['authorization'];
      const user = extractSandboxUserFromToken(authHeader);
      if (!user || (order.ownerUserId !== user.userId && user.role !== 'ADMIN')) {
        return res.status(403).json({
          error: 'Forbidden: Unauthorized object access. You do not own this order.',
          orderId,
          requestedBy: user?.userId || 'anonymous'
        });
      }
    }

    return res.json(order);
  });

  router.get('/sandbox/users/:id', (req: Request, res: Response) => {
    const userId = req.params.id;
    const user = SANDBOX_USERS[userId] || SANDBOX_USERS['101'];

    if (sandboxConfig.maskSensitiveFields) {
      return res.json({
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      });
    }

    return res.json(user);
  });

  router.get('/sandbox/products', (_req: Request, res: Response) => {
    return res.json([
      { id: 'prod_1', name: 'Artisan Wood-Fired Margherita', price: 14.5 },
      { id: 'prod_2', name: 'Truffle Mushroom Risotto', price: 21.0 }
    ]);
  });

  router.get('/sandbox/admin/users', (req: Request, res: Response) => {
    if (sandboxConfig.requireAdminAuth) {
      const authHeader = req.headers['authorization'];
      const user = extractSandboxUserFromToken(authHeader);
      if (!user || user.role !== 'ADMIN') {
        return res.status(401).json({
          error: 'Unauthorized: Missing or invalid administrative credentials'
        });
      }
    }

    return res.json(SANDBOX_ADMIN_STAFF);
  });

  return router;
}
