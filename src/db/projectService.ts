import { db } from './index';
import {
  projects,
  apiSpecs,
  endpoints,
  scans,
  vulnerabilities,
  reports,
  notifications
} from './schema';
import { eq, desc, and, avg, count, sql } from 'drizzle-orm';
import { ApiEndpoint, VulnerabilityFinding, SecurityScoreBreakdown } from '../types/security';

export async function getDashboardSummary(userId: number) {
  const [scanSummary, findingSummary] = await Promise.all([
    db
      .select({
        scansCount: count(scans.id),
        averageScore: avg(scans.securityScore)
      })
      .from(scans)
      .where(and(eq(scans.userId, userId), eq(scans.status, 'COMPLETED'))),
    db
      .select({
        vulnerabilitiesCount: count(vulnerabilities.id),
        criticalCount: sql<number>`count(*) filter (where ${vulnerabilities.severity} = 'CRITICAL')`,
        highCount: sql<number>`count(*) filter (where ${vulnerabilities.severity} = 'HIGH')`,
        mediumCount: sql<number>`count(*) filter (where ${vulnerabilities.severity} = 'MEDIUM')`,
        lowCount: sql<number>`count(*) filter (where ${vulnerabilities.severity} = 'LOW')`
      })
      .from(vulnerabilities)
      .innerJoin(projects, eq(vulnerabilities.projectId, projects.id))
      .where(eq(projects.userId, userId))
  ]);

  return {
    scansCount: Number(scanSummary[0]?.scansCount || 0),
    averageScore: Math.round(Number(scanSummary[0]?.averageScore || 0)),
    vulnerabilitiesCount: Number(findingSummary[0]?.vulnerabilitiesCount || 0),
    criticalCount: Number(findingSummary[0]?.criticalCount || 0),
    highCount: Number(findingSummary[0]?.highCount || 0),
    mediumCount: Number(findingSummary[0]?.mediumCount || 0),
    lowCount: Number(findingSummary[0]?.lowCount || 0)
  };
}

export async function getUserProjects(userId: number) {
  try {
    return await db
      .select()
      .from(projects)
      .where(eq(projects.userId, userId))
      .orderBy(desc(projects.createdAt));
  } catch (error) {
    console.error('Error in getUserProjects:', error);
    throw new Error('Failed to fetch user projects', { cause: error });
  }
}

export async function createProject(
  userId: number,
  name: string,
  description?: string,
  apiUrl?: string,
  isDemo = false
) {
  try {
    const result = await db
      .insert(projects)
      .values({
        userId,
        name,
        description: description || null,
        apiUrl: apiUrl || null,
        isDemo
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in createProject:', error);
    throw new Error('Failed to create project', { cause: error });
  }
}

export async function getProjectById(projectId: number, userId?: number) {
  try {
    const conditions = [eq(projects.id, projectId)];
    if (userId) {
      conditions.push(eq(projects.userId, userId));
    }
    const result = await db
      .select()
      .from(projects)
      .where(and(...conditions))
      .limit(1);
    return result[0] || null;
  } catch (error) {
    console.error('Error in getProjectById:', error);
    throw new Error('Failed to get project', { cause: error });
  }
}

export async function deleteProject(projectId: number, userId: number) {
  try {
    await db
      .delete(projects)
      .where(and(eq(projects.id, projectId), eq(projects.userId, userId)));
    return true;
  } catch (error) {
    console.error('Error in deleteProject:', error);
    throw new Error('Failed to delete project', { cause: error });
  }
}

export async function updateProject(
  projectId: number,
  userId: number,
  values: { name?: string; description?: string; apiUrl?: string }
) {
  const result = await db.update(projects)
    .set({
      ...(values.name !== undefined ? { name: values.name.trim() } : {}),
      ...(values.description !== undefined ? { description: values.description.trim() || null } : {}),
      ...(values.apiUrl !== undefined ? { apiUrl: values.apiUrl.trim() || null } : {}),
      updatedAt: new Date()
    })
    .where(and(eq(projects.id, projectId), eq(projects.userId, userId)))
    .returning();
  return result[0] || null;
}

export async function saveApiSpec(
  projectId: number,
  title: string,
  version: string,
  description: string | undefined,
  baseUrl: string | undefined,
  format: 'json' | 'yaml',
  rawSpec: string
) {
  try {
    const result = await db
      .insert(apiSpecs)
      .values({
        projectId,
        title,
        version,
        description: description || null,
        baseUrl: baseUrl || null,
        format,
        rawSpec
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in saveApiSpec:', error);
    throw new Error('Failed to save API specification', { cause: error });
  }
}

export async function getLatestApiSpec(projectId: number) {
  try {
    const result = await db
      .select()
      .from(apiSpecs)
      .where(eq(apiSpecs.projectId, projectId))
      .orderBy(desc(apiSpecs.createdAt))
      .limit(1);
    return result[0] || null;
  } catch (error) {
    console.error('Error in getLatestApiSpec:', error);
    throw new Error('Failed to get latest API specification', { cause: error });
  }
}

export async function saveEndpoints(
  projectId: number,
  apiSpecId: number,
  endpointList: ApiEndpoint[]
) {
  try {
    // Clean out old endpoints for this project to maintain consistent inventory
    await db.delete(endpoints).where(eq(endpoints.projectId, projectId));

    if (endpointList.length === 0) return [];

    const values = endpointList.map((ep) => ({
      apiSpecId,
      projectId,
      path: ep.path,
      method: ep.method,
      summary: ep.summary || null,
      authenticationRequired: ep.requiresAuth || false,
      parameters: ep.parameters ? JSON.stringify(ep.parameters) : null,
      requestSchema: (ep.requestBodySchema || (ep as any).requestSchema) ? JSON.stringify(ep.requestBodySchema || (ep as any).requestSchema) : null,
      responseSchema: ep.responseSchema ? JSON.stringify(ep.responseSchema) : null,
      riskLevel: (ep.riskLevel as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') || 'LOW'
    }));

    return await db.insert(endpoints).values(values).returning();
  } catch (error) {
    console.error('Error in saveEndpoints:', error);
    throw new Error('Failed to save discovered endpoints', { cause: error });
  }
}

export async function getProjectEndpoints(projectId: number): Promise<ApiEndpoint[]> {
  try {
    const rows = await db
      .select()
      .from(endpoints)
      .where(eq(endpoints.projectId, projectId));

    return rows.map((r) => ({
      id: String(r.id),
      path: r.path,
      method: r.method as any,
      summary: r.summary || '',
      requiresAuth: r.authenticationRequired,
      riskLevel: r.riskLevel as any,
      parameters: r.parameters ? JSON.parse(r.parameters) : [],
      requestBodySchema: r.requestSchema || undefined,
      responseSchema: r.responseSchema || undefined,
      findingsCount: 0,
      status: 'SCANNED' as const
    }));
  } catch (error) {
    console.error('Error in getProjectEndpoints:', error);
    throw new Error('Failed to fetch project endpoints', { cause: error });
  }
}

export async function createScanRecord(projectId: number, userId: number) {
  try {
    const scanId = `SCAN-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
    const result = await db
      .insert(scans)
      .values({
        scanId,
        projectId,
        userId,
        status: 'QUEUED',
        startedAt: new Date(),
        createdAt: new Date()
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in createScanRecord:', error);
    throw new Error('Failed to create scan record', { cause: error });
  }
}

export async function updateScanRecord(scanDbId: number, updates: Partial<typeof scans.$inferInsert>) {
  try {
    const result = await db
      .update(scans)
      .set(updates)
      .where(eq(scans.id, scanDbId))
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in updateScanRecord:', error);
    throw new Error('Failed to update scan record', { cause: error });
  }
}

export async function saveVulnerabilities(
  scanDbId: number,
  projectId: number,
  findings: VulnerabilityFinding[]
) {
  try {
    if (findings.length === 0) return [];

    // Query endpoints to map endpoint path to endpoint ID
    const dbEndpoints = await db
      .select({ id: endpoints.id, path: endpoints.path })
      .from(endpoints)
      .where(eq(endpoints.projectId, projectId));

    const pathMap = new Map<string, number>();
    dbEndpoints.forEach((e) => pathMap.set(e.path, e.id));

    const values = findings.map((f) => ({
      vulnId: f.id,
      scanId: scanDbId,
      projectId,
      endpointId: pathMap.get(f.endpoint) || null,
      title: f.title,
      category: f.category,
      severity: f.severity,
      owaspCategory: f.owaspCategory || null,
      endpoint: f.endpoint,
      method: f.method,
      description: f.description,
      evidence: f.evidence,
      reproduction: JSON.stringify(f.reproduction),
      impact: f.impact,
      remediation: JSON.stringify(f.remediation),
      aiExplanation: f.aiExplanation || null,
      status: f.status || 'OPEN',
      detectedAt: new Date()
    }));

    return await db.insert(vulnerabilities).values(values).returning();
  } catch (error) {
    console.error('Error in saveVulnerabilities:', error);
    throw new Error('Failed to save vulnerability findings to database', { cause: error });
  }
}

export async function getProjectScans(projectId: number) {
  try {
    return await db
      .select()
      .from(scans)
      .where(eq(scans.projectId, projectId))
      .orderBy(desc(scans.startedAt));
  } catch (error) {
    console.error('Error in getProjectScans:', error);
    throw new Error('Failed to fetch scans', { cause: error });
  }
}

export async function getProjectVulnerabilities(projectId: number, scanDbId?: number): Promise<VulnerabilityFinding[]> {
  try {
    const conditions = [eq(vulnerabilities.projectId, projectId)];
    if (scanDbId) {
      conditions.push(eq(vulnerabilities.scanId, scanDbId));
    }

    const rows = await db
      .select()
      .from(vulnerabilities)
      .where(and(...conditions))
      .orderBy(desc(vulnerabilities.detectedAt));

    return rows.map((r) => ({
      id: r.vulnId,
      dbId: r.id,
      title: r.title,
      category: r.category as any,
      severity: r.severity as any,
      owaspCategory: r.owaspCategory || '',
      endpoint: r.endpoint,
      method: r.method as any,
      description: r.description,
      evidence: r.evidence,
      reproduction: JSON.parse(r.reproduction),
      impact: r.impact,
      remediation: JSON.parse(r.remediation),
      aiExplanation: r.aiExplanation || undefined,
      status: r.status as any,
      detectedAt: r.detectedAt.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
    }));
  } catch (error) {
    console.error('Error in getProjectVulnerabilities:', error);
    throw new Error('Failed to fetch vulnerabilities', { cause: error });
  }
}

export async function updateVulnerabilityStatus(vulnIdStr: string, status: 'OPEN' | 'RESOLVED', userId: number) {
  try {
    const owned = await db
      .select({ id: vulnerabilities.id })
      .from(vulnerabilities)
      .innerJoin(projects, eq(vulnerabilities.projectId, projects.id))
      .where(and(eq(vulnerabilities.vulnId, vulnIdStr), eq(projects.userId, userId)))
      .limit(1);
    if (!owned[0]) return null;
    const result = await db
      .update(vulnerabilities)
      .set({ status })
      .where(eq(vulnerabilities.vulnId, vulnIdStr))
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in updateVulnerabilityStatus:', error);
    throw new Error('Failed to update vulnerability status', { cause: error });
  }
}

export async function saveReport(projectId: number, scanId: number, title: string, reportData: any) {
  try {
    const result = await db
      .insert(reports)
      .values({
        projectId,
        scanId,
        title,
        reportData: JSON.stringify(reportData),
        generatedAt: new Date()
      })
      .returning();
    return result[0];
  } catch (error) {
    console.error('Error in saveReport:', error);
    throw new Error('Failed to save audit report', { cause: error });
  }
}

export async function getProjectReports(projectId: number) {
  try {
    const rows = await db
      .select()
      .from(reports)
      .where(eq(reports.projectId, projectId))
      .orderBy(desc(reports.generatedAt));

    return rows.map((r) => ({
      id: r.id,
      projectId: r.projectId,
      scanId: r.scanId,
      title: r.title,
      reportData: JSON.parse(r.reportData),
      generatedAt: r.generatedAt
    }));
  } catch (error) {
    console.error('Error in getProjectReports:', error);
    throw new Error('Failed to fetch reports', { cause: error });
  }
}
