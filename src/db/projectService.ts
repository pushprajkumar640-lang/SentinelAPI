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

export async function getDashboardSummary(userId: string | number) {
  try {
    const result = await db.execute(sql`
      SELECT
        COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'completed') AS "scansCount",
        COALESCE(AVG(
          CASE
            WHEN s.status = 'completed' THEN
              CASE
                WHEN s.critical_count > 0 THEN 25
                WHEN s.high_count > 0 THEN 50
                WHEN s.medium_count > 0 THEN 75
                ELSE 100
              END
          END
        ), 0) AS "averageScore",
        COUNT(v.id) AS "vulnerabilitiesCount",
        COUNT(v.id) FILTER (WHERE UPPER(v.severity) = 'CRITICAL') AS "criticalCount",
        COUNT(v.id) FILTER (WHERE UPPER(v.severity) = 'HIGH') AS "highCount",
        COUNT(v.id) FILTER (WHERE UPPER(v.severity) = 'MEDIUM') AS "mediumCount",
        COUNT(v.id) FILTER (WHERE UPPER(v.severity) = 'LOW') AS "lowCount"
      FROM public.projects p
      LEFT JOIN public.scans s
        ON s.project_id = p.id
      LEFT JOIN public.vulnerabilities v
        ON v.project_id = p.id
      WHERE p.user_id = ${String(userId)}
    `);

    const row = result.rows[0] || {};

    return {
      scansCount: Number(row.scansCount || 0),
      averageScore: Math.round(Number(row.averageScore || 0)),
      vulnerabilitiesCount: Number(row.vulnerabilitiesCount || 0),
      criticalCount: Number(row.criticalCount || 0),
      highCount: Number(row.highCount || 0),
      mediumCount: Number(row.mediumCount || 0),
      lowCount: Number(row.lowCount || 0)
    };
  } catch (error) {
    console.error('Error in getDashboardSummary:', error);

    return {
      scansCount: 0,
      averageScore: 0,
      vulnerabilitiesCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0
    };
  }
}

export async function getUserProjects(userId: string) {
  const result = await db.execute(sql`
    SELECT
      id,
      user_id AS "userId",
      name,
      description,
      target_base_url AS "apiUrl",
      false AS "isDemo",
      created_at AS "createdAt",
      updated_at AS "updatedAt"
    FROM public.projects
    WHERE user_id = ${userId}
    ORDER BY created_at DESC
  `);

  return result.rows;
}

export async function createProject(
  userId: string | number,
  name: string,
  description?: string,
  apiUrl?: string,
  isDemo = false
) {
  try {
    const projectId = `project_${Date.now()}`;

    const result = await db.execute(sql`
      INSERT INTO public.projects
        (
          id,
          user_id,
          name,
          description,
          target_base_url,
          environment,
          auth_type,
          created_at,
          updated_at
        )
      VALUES
        (
          ${projectId},
          ${String(userId)},
          ${name.trim()},
          ${description?.trim() || null},
          ${apiUrl?.trim() || ''},
          'staging',
          'bearer',
          NOW(),
          NOW()
        )
      RETURNING
        id,
        user_id AS "userId",
        name,
        description,
        target_base_url AS "apiUrl",
        false AS "isDemo",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `);

    return result.rows[0];
  } catch (error) {
    console.error('Error in createProject:', error);
    throw new Error('Failed to create project', { cause: error });
  }
}

export async function getProjectById(
  projectId: string | number,
  userId?: string | number
) {
  try {
    const result = await db.execute(sql`
      SELECT
        id,
        user_id AS "userId",
        name,
        description,
        target_base_url AS "apiUrl",
        false AS "isDemo",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM public.projects
      WHERE id = ${String(projectId)}
        ${userId !== undefined
          ? sql`AND user_id = ${String(userId)}`
          : sql``}
      LIMIT 1
    `);

    return result.rows[0] || null;
  } catch (error) {
    console.error('Error in getProjectById:', error);
    throw new Error('Failed to get project', { cause: error });
  }
}

export async function deleteProject(
  projectId: string | number,
  userId: string | number
) {
  try {
    await db.execute(sql`
      DELETE FROM public.projects
      WHERE id = ${String(projectId)}
        AND user_id = ${String(userId)}
    `);

    return true;
  } catch (error) {
    console.error('Error in deleteProject:', error);
    throw new Error('Failed to delete project', { cause: error });
  }
}

export async function updateProject(
  projectId: string | number,
  userId: string | number,
  values: {
    name?: string;
    description?: string;
    apiUrl?: string;
  }
) {
  try {
    const result = await db.execute(sql`
      UPDATE public.projects
      SET
        name = COALESCE(${values.name?.trim() || null}, name),
        description = COALESCE(${values.description?.trim() || null}, description),
        target_base_url = COALESCE(${values.apiUrl?.trim() || null}, target_base_url),
        updated_at = NOW()
      WHERE id = ${String(projectId)}
        AND user_id = ${String(userId)}
      RETURNING
        id,
        user_id AS "userId",
        name,
        description,
        target_base_url AS "apiUrl",
        false AS "isDemo",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `);

    return result.rows[0] || null;
  } catch (error) {
    console.error('Error in updateProject:', error);
    throw new Error('Failed to update project', { cause: error });
  }
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
