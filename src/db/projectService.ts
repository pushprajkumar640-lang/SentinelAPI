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
  projectId: string | number,
  title: string,
  version: string,
  description: string | undefined,
  baseUrl: string | undefined,
  format: 'json' | 'yaml',
  rawSpec: string
) {
  try {
    const specId = `spec_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;

    let contentJson: unknown;

    try {
      contentJson = JSON.parse(rawSpec);
    } catch {
      contentJson = {
        raw: rawSpec
      };
    }

    const result = await db.execute(sql`
      INSERT INTO public.api_specs
        (
          id,
          project_id,
          title,
          version,
          spec_type,
          content_json,
          raw_spec,
          created_at,
          updated_at
        )
      VALUES
        (
          ${specId},
          ${String(projectId)},
          ${title},
          ${version || '1.0.0'},
          'openapi',
          ${JSON.stringify(contentJson)},
          ${rawSpec},
          NOW(),
          NOW()
        )
      RETURNING
        id,
        project_id AS "projectId",
        title,
        version,
        spec_type AS "specType",
        content_json AS "contentJson",
        raw_spec AS "rawSpec",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `);

    const row = result.rows[0];

    return {
      ...row,
      description: description || null,
      baseUrl: baseUrl || null,
      format
    };
  } catch (error) {
    console.error('Error in saveApiSpec:', error);
    throw new Error('Failed to save API specification', {
      cause: error
    });
  }
}

export async function getLatestApiSpec(projectId: string | number) {
  try {
    const result = await db.execute(sql`
      SELECT
        id,
        project_id AS "projectId",
        title,
        version,
        spec_type AS "specType",
        content_json AS "contentJson",
        raw_spec AS "rawSpec",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM public.api_specs
      WHERE project_id = ${String(projectId)}
      ORDER BY created_at DESC
      LIMIT 1
    `);

    const row = result.rows[0];

    if (!row) {
      return null;
    }

    return {
      ...row,
      description: null,
      baseUrl: null,
      format: 'json'
    };
  } catch (error) {
    console.error('Error in getLatestApiSpec:', error);
    throw new Error('Failed to get latest API specification', {
      cause: error
    });
  }
}

export async function saveEndpoints(
  projectId: string | number,
  apiSpecId: string | number,
  endpointList: ApiEndpoint[]
) {
  try {
    await db.execute(sql`
      DELETE FROM public.endpoints
      WHERE project_id = ${String(projectId)}
    `);

    const savedEndpoints = [];

    for (const endpoint of endpointList) {
      const endpointId = `endpoint_${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 8)}`;

      const result = await db.execute(sql`
        INSERT INTO public.endpoints
          (
            id,
            project_id,
            api_spec_id,
            path,
            method,
            summary,
            description,
            headers_json,
            parameters_json,
            request_body_json,
            responses_json,
            auth_required,
            risk_score,
            created_at
          )
        VALUES
          (
            ${endpointId},
            ${String(projectId)},
            ${String(apiSpecId)},
            ${endpoint.path || ''},
            ${String(endpoint.method || 'GET').toUpperCase()},
            ${endpoint.summary || null},
            ${endpoint.description || null},
            ${JSON.stringify(endpoint.headers || {})},
            ${JSON.stringify(endpoint.parameters || [])},
            ${JSON.stringify(endpoint.requestBodySchema || null)},
            ${JSON.stringify(endpoint.responseSchema || null)},
            ${endpoint.requiresAuth !== false},
            ${Number(endpoint.riskLevel || 0)},
            NOW()
          )
        RETURNING
          id,
          project_id AS "projectId",
          api_spec_id AS "apiSpecId",
          path,
          method,
          summary,
          description,
          headers_json AS "headers",
          parameters_json AS "parameters",
          request_body_json AS "requestBodySchema",
          responses_json AS "responseSchema",
          auth_required AS "requiresAuth",
          risk_score AS "riskLevel",
          created_at AS "createdAt"
      `);

      if (result.rows[0]) {
        savedEndpoints.push(result.rows[0]);
      }
    }

    return savedEndpoints;
  } catch (error) {
    console.error('Error in saveEndpoints:', error);
    throw new Error('Failed to save endpoints', { cause: error });
  }
}

export async function getProjectEndpoints(
  projectId: string | number
): Promise<ApiEndpoint[]> {
  try {
    const result = await db.execute(sql`
      SELECT
        id,
        project_id AS "projectId",
        api_spec_id AS "apiSpecId",
        path,
        method,
        summary,
        description,
        headers_json AS "headers",
        parameters_json AS "parameters",
        request_body_json AS "requestBodySchema",
        responses_json AS "responseSchema",
        auth_required AS "requiresAuth",
        risk_score AS "riskLevel",
        created_at AS "createdAt"
      FROM public.endpoints
      WHERE project_id = ${String(projectId)}
      ORDER BY created_at ASC
    `);

    return result.rows.map((row: any) => ({
      id: String(row.id),
      path: row.path || '',
      method: row.method || 'GET',
      summary: row.summary || '',
      description: row.description || '',
      headers: row.headers || {},
      parameters: row.parameters || [],
      requestBodySchema: row.requestBodySchema || null,
      responseSchema: row.responseSchema || null,
      requiresAuth: row.requiresAuth !== false,
      riskLevel: Number(row.riskLevel || 0)
    }));
  } catch (error) {
    console.error('Error in getProjectEndpoints:', error);
    throw new Error('Failed to get project endpoints', {
      cause: error
    });
  }
}

export async function createScanRecord(
  projectId: string | number,
  userId: string | number
) {
  try {
    const scanId = `scan_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;

    const projectResult = await db.execute(sql`
      SELECT target_base_url
      FROM public.projects
      WHERE id = ${String(projectId)}
      LIMIT 1
    `);

    const targetUrl = projectResult.rows[0]?.target_base_url || '';

    const result = await db.execute(sql`
      INSERT INTO public.scans
        (
          id,
          project_id,
          user_id,
          name,
          status,
          scan_type,
          target_url,
          total_endpoints,
          scanned_endpoints,
          vulnerabilities_count,
          critical_count,
          high_count,
          medium_count,
          low_count,
          created_at
        )
      VALUES
        (
          ${scanId},
          ${String(projectId)},
          ${String(userId)},
          ${`Security Scan ${new Date().toLocaleString()}`},
          'pending',
          'owasp_top10',
          ${targetUrl},
          0,
          0,
          0,
          0,
          0,
          0,
          0,
          NOW()
        )
      RETURNING
        id,
        project_id AS "projectId",
        user_id AS "userId",
        name,
        status,
        scan_type AS "scanType",
        target_url AS "targetUrl",
        total_endpoints AS "totalEndpoints",
        scanned_endpoints AS "scannedEndpoints",
        vulnerabilities_count AS "vulnerabilitiesCount",
        critical_count AS "criticalCount",
        high_count AS "highCount",
        medium_count AS "mediumCount",
        low_count AS "lowCount",
        started_at AS "startedAt",
        completed_at AS "completedAt",
        duration_ms AS "durationMs",
        created_at AS "createdAt"
    `);

    const row = result.rows[0];

    return {
      ...row,
      scanId: row.id,
      securityScore: 0,
      ratingGrade: 'N/A'
    };
  } catch (error) {
    console.error('Error in createScanRecord:', error);
    throw new Error('Failed to create scan record', {
      cause: error
    });
  }
}

export async function updateScanRecord(
  scanDbId: string | number,
  updates: any
) {
  try {
    const setParts: any[] = [];

    if (updates.status !== undefined) {
      const statusMap: Record<string, string> = {
        QUEUED: 'pending',
        PENDING: 'pending',
        RUNNING: 'running',
        COMPLETED: 'completed',
        FAILED: 'failed'
      };

      setParts.push(
        sql`status = ${statusMap[String(updates.status).toUpperCase()] || String(updates.status).toLowerCase()}`
      );
    }

    if (updates.totalEndpoints !== undefined) {
      setParts.push(sql`total_endpoints = ${Number(updates.totalEndpoints)}`);
    }

    if (updates.scannedEndpoints !== undefined) {
      setParts.push(sql`scanned_endpoints = ${Number(updates.scannedEndpoints)}`);
    }

    if (updates.vulnerabilitiesCount !== undefined) {
      setParts.push(
        sql`vulnerabilities_count = ${Number(updates.vulnerabilitiesCount)}`
      );
    }

    if (updates.criticalCount !== undefined) {
      setParts.push(sql`critical_count = ${Number(updates.criticalCount)}`);
    }

    if (updates.highCount !== undefined) {
      setParts.push(sql`high_count = ${Number(updates.highCount)}`);
    }

    if (updates.mediumCount !== undefined) {
      setParts.push(sql`medium_count = ${Number(updates.mediumCount)}`);
    }

    if (updates.lowCount !== undefined) {
      setParts.push(sql`low_count = ${Number(updates.lowCount)}`);
    }

    if (updates.startedAt !== undefined) {
      setParts.push(sql`started_at = ${updates.startedAt}`);
    }

    if (updates.completedAt !== undefined) {
      setParts.push(sql`completed_at = ${updates.completedAt}`);
    }

    if (updates.durationMs !== undefined) {
      setParts.push(sql`duration_ms = ${Number(updates.durationMs)}`);
    }

    if (setParts.length === 0) {
      return null;
    }

    const setClause = sql.join(setParts, sql`, `);

    const result = await db.execute(sql`
      UPDATE public.scans
      SET ${setClause}
      WHERE id = ${String(scanDbId)}
      RETURNING
        id,
        project_id AS "projectId",
        user_id AS "userId",
        name,
        status,
        scan_type AS "scanType",
        target_url AS "targetUrl",
        total_endpoints AS "totalEndpoints",
        scanned_endpoints AS "scannedEndpoints",
        vulnerabilities_count AS "vulnerabilitiesCount",
        critical_count AS "criticalCount",
        high_count AS "highCount",
        medium_count AS "mediumCount",
        low_count AS "lowCount",
        started_at AS "startedAt",
        completed_at AS "completedAt",
        duration_ms AS "durationMs",
        created_at AS "createdAt"
    `);

    const row = result.rows[0];

    if (!row) {
      return null;
    }

    const critical = Number(row.criticalCount || 0);
    const high = Number(row.highCount || 0);
    const medium = Number(row.mediumCount || 0);

    const securityScore =
      critical > 0 ? 25 :
      high > 0 ? 50 :
      medium > 0 ? 75 :
      100;

    return {
      ...row,
      scanId: row.id,
      securityScore,
      ratingGrade:
        securityScore >= 90 ? 'A' :
        securityScore >= 75 ? 'B' :
        securityScore >= 50 ? 'C' :
        securityScore >= 25 ? 'D' : 'F'
    };
  } catch (error) {
    console.error('Error in updateScanRecord:', error);
    throw new Error('Failed to update scan record', {
      cause: error
    });
  }
}

export async function saveVulnerabilities(
  scanDbId: string | number,
  projectId: string | number,
  findings: VulnerabilityFinding[]
) {
  try {
    const saved = [];

    for (const finding of findings) {
      const vulnerabilityId = `vuln_${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 8)}`;

      const severity = String(finding.severity || 'LOW').toUpperCase();

      const endpointInfo = {
        endpoint: finding.endpoint || '',
        method: finding.method || '',
        evidence: finding.evidence || ''
      };

      const result = await db.execute(sql`
        INSERT INTO public.vulnerabilities
          (
            id,
            scan_id,
            project_id,
            endpoint_id,
            title,
            severity,
            owasp_category,
            cwe_id,
            cvss_score,
            description,
            evidence_request,
            evidence_response,
            reproduction_steps,
            remediation,
            ai_analysis,
            status,
            created_at
          )
        VALUES
          (
            ${vulnerabilityId},
            ${String(scanDbId)},
            ${String(projectId)},
            NULL,
            ${finding.title || 'Security Vulnerability'},
            ${severity},
            ${finding.category || null},
            ${finding.cwe || null},
            ${finding.cvssScore != null ? Number(finding.cvssScore) : null},
            ${finding.description || ''},
            ${JSON.stringify(endpointInfo)},
            NULL,
            ${JSON.stringify(finding.reproduction || [])},
            ${JSON.stringify(finding.remediation || '')},
            ${JSON.stringify(finding.aiExplanation || '')},
            'open',
            NOW()
          )
        RETURNING
          id,
          scan_id AS "scanId",
          project_id AS "projectId",
          title,
          severity,
          owasp_category AS "owaspCategory",
          cwe_id AS "cweId",
          cvss_score AS "cvssScore",
          description,
          evidence_request AS "evidenceRequest",
          reproduction_steps AS "reproductionSteps",
          remediation,
          ai_analysis AS "aiAnalysis",
          status,
          created_at AS "createdAt"
      `);

      if (result.rows[0]) {
        saved.push(result.rows[0]);
      }
    }

    return saved;
  } catch (error) {
    console.error('Error in saveVulnerabilities:', error);
    throw new Error('Failed to save vulnerabilities', {
      cause: error
    });
  }
}

export async function getProjectScans(projectId: string | number) {
  try {
    const result = await db.execute(sql`
      SELECT
        id,
        project_id AS "projectId",
        user_id AS "userId",
        name,
        status,
        scan_type AS "scanType",
        target_url AS "targetUrl",
        total_endpoints AS "totalEndpoints",
        scanned_endpoints AS "scannedEndpoints",
        vulnerabilities_count AS "vulnerabilitiesCount",
        critical_count AS "criticalCount",
        high_count AS "highCount",
        medium_count AS "mediumCount",
        low_count AS "lowCount",
        started_at AS "startedAt",
        completed_at AS "completedAt",
        duration_ms AS "durationMs",
        created_at AS "createdAt"
      FROM public.scans
      WHERE project_id = ${String(projectId)}
      ORDER BY created_at DESC
    `);

    return result.rows.map((row: any) => {
      const critical = Number(row.criticalCount || 0);
      const high = Number(row.highCount || 0);
      const medium = Number(row.mediumCount || 0);

      const securityScore =
        critical > 0 ? 25 :
        high > 0 ? 50 :
        medium > 0 ? 75 :
        100;

      return {
        ...row,
        scanId: String(row.id),
        securityScore,
        ratingGrade:
          securityScore >= 90 ? 'A' :
          securityScore >= 75 ? 'B' :
          securityScore >= 50 ? 'C' :
          securityScore >= 25 ? 'D' : 'F'
      };
    });
  } catch (error) {
    console.error('Error in getProjectScans:', error);
    throw new Error('Failed to get project scans', {
      cause: error
    });
  }
}

export async function getProjectVulnerabilities(
  projectId: string | number,
  scanDbId?: string | number
) {
  try {
    const result = await db.execute(sql`
      SELECT
        v.id,
        v.scan_id AS "scanId",
        v.project_id AS "projectId",
        v.title,
        v.severity,
        v.owasp_category AS "owaspCategory",
        v.cwe_id AS "cweId",
        v.cvss_score AS "cvssScore",
        v.description,
        v.evidence_request AS "evidenceRequest",
        v.reproduction_steps AS "reproductionSteps",
        v.remediation,
        v.ai_analysis AS "aiAnalysis",
        v.status,
        v.created_at AS "createdAt"
      FROM public.vulnerabilities v
      WHERE v.project_id = ${String(projectId)}
        ${
          scanDbId !== undefined
            ? sql`AND v.scan_id = ${String(scanDbId)}`
            : sql``
        }
      ORDER BY v.created_at DESC
    `);

    return result.rows.map((row: any) => {
      let endpoint = '';
      let method = 'GET';
      let evidence = '';

      try {
        const info =
          typeof row.evidenceRequest === 'string'
            ? JSON.parse(row.evidenceRequest)
            : row.evidenceRequest || {};

        endpoint = info.endpoint || '';
        method = info.method || 'GET';
        evidence = info.evidence || '';
      } catch {
        evidence = row.evidenceRequest || '';
      }

      let reproduction: any[] = [];
      try {
        reproduction =
          typeof row.reproductionSteps === 'string'
            ? JSON.parse(row.reproductionSteps)
            : row.reproductionSteps || [];
      } catch {
        reproduction = [];
      }

      let remediation = '';
      try {
        remediation =
          typeof row.remediation === 'string'
            ? JSON.parse(row.remediation)
            : row.remediation || '';
      } catch {
        remediation = row.remediation || '';
      }

      let aiExplanation = '';
      try {
        aiExplanation =
          typeof row.aiAnalysis === 'string'
            ? JSON.parse(row.aiAnalysis)
            : row.aiAnalysis || '';
      } catch {
        aiExplanation = row.aiAnalysis || '';
      }

      return {
        id: String(row.id),
        scanId: String(row.scanId),
        projectId: String(row.projectId),
        title: row.title || 'Security Vulnerability',
        severity: row.severity || 'LOW',
        category: row.owaspCategory || '',
        owaspCategory: row.owaspCategory || '',
        cwe: row.cweId || '',
        cweId: row.cweId || '',
        cvssScore:
          row.cvssScore != null ? Number(row.cvssScore) : null,
        description: row.description || '',
        endpoint,
        method,
        evidence,
        reproduction,
        remediation,
        aiExplanation,
        status: row.status || 'open',
        createdAt: row.createdAt
      };
    });
  } catch (error) {
    console.error('Error in getProjectVulnerabilities:', error);
    throw new Error('Failed to get project vulnerabilities', {
      cause: error
    });
  }
}

export async function updateVulnerabilityStatus(
  vulnIdStr: string,
  status: 'open' | 'resolved' | 'false_positive',
  userId: string | number
) {
  try {
    const result = await db.execute(sql`
      UPDATE public.vulnerabilities v
      SET status = ${status}
      FROM public.projects p
      WHERE v.id = ${String(vulnIdStr)}
        AND v.project_id = p.id
        AND p.user_id = ${String(userId)}
      RETURNING
        v.id,
        v.scan_id AS "scanId",
        v.project_id AS "projectId",
        v.title,
        v.severity,
        v.owasp_category AS "owaspCategory",
        v.cwe_id AS "cweId",
        v.cvss_score AS "cvssScore",
        v.description,
        v.status,
        v.created_at AS "createdAt"
    `);

    return result.rows[0] || null;
  } catch (error) {
    console.error('Error in updateVulnerabilityStatus:', error);
    throw new Error('Failed to update vulnerability status', {
      cause: error
    });
  }
}

export async function saveReport(
  projectId: string | number,
  scanId: string | number,
  title: string,
  reportData: any
) {
  try {
    const reportId = `report_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;

    const summary =
      reportData?.summary ||
      reportData?.executiveSummary ||
      '';

    const executiveSummary =
      reportData?.executiveSummary ||
      reportData?.summary ||
      '';

    const result = await db.execute(sql`
      INSERT INTO public.reports
        (
          id,
          project_id,
          scan_id,
          user_id,
          title,
          summary,
          executive_summary,
          format,
          report_data_json,
          generated_at,
          created_at
        )
      SELECT
        ${reportId},
        p.id,
        ${String(scanId)},
        p.user_id,
        ${title},
        ${summary},
        ${executiveSummary},
        'json',
        ${JSON.stringify(reportData || {})},
        NOW(),
        NOW()
      FROM public.projects p
      WHERE p.id = ${String(projectId)}
      RETURNING
        id,
        project_id AS "projectId",
        scan_id AS "scanId",
        user_id AS "userId",
        title,
        summary,
        executive_summary AS "executiveSummary",
        format,
        report_data_json AS "reportData",
        generated_at AS "generatedAt",
        created_at AS "createdAt"
    `);

    const row = result.rows[0];

    if (!row) {
      throw new Error('Project not found');
    }

    return {
      ...row,
      reportData:
        typeof row.reportData === 'string'
          ? JSON.parse(row.reportData)
          : row.reportData || {}
    };
  } catch (error) {
    console.error('Error in saveReport:', error);
    throw new Error('Failed to save report', {
      cause: error
    });
  }
}

export async function getProjectReports(projectId: string | number) {
  try {
    const result = await db.execute(sql`
      SELECT
        id,
        project_id AS "projectId",
        scan_id AS "scanId",
        user_id AS "userId",
        title,
        summary,
        executive_summary AS "executiveSummary",
        format,
        report_data_json AS "reportData",
        generated_at AS "generatedAt",
        created_at AS "createdAt"
      FROM public.reports
      WHERE project_id = ${String(projectId)}
      ORDER BY created_at DESC
    `);

    return result.rows.map((row: any) => ({
      ...row,
      reportData:
        typeof row.reportData === 'string'
          ? JSON.parse(row.reportData)
          : row.reportData || {}
    }));
  } catch (error) {
    console.error('Error in getProjectReports:', error);
    throw new Error('Failed to get project reports', {
      cause: error
    });
  }
}