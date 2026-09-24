import { VulnerabilityFinding, ApiEndpoint } from '../../types/security';

export function deduplicateFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
  const seen = new Set<string>();
  const seenIds = new Set<string>();
  const unique: VulnerabilityFinding[] = [];

  for (const f of findings) {
    const key = `${f.category}:${f.endpoint}:${f.method}`;
    if (!seen.has(key)) {
      seen.add(key);
      let uniqueId = f.id;
      if (!uniqueId || seenIds.has(uniqueId)) {
        uniqueId = `${f.id || 'VULN'}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
      }
      seenIds.add(uniqueId);
      unique.push({ ...f, id: uniqueId });
    }
  }

  return unique;
}

export function correlateEndpointsWithFindings(
  endpoints: ApiEndpoint[],
  findings: VulnerabilityFinding[]
): ApiEndpoint[] {
  return endpoints.map((ep) => {
    const matching = findings.filter(
      (f) =>
        f.endpoint === ep.path ||
        (f.endpoint.includes('{') &&
          ep.path.replace(/\{[^}]+\}/g, '*') === f.endpoint.replace(/\{[^}]+\}/g, '*'))
    );

    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (matching.some((f) => f.severity === 'CRITICAL')) riskLevel = 'CRITICAL';
    else if (matching.some((f) => f.severity === 'HIGH')) riskLevel = 'HIGH';
    else if (matching.some((f) => f.severity === 'MEDIUM')) riskLevel = 'MEDIUM';

    return {
      ...ep,
      riskLevel,
      findingsCount: matching.length,
      status: 'TESTED'
    };
  });
}
