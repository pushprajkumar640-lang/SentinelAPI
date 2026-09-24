import { VulnerabilityFinding, SecurityScoreBreakdown, ApiEndpoint } from '../../types/security';

export function calculateSecurityScore(
  findings: VulnerabilityFinding[],
  endpoints: ApiEndpoint[]
): SecurityScoreBreakdown {
  const openFindings = findings.filter((f) => f.status === 'OPEN');

  const criticalCount = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = openFindings.filter((f) => f.severity === 'LOW').length;

  // Exact user scoring logic:
  // Base = 100
  // Critical = -25
  // High = -15
  // Medium = -8
  // Low = -3
  const criticalDeduction = criticalCount * 25;
  const highDeduction = highCount * 15;
  const mediumDeduction = mediumCount * 8;
  const lowDeduction = lowCount * 3;

  const totalDeductions =
    criticalDeduction + highDeduction + mediumDeduction + lowDeduction;

  const currentScore = Math.max(0, Math.min(100, 100 - totalDeductions));

  // Compute Letter Grade
  let ratingGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'D';
  if (currentScore >= 95) ratingGrade = 'A+';
  else if (currentScore >= 85) ratingGrade = 'A';
  else if (currentScore >= 75) ratingGrade = 'B';
  else if (currentScore >= 65) ratingGrade = 'C';
  else if (currentScore >= 50) ratingGrade = 'D';
  else ratingGrade = 'F';

  // Auth coverage percentage
  const totalEps = endpoints.length || 1;
  const authEps = endpoints.filter((ep) => ep.requiresAuth).length;
  const authCoveragePercentage = Math.round((authEps / totalEps) * 100);

  return {
    currentScore,
    baseScore: 100,
    deductions: {
      criticalCount,
      criticalDeduction,
      highCount,
      highDeduction,
      mediumCount,
      mediumDeduction,
      lowCount,
      lowDeduction
    },
    authCoveragePercentage,
    ratingGrade
  };
}
