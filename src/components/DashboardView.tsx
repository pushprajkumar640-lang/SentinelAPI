import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Layers,
  Award,
  ChevronRight,
  TrendingDown,
  Info,
  ExternalLink,
  Play,
  FileCode,
  CheckCircle2,
  ShieldCheck
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts';
import { VulnerabilityFinding, SecurityScoreBreakdown } from '../types/security';

interface DashboardViewProps {
  score: SecurityScoreBreakdown;
  findings: VulnerabilityFinding[];
  totalEndpoints: number;
  hasScanned: boolean;
  projectName?: string;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onNavigateTab: (tab: 'scan' | 'vulnerabilities' | 'endpoints' | 'reports') => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  score,
  findings,
  totalEndpoints,
  hasScanned,
  projectName = 'Authorized Project',
  onSelectFinding,
  onNavigateTab
}) => {
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  const chartData = [
    { name: 'Critical', count: criticalCount, color: '#ef4444' },
    { name: 'High', count: highCount, color: '#f97316' },
    { name: 'Medium', count: mediumCount, color: '#eab308' },
    { name: 'Low', count: lowCount, color: '#3b82f6' }
  ];

  return (
    <div className="space-y-6">
      {/* Top 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Security Score */}
        <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-[#0c1017] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Security Score</span>
            <Award
              className={`h-5 w-5 ${
                !hasScanned
                  ? 'text-slate-500'
                  : score.currentScore >= 80
                  ? 'text-emerald-400'
                  : score.currentScore >= 60
                  ? 'text-amber-400'
                  : 'text-red-400'
              }`}
            />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            {hasScanned ? (
              <>
                <span
                  className={`text-3xl font-extrabold font-mono tracking-tight ${
                    score.currentScore >= 80
                      ? 'text-emerald-400'
                      : score.currentScore >= 60
                      ? 'text-amber-400'
                      : 'text-red-400'
                  }`}
                >
                  {score.currentScore}
                </span>
                <span className="text-xs font-mono text-slate-400">/ 100</span>
                <span
                  className={`ml-auto text-xs font-mono px-2 py-0.5 rounded border ${
                    score.ratingGrade === 'A' || score.ratingGrade === 'A+'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : score.ratingGrade === 'B'
                      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                      : score.ratingGrade === 'C'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      : 'bg-red-500/10 text-red-400 border-red-500/20'
                  }`}
                >
                  Grade: {score.ratingGrade}
                </span>
              </>
            ) : (
              <>
                <span className="text-2xl font-bold font-mono tracking-tight text-slate-500">
                  Not Scanned
                </span>
                <span className="ml-auto text-xs font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-400">
                  Pending Scan
                </span>
              </>
            )}
          </div>
          <p className="mt-2 text-[11px] text-slate-400 font-mono">
            {hasScanned ? (
              score.currentScore === 100 ? (
                'No deductions (Clean API)'
              ) : (
                <>
                  Deductions: {score.deductions.criticalCount > 0 && `-${score.deductions.criticalDeduction} Crit `}
                  {score.deductions.highCount > 0 && `-${score.deductions.highDeduction} High `}
                  {score.deductions.mediumCount > 0 && `-${score.deductions.mediumDeduction} Med `}
                  {score.deductions.lowCount > 0 && `-${score.deductions.lowDeduction} Low`}
                </>
              )
            ) : (
              'Run a security scan to compute score'
            )}
          </p>
        </div>

        {/* Critical Vulnerabilities */}
        <div className="relative overflow-hidden rounded-xl border border-red-500/20 bg-[#0c1017] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-red-400">Critical Issues (BOLA)</span>
            <ShieldAlert className="h-5 w-5 text-red-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-red-400">
              {hasScanned ? criticalCount : 0}
            </span>
            <span className="text-xs font-mono text-slate-400">active exploit paths</span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            {hasScanned
              ? criticalCount > 0
                ? 'Immediate remediation required'
                : 'No critical BOLA flaws detected'
              : 'Evaluated upon scan execution'}
          </p>
        </div>

        {/* High Vulnerabilities */}
        <div className="relative overflow-hidden rounded-xl border border-orange-500/20 bg-[#0c1017] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-orange-400">High Vulnerabilities</span>
            <AlertTriangle className="h-5 w-5 text-orange-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-orange-400">
              {hasScanned ? highCount : 0}
            </span>
            <span className="text-xs font-mono text-slate-400">flaws detected</span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            {hasScanned
              ? highCount > 0
                ? 'Excessive Data Exposure & Missing Auth'
                : 'No high severity findings'
              : 'Evaluated upon scan execution'}
          </p>
        </div>

        {/* Endpoints Discovered/Audited */}
        <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-[#0c1017] p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Endpoints Inventory</span>
            <Layers className="h-5 w-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100">
              {totalEndpoints}
            </span>
            <span className="text-xs font-mono text-emerald-400">
              {totalEndpoints > 0 ? (hasScanned ? '100% evaluated' : 'discovered') : 'none uploaded'}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400">
            {totalEndpoints > 0
              ? hasScanned
                ? `Auth coverage: ${score.authCoveragePercentage}% of endpoints`
                : 'Endpoints ready for defensive scanning'
              : 'Upload OpenAPI contract to discover'}
          </p>
        </div>
      </div>

      {/* If No Scan Has Been Run Yet: Clear Empty State CTA */}
      {!hasScanned && (
        <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-br from-emerald-950/20 via-slate-900/60 to-cyan-950/20 p-6 md:p-8 text-center space-y-4">
          <div className="h-12 w-12 mx-auto rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="h-6 w-6" />
          </div>

          <div className="max-w-xl mx-auto space-y-2">
            <h3 className="text-lg font-bold text-white">
              Run your first security scan to analyze this API
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              SentinelAPI will perform controlled defensive tests across all discovered endpoints to detect Broken Object Level Authorization (BOLA/IDOR), excessive data exposure, missing rate limits, and authentication misconfigurations.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            {totalEndpoints === 0 ? (
              <button
                onClick={() => onNavigateTab('scan')}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-5 py-2.5 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
              >
                <FileCode className="h-4 w-4" />
                <span>Add API Specification (OpenAPI / Swagger)</span>
              </button>
            ) : (
              <button
                onClick={() => onNavigateTab('scan')}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-6 py-2.5 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
              >
                <Play className="h-4 w-4 fill-slate-950" />
                <span>Launch Defensive Scan ({totalEndpoints} endpoints)</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* Post-Scan Sections: Chart & Transparent Scoring Breakdown */}
      {hasScanned && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Vulnerability Distribution Chart */}
          <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-[#0c1017] p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">
                  Vulnerability Severity Distribution
                </h3>
                <p className="text-xs text-slate-400">
                  Ranked breakdown according to OWASP API Security Standard
                </p>
              </div>
              <button
                onClick={() => onNavigateTab('vulnerabilities')}
                className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1 cursor-pointer"
              >
                <span>View All</span>
                <ChevronRight className="h-3 w-3" />
              </button>
            </div>

            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={chartData}
                  layout="vertical"
                  margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#64748b" tick={{ fill: '#64748b', fontSize: 12 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#64748b"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc'
                    }}
                    cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Transparent Score Calculation Card */}
          <div className="rounded-xl border border-slate-800 bg-[#0c1017] p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <TrendingDown className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  Transparent Score Formula
                </h3>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                SentinelAPI calculates an objective posture score out of 100 based on verified defensive findings:
              </p>

              <div className="space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between pb-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Baseline Perfect API</span>
                  <span className="text-slate-200 font-bold">100 pts</span>
                </div>
                <div className="flex items-center justify-between text-red-400">
                  <span>Critical Flaws ({score.deductions.criticalCount})</span>
                  <span>-{score.deductions.criticalDeduction} pts</span>
                </div>
                <div className="flex items-center justify-between text-orange-400">
                  <span>High Severity ({score.deductions.highCount})</span>
                  <span>-{score.deductions.highDeduction} pts</span>
                </div>
                <div className="flex items-center justify-between text-yellow-400">
                  <span>Medium Severity ({score.deductions.mediumCount})</span>
                  <span>-{score.deductions.mediumDeduction} pts</span>
                </div>
                <div className="flex items-center justify-between text-blue-400">
                  <span>Low Severity ({score.deductions.lowCount})</span>
                  <span>-{score.deductions.lowDeduction} pts</span>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-slate-100 font-bold">
                  <span>Computed Score</span>
                  <span className="text-amber-400">{score.currentScore} / 100</span>
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-lg bg-slate-900/60 p-3 border border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-2">
              <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>
                {criticalCount > 0
                  ? `Resolving the Critical BOLA vulnerability will restore +${score.deductions.criticalDeduction} points to your security score.`
                  : 'All endpoints pass baseline ownership checks. Maintain zero-trust token verification.'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Recent Findings Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1017] p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">
              Verified Defensive Findings
            </h3>
            <p className="text-xs text-slate-400">
              {hasScanned
                ? 'Sandbox-verified vulnerabilities requiring remediation'
                : 'Vulnerabilities discovered during security scans will appear here'}
            </p>
          </div>
          {hasScanned && findings.length > 0 && (
            <button
              onClick={() => onNavigateTab('vulnerabilities')}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1 cursor-pointer"
            >
              <span>Open Findings Manager</span>
              <ExternalLink className="h-3 w-3" />
            </button>
          )}
        </div>

        {findings.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs font-mono border border-dashed border-slate-800 rounded-lg">
            {hasScanned
              ? '✓ No vulnerabilities detected for this API.'
              : 'No security findings recorded yet. Run a defensive scan to detect and verify vulnerabilities.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="pb-3 pl-2">Severity</th>
                  <th className="pb-3">Vulnerability</th>
                  <th className="pb-3">Endpoint</th>
                  <th className="pb-3">OWASP Category</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3 text-right pr-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.slice(0, 5).map((f, idx) => (
                  <tr
                    key={`${f.id}-${idx}`}
                    onClick={() => onSelectFinding(f)}
                    className="hover:bg-slate-900/40 cursor-pointer transition-colors group"
                  >
                    <td className="py-3.5 pl-2 font-mono">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          f.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : f.severity === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : f.severity === 'MEDIUM'
                            ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                            : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3.5 text-slate-200 font-medium group-hover:text-emerald-300 transition-colors">
                      {f.title}
                    </td>
                    <td className="py-3.5 font-mono text-slate-400">
                      <span className="text-[10px] text-slate-500 mr-1.5">{f.method}</span>
                      {f.endpoint}
                    </td>
                    <td className="py-3.5 text-slate-400 font-mono text-[11px]">
                      {f.owaspCategory || 'OWASP API Security'}
                    </td>
                    <td className="py-3.5 font-mono">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] ${
                          f.status === 'RESOLVED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}
                      >
                        {f.status}
                      </span>
                    </td>
                    <td className="py-3.5 text-right pr-2">
                      <span className="text-emerald-400 group-hover:underline text-[11px] font-mono">
                        Inspect &rarr;
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
