import React from 'react';
import {
  Printer,
  Download,
  Shield,
  Award,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Layers,
  Calendar,
  FileCheck
} from 'lucide-react';
import { VulnerabilityFinding, SecurityScoreBreakdown } from '../types/security';

interface ReportsViewProps {
  findings: VulnerabilityFinding[];
  score: SecurityScoreBreakdown;
  totalEndpoints: number;
  apiName?: string;
  apiVersion?: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  findings,
  score,
  totalEndpoints,
  apiName = 'FoodDelivery Sandbox API',
  apiVersion = 'v1.0.0'
}) => {
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
  const highFindings = findings.filter(f => f.severity === 'HIGH');
  const mediumFindings = findings.filter(f => f.severity === 'MEDIUM');
  const lowFindings = findings.filter(f => f.severity === 'LOW');

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const reportData = {
      reportTitle: 'SENTINELAPI Defensive Audit Report',
      generatedAt: new Date().toISOString(),
      apiInformation: {
        name: apiName,
        version: apiVersion,
        targetScope: 'LOCAL_ISOLATED_SANDBOX_127.0.0.1',
        totalEndpoints
      },
      securityScore: {
        score: score.currentScore,
        grade: score.ratingGrade,
        deductions: score.deductions
      },
      findingsSummary: {
        critical: criticalFindings.length,
        high: highFindings.length,
        medium: mediumFindings.length,
        low: lowFindings.length
      },
      findings
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelapi-audit-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 no-print">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Security Audit Report
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Executive vulnerability assessment & OWASP API Top 10 compliance document
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-all cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download JSON</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-teal-500 px-4 py-2 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
          >
            <Printer className="h-3.5 w-3.5" />
            <span>Print / Export PDF</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document Card */}
      <div className="rounded-2xl border border-slate-800 bg-[#0c1017] p-8 sm:p-10 shadow-lg print:border-none print:bg-white print:text-black">
        {/* Document Header */}
        <div className="border-b border-slate-800 print:border-black/20 pb-6 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/30 print:border-emerald-600">
              <Shield className="h-6 w-6 text-emerald-400 print:text-emerald-700" />
            </div>
            <div>
              <div className="text-lg font-black tracking-wider text-white print:text-black">
                SENTINEL<span className="text-emerald-400 print:text-emerald-700">API</span> AUDIT REPORT
              </div>
              <div className="text-xs text-slate-400 print:text-slate-600 font-mono">
                Defensive API Vulnerability Assessment &middot; Confidential
              </div>
            </div>
          </div>

          <div className="text-right text-xs font-mono text-slate-400 print:text-slate-600">
            <div>Audit Date: 2026-09-24</div>
            <div>Target: 127.0.0.1 (Local Sandbox)</div>
            <div>Status: <span className="text-emerald-400 print:text-emerald-700 font-bold">VERIFIED</span></div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="mb-8">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-700 mb-2">
            1. Executive Summary
          </h3>
          <p className="text-xs sm:text-sm text-slate-300 print:text-slate-800 leading-relaxed">
            SentinelAPI conducted an automated defensive security assessment against <span className="font-semibold text-white print:text-black">{apiName} ({apiVersion})</span>. 
            A total of <span className="font-mono font-bold text-white print:text-black">{totalEndpoints} endpoints</span> were cataloged and tested for OWASP API Security Top 10 flaws. 
            The system identified <span className="text-red-400 print:text-red-700 font-bold">{criticalFindings.length} Critical</span>, <span className="text-orange-400 print:text-orange-700 font-bold">{highFindings.length} High</span>, and <span className="text-amber-400 print:text-amber-700 font-bold">{mediumFindings.length} Medium</span> severity vulnerabilities. 
            The computed defensive posture score is <span className="font-mono font-bold text-emerald-400 print:text-emerald-700">{score.currentScore}/100</span> (Grade {score.ratingGrade}).
          </p>
        </div>

        {/* KPI Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          <div className="rounded-xl border border-slate-800 print:border-slate-300 bg-slate-900/50 print:bg-slate-50 p-3.5 text-center">
            <div className="text-[11px] text-slate-400 print:text-slate-600">Overall Score</div>
            <div className="text-2xl font-mono font-bold text-emerald-400 print:text-emerald-700 mt-1">
              {score.currentScore} / 100
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 print:border-slate-300 bg-slate-900/50 print:bg-slate-50 p-3.5 text-center">
            <div className="text-[11px] text-slate-400 print:text-slate-600">Audited Routes</div>
            <div className="text-2xl font-mono font-bold text-white print:text-black mt-1">
              {totalEndpoints}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 print:border-slate-300 bg-slate-900/50 print:bg-slate-50 p-3.5 text-center">
            <div className="text-[11px] text-slate-400 print:text-slate-600">Critical Issues</div>
            <div className="text-2xl font-mono font-bold text-red-400 print:text-red-700 mt-1">
              {criticalFindings.length}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 print:border-slate-300 bg-slate-900/50 print:bg-slate-50 p-3.5 text-center">
            <div className="text-[11px] text-slate-400 print:text-slate-600">Auth Coverage</div>
            <div className="text-2xl font-mono font-bold text-cyan-400 print:text-cyan-700 mt-1">
              {score.authCoveragePercentage}%
            </div>
          </div>
        </div>

        {/* Detailed Findings Breakdown */}
        <div className="space-y-6">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400 print:text-emerald-700">
            2. Detailed Findings & Safe Proof-of-Concept Reproductions
          </h3>

          {findings.map((finding, idx) => (
            <div
              key={`${finding.id}-${idx}`}
              className="rounded-xl border border-slate-800 print:border-slate-300 bg-slate-950/40 print:bg-transparent p-5 space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800 print:border-slate-200">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-slate-500 font-bold">
                    #{idx + 1}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 print:text-red-700'
                        : finding.severity === 'HIGH'
                        ? 'bg-orange-500/10 text-orange-400 print:text-orange-700'
                        : 'bg-amber-500/10 text-amber-400 print:text-amber-700'
                    }`}
                  >
                    {finding.severity}
                  </span>
                  <h4 className="text-sm font-bold text-white print:text-black">
                    {finding.title}
                  </h4>
                </div>

                <div className="font-mono text-xs text-slate-400 print:text-slate-700">
                  {finding.method} {finding.endpoint}
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-slate-300 print:text-slate-800 leading-relaxed">
                {finding.description}
              </p>

              {/* Evidence */}
              <div className="rounded-lg bg-black/50 print:bg-slate-100 p-3 text-xs font-mono">
                <span className="text-slate-400 print:text-slate-600 block text-[10px] uppercase font-bold mb-1">
                  Evidence:
                </span>
                <span className="text-amber-300 print:text-amber-900">
                  {finding.evidence}
                </span>
              </div>

              {/* Safe Reproduction Request */}
              {finding.reproduction.request1 && (
                <div className="text-xs font-mono space-y-1">
                  <div className="text-[10px] text-slate-400 print:text-slate-600 uppercase font-bold">
                    Safe Reproduction Request:
                  </div>
                  <pre className="rounded-lg bg-black/60 print:bg-slate-100 p-3 text-[11px] text-emerald-400 print:text-emerald-800 overflow-x-auto border border-slate-800 print:border-slate-300">
                    {finding.reproduction.request1.raw}
                  </pre>
                </div>
              )}

              {/* Remediation */}
              <div className="pt-2 border-t border-slate-800/60 print:border-slate-200 text-xs">
                <div className="text-emerald-400 print:text-emerald-700 font-bold mb-1">
                  Recommended Remediation:
                </div>
                <div className="text-slate-300 print:text-slate-800 mb-2">
                  {finding.remediation.summary}
                </div>
                <pre className="rounded-lg bg-black/60 print:bg-slate-100 p-3 text-[11px] font-mono text-emerald-400 print:text-emerald-800 overflow-x-auto border border-slate-800 print:border-slate-300">
                  {finding.remediation.codeSnippet}
                </pre>
              </div>
            </div>
          ))}
        </div>

        {/* Footer Signoff */}
        <div className="mt-8 pt-6 border-t border-slate-800 print:border-slate-300 text-xs font-mono text-slate-400 print:text-slate-600 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <FileCheck className="h-4 w-4 text-emerald-400 print:text-emerald-700" />
            <span>Generated by SENTINELAPI Defensive Scanner &middot; Hash: 8b7f...c42a</span>
          </div>
          <div>Page 1 of 1</div>
        </div>
      </div>
    </div>
  );
};
