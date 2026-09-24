import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Sparkles,
  ExternalLink,
  Code2,
  FileText
} from 'lucide-react';
import { VulnerabilityFinding, Severity } from '../types/security';

interface VulnerabilitiesViewProps {
  findings: VulnerabilityFinding[];
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onToggleResolve: (findingId: string) => void;
  onOpenAiAssistant: (finding: VulnerabilityFinding) => void;
  onNavigateTab: (tab: 'reports') => void;
}

export const VulnerabilitiesView: React.FC<VulnerabilitiesViewProps> = ({
  findings,
  onSelectFinding,
  onToggleResolve,
  onOpenAiAssistant,
  onNavigateTab
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredFindings = findings.filter((f) => {
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || f.status === statusFilter;
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesStatus && matchesSearch;
  });

  const getSeverityBadgeClass = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30 font-bold';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30 font-bold';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Vulnerability Findings
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Defensive security findings discovered across the authorized sandbox API
          </p>
        </div>

        <button
          onClick={() => onNavigateTab('reports')}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-all cursor-pointer self-start sm:self-auto"
        >
          <FileText className="h-3.5 w-3.5" />
          <span>Export Security Report</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0c1017] p-3.5">
        <div className="flex flex-wrap items-center gap-2 flex-1">
          {/* Search Input */}
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by vulnerability or route..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="rounded-lg border border-slate-800 bg-slate-950 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500/50 focus:outline-none w-52 sm:w-64"
            />
          </div>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-300 focus:border-emerald-500/50 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical (BOLA / IDOR)</option>
            <option value="HIGH">High (Data Exposure / Auth)</option>
            <option value="MEDIUM">Medium (Rate Limiting)</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Dropdown */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-300 focus:border-emerald-500/50 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open Flaws</option>
            <option value="RESOLVED">Resolved Flaws</option>
          </select>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-emerald-400 font-bold">{filteredFindings.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Findings Cards List */}
      <div className="space-y-4">
        {filteredFindings.map((finding, idx) => {
          const isResolved = finding.status === 'RESOLVED';

          return (
            <div
              key={`${finding.id}-${idx}`}
              className={`rounded-xl border transition-all p-5 shadow-sm ${
                isResolved
                  ? 'border-slate-800 bg-slate-950/40 opacity-70'
                  : finding.severity === 'CRITICAL'
                  ? 'border-red-500/30 bg-[#0c1017] hover:border-red-500/50'
                  : finding.severity === 'HIGH'
                  ? 'border-orange-500/30 bg-[#0c1017] hover:border-orange-500/50'
                  : 'border-slate-800 bg-[#0c1017] hover:border-slate-700'
              }`}
            >
              {/* Card Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
                <div className="flex items-center gap-2.5 flex-wrap">
                  {/* Severity Badge */}
                  <span
                    className={`px-2.5 py-0.5 rounded text-[11px] font-mono border ${getSeverityBadgeClass(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>

                  {/* Title */}
                  <h3 className="text-sm sm:text-base font-bold text-slate-100">
                    {finding.title}
                  </h3>

                  {/* Resolved Badge */}
                  {isResolved && (
                    <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-mono text-emerald-400 border border-emerald-500/20">
                      <CheckCircle2 className="h-3 w-3" />
                      <span>RESOLVED</span>
                    </span>
                  )}
                </div>

                {/* Endpoint & Method */}
                <div className="flex items-center gap-2 font-mono text-xs text-slate-300 self-start sm:self-auto">
                  <span className={`px-1.5 py-0.5 rounded font-bold text-[10px] ${
                    finding.method === 'GET' ? 'bg-blue-950 text-blue-400 border border-blue-800/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                  }`}>
                    {finding.method}
                  </span>
                  <span className="text-slate-300 font-semibold">{finding.endpoint}</span>
                </div>
              </div>

              {/* Card Body */}
              <div className="mt-3.5 space-y-3 text-xs">
                {/* Description */}
                <p className="text-slate-300 leading-relaxed">
                  {finding.description}
                </p>

                {/* Evidence Callout */}
                <div className="rounded-lg bg-slate-950 border border-slate-800/80 p-3 font-mono">
                  <span className="text-slate-400 uppercase text-[10px] block mb-1">
                    Verified Evidence:
                  </span>
                  <span className="text-amber-300/90 text-[11px]">
                    {finding.evidence}
                  </span>
                </div>

                {/* Recommendation Summary */}
                <div className="flex items-start gap-2 text-slate-400 text-[11px]">
                  <span className="text-emerald-400 font-semibold shrink-0">Remediation:</span>
                  <span>{finding.remediation.summary}</span>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                <div className="text-[11px] font-mono text-slate-400">
                  {finding.owaspCategory} &middot; Detected {finding.detectedAt}
                </div>

                <div className="flex items-center gap-2">
                  {/* Ask Sentinel AI */}
                  <button
                    onClick={() => onOpenAiAssistant(finding)}
                    className="flex items-center gap-1.5 rounded-lg border border-purple-500/30 bg-purple-500/10 px-3 py-1.5 text-xs font-medium text-purple-300 hover:bg-purple-500/20 transition-all cursor-pointer"
                  >
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    <span>Ask Sentinel AI</span>
                  </button>

                  {/* Toggle Resolved */}
                  <button
                    onClick={() => onToggleResolve(finding.id)}
                    className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all cursor-pointer border ${
                      isResolved
                        ? 'border-amber-500/30 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'
                        : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20'
                    }`}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    <span>{isResolved ? 'Re-open Flaw' : 'Mark Resolved'}</span>
                  </button>

                  {/* View Details / Safe PoC Modal */}
                  <button
                    onClick={() => onSelectFinding(finding)}
                    className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-teal-500 px-3.5 py-1.5 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-sm"
                  >
                    <span>View PoC & Code Fix</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
