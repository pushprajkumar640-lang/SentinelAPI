import React from 'react';
import { History, ShieldAlert, Award, Layers, Calendar, Play } from 'lucide-react';

export interface ScanRecordItem {
  id: string | number;
  scanId: string;
  projectId: string | number;
  status: string;
  securityScore: number;
  ratingGrade: string;
  totalEndpoints: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  durationSeconds: number;
  startedAt: string;
  completedAt?: string | null;
}

interface ScanHistoryViewProps {
  scans: ScanRecordItem[];
  projectName?: string;
  onNavigateScan?: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  scans,
  projectName = 'Current Project',
  onNavigateScan
}) => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Audit Scan History
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Historical log of defensive security assessments stored in PostgreSQL for {projectName}
          </p>
        </div>

        {onNavigateScan && (
          <button
            onClick={onNavigateScan}
            className="flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-4 py-2 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
          >
            <Play className="h-3.5 w-3.5 fill-slate-950" />
            <span>Launch New Scan</span>
          </button>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-[#0c1017] overflow-hidden shadow-sm">
        {scans.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <div className="h-10 w-10 mx-auto rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-500">
              <History className="h-5 w-5" />
            </div>
            <p className="text-xs font-mono text-slate-400">
              No scans recorded yet for this project.
            </p>
            <p className="text-[11px] text-slate-500">
              Execute a defensive scan from the "Scan API" tab to generate your first audit record.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <tr>
                  <th className="py-3 pl-4">Scan ID</th>
                  <th className="py-3">Timestamp (UTC)</th>
                  <th className="py-3">Endpoints</th>
                  <th className="py-3">Vulnerabilities</th>
                  <th className="py-3">Security Score</th>
                  <th className="py-3">Duration</th>
                  <th className="py-3 pr-4 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {scans.map((item) => {
                  const totalIssues =
                    (item.criticalCount || 0) +
                    (item.highCount || 0) +
                    (item.mediumCount || 0) +
                    (item.lowCount || 0);

                  return (
                    <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                      {/* Scan ID */}
                      <td className="py-3.5 pl-4 font-mono font-bold text-emerald-400">
                        {item.scanId}
                      </td>

                      {/* Date */}
                      <td className="py-3.5 text-slate-400 font-mono text-[11px]">
                        {new Date(item.startedAt).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>

                      {/* Endpoints */}
                      <td className="py-3.5 font-mono text-slate-300">
                        {item.totalEndpoints} endpoints
                      </td>

                      {/* Vulnerabilities Breakdown */}
                      <td className="py-3.5 font-mono text-[11px]">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {item.criticalCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold">
                              {item.criticalCount} Crit
                            </span>
                          )}
                          {item.highCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
                              {item.highCount} High
                            </span>
                          )}
                          {item.mediumCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                              {item.mediumCount} Med
                            </span>
                          )}
                          {item.lowCount > 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                              {item.lowCount} Low
                            </span>
                          )}
                          {totalIssues === 0 && (
                            <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              0 issues
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Security Score */}
                      <td className="py-3.5 font-mono">
                        <span
                          className={`font-bold ${
                            item.securityScore >= 80
                              ? 'text-emerald-400'
                              : item.securityScore >= 60
                              ? 'text-amber-400'
                              : 'text-red-400'
                          }`}
                        >
                          {item.securityScore}/100 (Grade {item.ratingGrade})
                        </span>
                      </td>

                      {/* Duration */}
                      <td className="py-3.5 text-slate-400 font-mono text-[11px]">
                        {item.durationSeconds || 1}s
                      </td>

                      {/* Status */}
                      <td className="py-3.5 pr-4 text-right">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium border ${
                            item.status === 'COMPLETED'
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                              : item.status === 'RUNNING'
                              ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400'
                              : 'border-slate-700 bg-slate-800 text-slate-400'
                          }`}
                        >
                          {item.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
