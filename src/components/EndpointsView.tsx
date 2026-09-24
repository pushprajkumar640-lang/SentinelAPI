import React, { useState } from 'react';
import {
  Layers,
  Search,
  Key,
  ShieldAlert,
  ChevronRight,
  X,
  Code2,
  Lock,
  Unlock,
  CheckCircle2
} from 'lucide-react';
import { ApiEndpoint, VulnerabilityFinding } from '../types/security';

interface EndpointsViewProps {
  endpoints: ApiEndpoint[];
  findings: VulnerabilityFinding[];
  onSelectFinding: (finding: VulnerabilityFinding) => void;
}

export const EndpointsView: React.FC<EndpointsViewProps> = ({
  endpoints,
  findings,
  onSelectFinding
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint | null>(null);

  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesSearch =
      ep.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ep.summary.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesMethod = methodFilter === 'ALL' || ep.method === methodFilter;
    const matchesRisk = riskFilter === 'ALL' || ep.riskLevel === riskFilter;
    return matchesSearch && matchesMethod && matchesRisk;
  });

  const getMethodBadgeClass = (method: string) => {
    switch (method) {
      case 'GET':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'POST':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'PUT':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'DELETE':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getRiskBadgeClass = (risk: string) => {
    switch (risk) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/30 font-bold';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30 font-bold';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  // Find findings associated with the inspected endpoint
  const endpointFindings = selectedEndpoint
    ? findings.filter((f) => f.endpoint === selectedEndpoint.path)
    : [];

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            API Endpoint Inventory
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Complete route surface extracted from OpenAPI specification (24 endpoints)
          </p>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search route or path..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="rounded-lg border border-slate-800 bg-[#0c1017] pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500/50 focus:outline-none w-48 sm:w-56"
            />
          </div>

          {/* Method Filter */}
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#0c1017] px-2.5 py-1.5 text-xs text-slate-300 focus:border-emerald-500/50 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>

          {/* Risk Filter */}
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#0c1017] px-2.5 py-1.5 text-xs text-slate-300 focus:border-emerald-500/50 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0c1017] overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-900/40 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 pl-4">Method</th>
                <th className="py-3">Endpoint</th>
                <th className="py-3">Description</th>
                <th className="py-3">Authentication</th>
                <th className="py-3">Risk</th>
                <th className="py-3">Findings</th>
                <th className="py-3 pr-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredEndpoints.map((ep) => (
                <tr
                  key={ep.id}
                  onClick={() => setSelectedEndpoint(ep)}
                  className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                >
                  {/* Method */}
                  <td className="py-3 pl-4">
                    <span
                      className={`inline-block px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${getMethodBadgeClass(
                        ep.method
                      )}`}
                    >
                      {ep.method}
                    </span>
                  </td>

                  {/* Path */}
                  <td className="py-3 font-mono font-medium text-slate-200 group-hover:text-emerald-400 transition-colors">
                    {ep.path}
                  </td>

                  {/* Summary */}
                  <td className="py-3 text-slate-400 max-w-xs truncate">
                    {ep.summary}
                  </td>

                  {/* Auth */}
                  <td className="py-3">
                    <div className="flex items-center gap-1.5 font-mono text-[11px]">
                      {ep.requiresAuth ? (
                        <>
                          <Lock className="h-3 w-3 text-emerald-400" />
                          <span className="text-slate-300">{ep.authType || 'Bearer JWT'}</span>
                        </>
                      ) : (
                        <>
                          <Unlock className="h-3 w-3 text-slate-500" />
                          <span className="text-slate-500">None / Public</span>
                        </>
                      )}
                    </div>
                  </td>

                  {/* Risk */}
                  <td className="py-3">
                    <span
                      className={`inline-flex px-2 py-0.5 rounded font-mono text-[10px] border ${getRiskBadgeClass(
                        ep.riskLevel
                      )}`}
                    >
                      {ep.riskLevel}
                    </span>
                  </td>

                  {/* Findings Count */}
                  <td className="py-3 font-mono">
                    {ep.findingsCount > 0 ? (
                      <span className="inline-flex items-center gap-1 text-red-400 font-bold">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>{ep.findingsCount}</span>
                      </span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                  </td>

                  {/* Inspect Arrow */}
                  <td className="py-3 pr-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedEndpoint(ep);
                      }}
                      className="inline-flex items-center gap-1 text-slate-400 hover:text-emerald-400 text-xs font-medium cursor-pointer"
                    >
                      <span>Details</span>
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Endpoint Detail Inspector Drawer/Modal */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl rounded-2xl border border-slate-800 bg-[#0c1017] p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
            {/* Close Button */}
            <button
              onClick={() => setSelectedEndpoint(null)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>

            {/* Title & Method */}
            <div className="flex items-center gap-2 mb-2">
              <span
                className={`px-2 py-0.5 rounded font-mono font-bold text-xs border ${getMethodBadgeClass(
                  selectedEndpoint.method
                )}`}
              >
                {selectedEndpoint.method}
              </span>
              <h3 className="text-base font-bold font-mono text-white">
                {selectedEndpoint.path}
              </h3>
            </div>

            <p className="text-xs text-slate-400 mb-5">
              {selectedEndpoint.summary}
            </p>

            {/* Quick Metadata Pill Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5 text-xs font-mono">
              <div className="rounded-lg bg-slate-900/60 p-2.5 border border-slate-800">
                <div className="text-[10px] text-slate-500">AUTH REQUIRED</div>
                <div className="text-slate-200 font-semibold mt-0.5">
                  {selectedEndpoint.requiresAuth ? 'Yes (Bearer JWT)' : 'No (Public)'}
                </div>
              </div>
              <div className="rounded-lg bg-slate-900/60 p-2.5 border border-slate-800">
                <div className="text-[10px] text-slate-500">RISK RATING</div>
                <div className={`font-semibold mt-0.5 ${
                  selectedEndpoint.riskLevel === 'CRITICAL' ? 'text-red-400' :
                  selectedEndpoint.riskLevel === 'HIGH' ? 'text-orange-400' : 'text-slate-200'
                }`}>
                  {selectedEndpoint.riskLevel}
                </div>
              </div>
              <div className="rounded-lg bg-slate-900/60 p-2.5 border border-slate-800">
                <div className="text-[10px] text-slate-500">AUDIT STATUS</div>
                <div className="text-emerald-400 font-semibold mt-0.5 flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>{selectedEndpoint.status}</span>
                </div>
              </div>
              <div className="rounded-lg bg-slate-900/60 p-2.5 border border-slate-800">
                <div className="text-[10px] text-slate-500">FINDINGS DETECTED</div>
                <div className="text-slate-200 font-semibold mt-0.5">
                  {endpointFindings.length}
                </div>
              </div>
            </div>

            {/* Path / Query Parameters */}
            <div className="mb-5">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono mb-2">
                Parameters
              </h4>
              {selectedEndpoint.parameters.length > 0 ? (
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2">
                  {selectedEndpoint.parameters.map((p, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs font-mono">
                      <div>
                        <span className="text-emerald-400 font-bold">{p.name}</span>
                        <span className="text-slate-500 ml-2">({p.in})</span>
                      </div>
                      <span className="text-slate-400">{p.type} &middot; required</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-slate-500 italic">No parameters declared.</div>
              )}
            </div>

            {/* Response Schema Preview if available */}
            {selectedEndpoint.responseSchema && (
              <div className="mb-5">
                <div className="flex items-center gap-2 mb-2 text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                  <Code2 className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Response Schema Model</span>
                </div>
                <pre className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs font-mono text-cyan-300 overflow-x-auto">
                  {selectedEndpoint.responseSchema}
                </pre>
              </div>
            )}

            {/* Associated Vulnerability Findings */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono mb-2">
                Active Security Findings on this Route
              </h4>
              {endpointFindings.length > 0 ? (
                <div className="space-y-2">
                  {endpointFindings.map((f, fIdx) => (
                    <div
                      key={`${f.id}-${fIdx}`}
                      onClick={() => {
                        setSelectedEndpoint(null);
                        onSelectFinding(f);
                      }}
                      className="flex items-center justify-between rounded-lg border border-red-500/30 bg-red-950/20 p-3 hover:bg-red-950/30 transition-all cursor-pointer"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                            {f.severity}
                          </span>
                          <span className="text-xs font-semibold text-slate-100">
                            {f.title}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">
                          {f.description}
                        </p>
                      </div>
                      <button className="text-xs font-mono text-red-400 flex items-center gap-1 shrink-0 ml-3">
                        <span>View PoC</span>
                        <ChevronRight className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-400 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  <span>No active vulnerabilities discovered on this endpoint.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
