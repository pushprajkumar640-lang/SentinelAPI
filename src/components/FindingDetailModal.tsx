import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import {
  X,
  ShieldAlert,
  Copy,
  Check,
  Sparkles,
  Terminal,
  Code2,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { VulnerabilityFinding } from '../types/security';

interface FindingDetailModalProps {
  finding: VulnerabilityFinding | null;
  onClose: () => void;
  onToggleResolve: (findingId: string) => void;
  onOpenAiAssistant?: (finding: VulnerabilityFinding) => void;
  scanContext?: Record<string, unknown>;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onToggleResolve,
  onOpenAiAssistant
  , scanContext
}) => {
  const [activeTab, setActiveTab] = useState<'poc' | 'remediation' | 'ai'>('poc');
  const [copiedCode, setCopiedCode] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResponse, setAiResponse] = useState<string | null>(null);

  if (!finding) return null;

  const copyRemediation = () => {
    navigator.clipboard.writeText(finding.remediation.codeSnippet);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const askAi = async (promptQuery: string) => {
    setAiLoading(true);
    setActiveTab('ai');
    try {
      const res = await apiFetch('/api/gemini/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: promptQuery,
          findingTitle: finding.title,
          severity: finding.severity,
          endpoint: `${finding.method} ${finding.endpoint}`,
          evidence: finding.evidence,
          codeSnippet: finding.remediation.codeSnippet
          , ...scanContext
        })
      });
      const data = await res.json();
      setAiResponse(data.answer || 'No response received from Sentinel AI.');
    } catch {
      setAiResponse(finding.aiExplanation || 'Sentinel AI is currently in offline defensive mode.');
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-3 sm:p-6 backdrop-blur-md">
      <div className="relative flex flex-col w-full max-w-4xl rounded-2xl border border-slate-800 bg-[#0c1017] shadow-2xl max-h-[92vh] overflow-hidden">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/60 px-6 py-4">
          <div className="flex items-center gap-3">
            <span
              className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${
                finding.severity === 'CRITICAL'
                  ? 'bg-red-500/10 text-red-400 border-red-500/30'
                  : finding.severity === 'HIGH'
                  ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}
            >
              {finding.severity}
            </span>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-white">
                {finding.title}
              </h2>
              <div className="text-xs font-mono text-slate-400">
                {finding.owaspCategory} &middot; <span className="text-emerald-400">{finding.method}</span> {finding.endpoint}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onToggleResolve(finding.id)}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 transition-all cursor-pointer font-medium"
            >
              {finding.status === 'RESOLVED' ? 'Re-open' : 'Mark Resolved'}
            </button>
            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-all cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-4 px-6 border-b border-slate-800 bg-slate-950/40 text-xs">
          <button
            onClick={() => setActiveTab('poc')}
            className={`py-3 border-b-2 font-medium transition-all cursor-pointer ${
              activeTab === 'poc'
                ? 'border-emerald-400 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Safe Proof-of-Concept & Evidence
          </button>

          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-3 border-b-2 font-medium transition-all cursor-pointer ${
              activeTab === 'remediation'
                ? 'border-emerald-400 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Remediation & Code Fix
          </button>

          <button
            onClick={() => {
              setActiveTab('ai');
              if (!aiResponse) {
                askAi('Explain what this vulnerability means, why it is dangerous, and how to fix it.');
              }
            }}
            className={`flex items-center gap-1.5 py-3 border-b-2 font-medium transition-all cursor-pointer ${
              activeTab === 'ai'
                ? 'border-purple-400 text-purple-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="h-3.5 w-3.5 text-purple-400" />
            <span>Sentinel AI Assistant</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Overview Callout */}
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-2">
            <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
              Vulnerability Summary
            </h4>
            <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
              {finding.description}
            </p>
            <div className="pt-2 text-xs text-red-400/90 font-mono">
              <span className="font-bold">Real-World Impact:</span> {finding.impact}
            </div>
          </div>

          {/* TAB 1: Safe PoC & Evidence */}
          {activeTab === 'poc' && (
            <div className="space-y-6">
              {/* Evidence Banner */}
              <div className="rounded-xl border border-red-500/20 bg-red-950/20 p-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-red-400 mb-1">
                  <ShieldAlert className="h-4 w-4" />
                  <span>Verified Defensive Evidence</span>
                </div>
                <p className="text-xs font-mono text-red-200/90 leading-relaxed">
                  {finding.evidence}
                </p>
              </div>

              {/* Side-by-Side Safe Reproduction Requests */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
                    Safe Reproduction Requests (Isolated Testbed)
                  </h3>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Target: 127.0.0.1:3000
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Request 1 */}
                  {finding.reproduction.request1 && (
                    <div className="rounded-xl border border-slate-800 bg-[#080a0f] p-4 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                          <span className="font-semibold text-slate-300">
                            {finding.reproduction.request1.description}
                          </span>
                          <span className="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                            Status: {finding.reproduction.request1.actualStatus} OK
                          </span>
                        </div>
                        <pre className="rounded-lg bg-black/60 p-3 text-[11px] font-mono text-emerald-400 overflow-x-auto border border-slate-800 mb-3">
                          {finding.reproduction.request1.raw}
                        </pre>
                      </div>

                      {finding.reproduction.request1.sampleResponse && (
                        <div>
                          <div className="text-[10px] font-mono text-slate-500 mb-1">
                            Response Payload:
                          </div>
                          <pre className="rounded-lg bg-black/60 p-3 text-[10px] font-mono text-slate-300 overflow-x-auto border border-slate-800 max-h-40">
                            {finding.reproduction.request1.sampleResponse}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Request 2 (Exploit step in sandbox) */}
                  {finding.reproduction.request2 && (
                    <div className="rounded-xl border border-red-500/30 bg-[#080a0f] p-4 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between text-xs font-mono mb-2">
                          <span className="font-semibold text-red-300">
                            {finding.reproduction.request2.description}
                          </span>
                          <span className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                            Observed: {finding.reproduction.request2.actualStatus} (Expected {finding.reproduction.request2.expectedStatus})
                          </span>
                        </div>
                        <pre className="rounded-lg bg-black/60 p-3 text-[11px] font-mono text-red-400 overflow-x-auto border border-red-500/20 mb-3">
                          {finding.reproduction.request2.raw}
                        </pre>
                      </div>

                      {finding.reproduction.request2.sampleResponse && (
                        <div>
                          <div className="text-[10px] font-mono text-red-400/80 mb-1">
                            Leaked Tenant Data (User B Record):
                          </div>
                          <pre className="rounded-lg bg-black/60 p-3 text-[10px] font-mono text-red-300/90 overflow-x-auto border border-red-500/20 max-h-40">
                            {finding.reproduction.request2.sampleResponse}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Remediation Code Fix */}
          {activeTab === 'remediation' && (
            <div className="space-y-6">
              {/* Guidance Summary */}
              <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-4">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-1">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Recommended Fix</span>
                </div>
                <p className="text-xs text-slate-200">
                  {finding.remediation.summary}
                </p>
              </div>

              {/* Code Snippet */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-300">
                    <Code2 className="h-4 w-4 text-emerald-400" />
                    <span>Production Hardened Controller Patch ({finding.remediation.language})</span>
                  </div>
                  <button
                    onClick={copyRemediation}
                    className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-all cursor-pointer"
                  >
                    {copiedCode ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>
                </div>

                <pre className="rounded-xl border border-slate-800 bg-[#080a0f] p-4 text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed shadow-inner">
                  {finding.remediation.codeSnippet}
                </pre>
              </div>

              {/* Best Practices Checklist */}
              <div>
                <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Security Engineering Best Practices
                </h4>
                <div className="space-y-2">
                  {finding.remediation.bestPractices.map((bp, i) => (
                    <div key={i} className="flex items-start gap-2.5 text-xs text-slate-300 rounded-lg border border-slate-800 bg-slate-950 p-3">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{bp}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Sentinel AI Assistant */}
          {activeTab === 'ai' && (
            <div className="space-y-4">
              {/* Quick Prompts */}
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => askAi(`What does this ${finding.title} vulnerability mean in simple terms?`)}
                  className="rounded-lg border border-purple-500/30 bg-purple-950/30 px-3 py-1.5 text-xs text-purple-300 hover:bg-purple-900/40 transition-all cursor-pointer"
                >
                  Explain in Simple Terms
                </button>
                <button
                  onClick={() => askAi(`Generate complete TypeScript/Express middleware to fix ${finding.title} on ${finding.endpoint}.`)}
                  className="rounded-lg border border-purple-500/30 bg-purple-950/30 px-3 py-1.5 text-xs text-purple-300 hover:bg-purple-900/40 transition-all cursor-pointer"
                >
                  Generate Developer Fix Guidance
                </button>
                <button
                  onClick={() => askAi(`Summarize executive risk and compliance breach impact for ${finding.title}.`)}
                  className="rounded-lg border border-purple-500/30 bg-purple-950/30 px-3 py-1.5 text-xs text-purple-300 hover:bg-purple-900/40 transition-all cursor-pointer"
                >
                  Executive Risk Summary
                </button>
              </div>

              {/* AI Response Box */}
              <div className="rounded-xl border border-purple-500/30 bg-[#080a0f] p-5">
                <div className="flex items-center justify-between pb-3 border-b border-purple-500/20 mb-3">
                  <div className="flex items-center gap-2 text-xs font-semibold text-purple-300">
                    <Sparkles className="h-4 w-4 text-purple-400" />
                    <span>Sentinel AI Defensive Engine (Powered by Gemini 3.8 Flash)</span>
                  </div>
                  {aiLoading && (
                    <div className="flex items-center gap-1.5 text-xs font-mono text-purple-400">
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                      <span>Synthesizing...</span>
                    </div>
                  )}
                </div>

                {aiLoading ? (
                  <div className="py-8 text-center space-y-2">
                    <div className="h-6 w-6 animate-spin rounded-full border-2 border-purple-400 border-t-transparent mx-auto"></div>
                    <p className="text-xs text-slate-400 font-mono">
                      Querying Sentinel AI security model...
                    </p>
                  </div>
                ) : (
                  <div className="text-xs leading-relaxed text-slate-200 whitespace-pre-wrap font-sans">
                    {aiResponse || finding.aiExplanation}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
