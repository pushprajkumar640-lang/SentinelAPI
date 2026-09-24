import React, { useState } from 'react';
import {
  X,
  Play,
  ArrowRight,
  ArrowLeft,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Terminal,
  Code2,
  Award,
  Layers,
  FileCheck,
  RefreshCw
} from 'lucide-react';
import { VulnerabilityFinding, SecurityScoreBreakdown } from '../types/security';

interface PresentationModeModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings: VulnerabilityFinding[];
  score: SecurityScoreBreakdown;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
}

export const PresentationModeModal: React.FC<PresentationModeModalProps> = ({
  isOpen,
  onClose,
  findings,
  score,
  onSelectFinding
}) => {
  const [currentStep, setCurrentStep] = useState<number>(1);
  const totalSteps = 7;

  if (!isOpen) return null;

  const idorFinding = findings.find(f => f.category === 'BOLA_IDOR') || findings[0];
  const dataExposureFinding = findings.find(f => f.category === 'EXCESSIVE_DATA_EXPOSURE') || findings[1];
  const rateLimitFinding = findings.find(f => f.category === 'WEAK_RATE_LIMITING') || findings[3];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4 sm:p-8 backdrop-blur-lg">
      <div className="relative flex flex-col w-full max-w-5xl rounded-2xl border border-cyan-500/30 bg-[#0a0d14] shadow-2xl shadow-cyan-500/10 max-h-[92vh] overflow-hidden">
        {/* Presentation Header */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Play className="h-4 w-4 fill-cyan-400" />
            </div>
            <div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                <span>SENTINELAPI JUDGE DEMO WALKTHROUGH</span>
                <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/20">
                  Step {currentStep} of {totalSteps}
                </span>
              </div>
              <div className="text-[11px] text-slate-400">
                Core Hackathon Proof-of-Concept &middot; 3-Minute Presentation Mode
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-all cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Presentation Step Indicator Tracker */}
        <div className="grid grid-cols-7 border-b border-slate-800 bg-slate-900/30 text-center text-[10px] font-mono">
          {[
            '1. API Contract',
            '2. Safe Sandbox Scan',
            '3. IDOR Detection',
            '4. Data Exposure',
            '5. Rate Limiting',
            '6. Sentinel AI Fix',
            '7. Security Score'
          ].map((title, i) => (
            <button
              key={i}
              onClick={() => setCurrentStep(i + 1)}
              className={`py-2 px-1 border-b-2 transition-all cursor-pointer truncate ${
                currentStep === i + 1
                  ? 'border-cyan-400 text-cyan-300 font-bold bg-cyan-950/20'
                  : currentStep > i + 1
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-slate-500'
              }`}
            >
              {title}
            </button>
          ))}
        </div>

        {/* Step Body */}
        <div className="flex-1 overflow-y-auto p-6 sm:p-8 space-y-6">
          {/* STEP 1: API Upload & Contract Analysis */}
          {currentStep === 1 && (
            <div className="space-y-4 max-w-3xl mx-auto text-center sm:text-left">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-xs font-mono text-cyan-400">
                <span>Phase 1: API Ingestion & Surface Discovery</span>
              </div>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Developer Uploads OpenAPI / Swagger Specification
              </h2>
              <p className="text-sm text-slate-300 leading-relaxed">
                SentinelAPI accepts any standard OpenAPI 3.0 or Swagger 2.0 contract for an authorized test environment. 
                For this live hackathon demo, we evaluate the <span className="text-emerald-400 font-semibold">FoodDelivery Sandbox API (v1.0.0)</span> running in an isolated container.
              </p>

              <div className="grid grid-cols-3 gap-3 pt-4 text-left font-mono text-xs">
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="text-slate-500 text-[10px]">TOTAL ROUTES</div>
                  <div className="text-xl font-bold text-white mt-1">24 Endpoints</div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="text-slate-500 text-[10px]">TARGET SCOPE</div>
                  <div className="text-sm font-bold text-emerald-400 mt-1 truncate">127.0.0.1:3000</div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="text-slate-500 text-[10px]">AUTHENTICATION</div>
                  <div className="text-sm font-bold text-cyan-400 mt-1">Bearer JWT</div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Automated Safe Scan in Action */}
          {currentStep === 2 && (
            <div className="space-y-4 max-w-3xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono text-emerald-400">
                <Terminal className="h-3.5 w-3.5" />
                <span>Phase 2: Automated Multi-Stage Defense Audit</span>
              </div>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Real-Time Scanner Executes Safe Bounded Probes
              </h2>
              <p className="text-sm text-slate-300">
                SentinelAPI executes non-destructive tests: analyzing parameters, checking authorization boundaries between test users, and evaluating response schemas.
              </p>

              <div className="rounded-xl border border-slate-800 bg-black/80 p-4 font-mono text-xs text-emerald-400 space-y-2 border-glow-emerald">
                <div className="text-slate-400">[✓] OpenAPI specification parsed (24 endpoints mapped)</div>
                <div className="text-emerald-400">[✓] Authentication analyzed: 82% coverage (Missing on /api/admin/users)</div>
                <div className="text-amber-400">[✓] Authorization check: User A requested Order #1002 (BOLA Flaw Confirmed)</div>
                <div className="text-orange-400">[✓] Schema analysis: Leaked passwordHash and internalNotes on /api/users/101</div>
                <div className="text-cyan-400">[✓] Rate limit audit: 12 rapid probe requests accepted without 429 throttling</div>
                <div className="text-emerald-300 font-bold pt-2 border-t border-slate-800">[✓] Vulnerability Report Completed & Score Calculated (62/100)</div>
              </div>
            </div>
          )}

          {/* STEP 3: IDOR / BOLA Discovery */}
          {currentStep === 3 && idorFinding && (
            <div className="space-y-4 max-w-3xl mx-auto">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-xs font-mono font-bold border border-red-500/30">
                  CRITICAL SEVERITY
                </span>
                <span className="text-xs font-mono text-slate-400">
                  OWASP API1:2023 - Broken Object Level Authorization
                </span>
              </div>

              <h2 className="text-2xl font-black text-white tracking-tight">
                Finding 1: Broken Object-Level Authorization (BOLA / IDOR)
              </h2>

              <p className="text-sm text-slate-300">
                The scanner confirmed that an authenticated sandbox user can access private order records belonging to other users simply by changing the ID.
              </p>

              {/* Reproduction Comparison Box */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3.5">
                  <div className="text-emerald-400 font-bold mb-1">User A accesses Order 1001 (Legitimate):</div>
                  <div className="text-slate-400 text-[11px] mb-2">GET /api/orders/1001 &rarr; 200 OK</div>
                  <pre className="bg-black/60 p-2.5 rounded text-[10px] text-emerald-300">
{`{
  "orderId": "1001",
  "ownerUserId": "user_a",
  "status": "DELIVERED"
}`}
                  </pre>
                </div>

                <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-3.5">
                  <div className="text-red-400 font-bold mb-1">User A accesses Order 1002 (BOLA Breach):</div>
                  <div className="text-red-300 text-[11px] mb-2">Expected 403 Forbidden &rarr; Observed 200 OK!</div>
                  <pre className="bg-black/60 p-2.5 rounded text-[10px] text-red-300">
{`{
  "orderId": "1002",
  "ownerUserId": "user_b",
  "deliveryAddress": "742 Evergreen Terr",
  "totalAmount": 48.50
}`}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* STEP 4: Excessive Data Exposure */}
          {currentStep === 4 && dataExposureFinding && (
            <div className="space-y-4 max-w-3xl mx-auto">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 text-xs font-mono font-bold border border-orange-500/30">
                  HIGH SEVERITY
                </span>
                <span className="text-xs font-mono text-slate-400">
                  OWASP API3:2023 - Excessive Data Exposure
                </span>
              </div>

              <h2 className="text-2xl font-black text-white tracking-tight">
                Finding 2: Excessive Data Exposure on /api/users/101
              </h2>

              <p className="text-sm text-slate-300">
                The endpoint returns the full internal database model, including password hashes, SSN fragments, and internal risk notes, assuming the client frontend will hide them.
              </p>

              <div className="rounded-xl border border-orange-500/30 bg-slate-950 p-4 font-mono text-xs">
                <div className="text-orange-400 font-bold mb-2">Leaked Sensitive Payload (Inspected by Scanner):</div>
                <pre className="bg-black/60 p-3 rounded text-[11px] text-orange-300 overflow-x-auto">
{`{
  "id": 101,
  "name": "Rahul Sharma",
  "email": "rahul@demo.internal",
  "passwordHash": "$2b$12$e8x4k2LPp8qH4vj4zL50ke7XjKl8q71N00a4P7h4H9K",  // LEAKED BCRYPT HASH!
  "internalNotes": "VIP client; risk score tier 0",                     // CONFIDENTIAL NOTE!
  "ssnLast4": "8842",                                                  // PII LEAK!
  "stripeCustomerId": "cus_N924ka82"
}`}
                </pre>
              </div>
            </div>
          )}

          {/* STEP 5: Weak Rate Limiting */}
          {currentStep === 5 && rateLimitFinding && (
            <div className="space-y-4 max-w-3xl mx-auto">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 text-xs font-mono font-bold border border-amber-500/30">
                  MEDIUM SEVERITY
                </span>
                <span className="text-xs font-mono text-slate-400">
                  OWASP API4:2023 - Unrestricted Resource Consumption
                </span>
              </div>

              <h2 className="text-2xl font-black text-white tracking-tight">
                Finding 3: Weak or Missing Rate Limiting on Search API
              </h2>

              <p className="text-sm text-slate-300">
                SentinelAPI dispatched 12 rapid sequential test requests within 500ms to <span className="font-mono text-white">/api/products</span>. 
                All 12 succeeded with HTTP 200, with no 429 response or RateLimit headers returned.
              </p>

              <div className="rounded-xl border border-amber-500/30 bg-slate-950 p-4 font-mono text-xs text-slate-300">
                <div className="text-amber-400 font-bold mb-2">Controlled Probe Evidence:</div>
                <div className="space-y-1 text-[11px]">
                  <div>[Probe 01/12] GET /api/products &rarr; 200 OK (X-RateLimit: None)</div>
                  <div>[Probe 06/12] GET /api/products &rarr; 200 OK (X-RateLimit: None)</div>
                  <div>[Probe 12/12] GET /api/products &rarr; 200 OK (Expected 429 &middot; Missing Throttling)</div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 6: Sentinel AI Code Fix */}
          {currentStep === 6 && idorFinding && (
            <div className="space-y-4 max-w-3xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-xs font-mono text-purple-400">
                <Sparkles className="h-3.5 w-3.5" />
                <span>Phase 6: Sentinel AI Automated Remediation (Gemini 3.8 Flash)</span>
              </div>

              <h2 className="text-2xl font-black text-white tracking-tight">
                Sentinel AI Generates Production-Grade Code Patch
              </h2>

              <p className="text-sm text-slate-300">
                Developers can immediately copy production-ready authorization middleware to eliminate the BOLA flaw before deploying to production.
              </p>

              <div className="rounded-xl border border-purple-500/30 bg-[#080a0f] p-4 font-mono text-xs">
                <div className="text-purple-300 font-bold mb-2">Generated TypeScript / Express Fix:</div>
                <pre className="bg-black/60 p-3 rounded text-[11px] text-emerald-400 overflow-x-auto">
{idorFinding.remediation.codeSnippet}
                </pre>
              </div>
            </div>
          )}

          {/* STEP 7: Security Score & Executive Report */}
          {currentStep === 7 && (
            <div className="space-y-4 max-w-3xl mx-auto text-center sm:text-left">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono text-emerald-400">
                <Award className="h-3.5 w-3.5" />
                <span>Phase 7: Transparent Security Score & Executive Audit</span>
              </div>

              <h2 className="text-2xl font-black text-white tracking-tight">
                Comprehensive Defensive Score: {score.currentScore} / 100
              </h2>

              <p className="text-sm text-slate-300">
                The score dynamically reflects identified vulnerabilities: 100 baseline minus 25 for Critical BOLA, minus 10 for High flaws, minus 3 for Medium flaws.
              </p>

              <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/10 p-5 font-mono text-xs flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="text-left space-y-1">
                  <div className="text-emerald-400 font-bold text-sm">Audit Complete & Verifiable</div>
                  <div className="text-slate-400 text-[11px]">
                    Ready for executive PDF export, CI/CD pipeline integration, or developer remediation.
                  </div>
                </div>

                <button
                  onClick={onClose}
                  className="rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-6 py-2.5 text-xs font-bold text-slate-950 hover:from-emerald-400 transition-all cursor-pointer shrink-0 shadow-md"
                >
                  Return to Dashboard
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Presentation Footer Controls */}
        <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950 px-6 py-4">
          <button
            onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
            disabled={currentStep === 1}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 px-3.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-900 disabled:opacity-40 transition-all cursor-pointer"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Previous</span>
          </button>

          <div className="flex items-center gap-1">
            {Array.from({ length: totalSteps }).map((_, i) => (
              <span
                key={i}
                className={`h-1.5 rounded-full transition-all ${
                  currentStep === i + 1 ? 'w-6 bg-cyan-400' : 'w-1.5 bg-slate-700'
                }`}
              />
            ))}
          </div>

          <button
            onClick={() => {
              if (currentStep < totalSteps) {
                setCurrentStep((prev) => prev + 1);
              } else {
                onClose();
              }
            }}
            className="flex items-center gap-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 px-4 py-1.5 text-xs font-bold text-slate-950 transition-all cursor-pointer shadow-md shadow-cyan-500/10"
          >
            <span>{currentStep === totalSteps ? 'Finish Demo' : 'Next Step'}</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
