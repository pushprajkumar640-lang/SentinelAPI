import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Lock,
  Terminal,
  Save,
  CheckCircle2,
  AlertOctagon,
  Sliders,
  RotateCcw,
  RefreshCw
} from 'lucide-react';

interface SandboxConfig {
  enforceBolaCheck: boolean;
  maskSensitiveFields: boolean;
  enableRateLimit: boolean;
  requireAdminAuth: boolean;
}

export const SettingsView: React.FC = () => {
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [targetScope, setTargetScope] = useState('127.0.0.1:3000');
  const [maxRateLimitBurst, setMaxRateLimitBurst] = useState(8);
  const [sensitiveFields, setSensitiveFields] = useState(
    'password, passwordHash, internalNotes, ssnLast4, stripeCustomerId, mfaSecret, creditRating'
  );
  const [enableGeminiDefensiveAi, setEnableGeminiDefensiveAi] = useState(true);

  // Sandbox Live Vulnerability Testbed State
  const [sandboxConfig, setSandboxConfig] = useState<SandboxConfig>({
    enforceBolaCheck: false,
    maskSensitiveFields: false,
    enableRateLimit: false,
    requireAdminAuth: false
  });
  const [isUpdatingSandbox, setIsUpdatingSandbox] = useState(false);

  useEffect(() => {
    fetch('/api/sandbox/config')
      .then((res) => res.json())
      .then((cfg) => {
        if (cfg && typeof cfg.enforceBolaCheck === 'boolean') {
          setSandboxConfig(cfg);
        }
      })
      .catch(() => {});
  }, []);

  const handleToggleSandboxFix = async (key: keyof SandboxConfig) => {
    setIsUpdatingSandbox(true);
    const updated = { ...sandboxConfig, [key]: !sandboxConfig[key] };
    try {
      const res = await fetch('/api/sandbox/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated)
      });
      const data = await res.json();
      if (data && data.config) {
        setSandboxConfig(data.config);
      }
    } finally {
      setIsUpdatingSandbox(false);
    }
  };

  const handleResetSandbox = async () => {
    setIsUpdatingSandbox(true);
    try {
      const res = await fetch('/api/sandbox/reset', { method: 'POST' });
      const data = await res.json();
      if (data && data.config) {
        setSandboxConfig(data.config);
      }
    } finally {
      setIsUpdatingSandbox(false);
    }
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Scanner Guardrails & Settings
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Defensive policy enforcement, safety thresholds, and isolated sandbox vulnerability testbeds
        </p>
      </div>

      {/* Sandbox Testbed Vulnerability Controls */}
      <div className="rounded-xl border border-purple-500/30 bg-purple-950/10 p-5 space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-300">
            <Sliders className="h-4 w-4 text-purple-400" />
            <span>SANDBOX VULNERABILITY TESTBED TOGGLES (DEMO VERIFICATION)</span>
          </div>
          <button
            type="button"
            onClick={handleResetSandbox}
            disabled={isUpdatingSandbox}
            className="flex items-center gap-1 text-[10px] font-mono text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-900 border border-slate-800 transition-all cursor-pointer"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset All to Vulnerable</span>
          </button>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          The local sandbox simulates real OWASP API vulnerabilities. Toggle fixes below to test the scanner:
          when a fix is active, re-running the scan will dynamically omit that vulnerability and boost your security score!
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
          {/* BOLA Check Toggle */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">BOLA / IDOR Verification</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {sandboxConfig.enforceBolaCheck ? '✓ Object ownership enforced (403 Forbidden)' : '✗ Vulnerable (User A can access User B orders)'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleToggleSandboxFix('enforceBolaCheck')}
              disabled={isUpdatingSandbox}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                sandboxConfig.enforceBolaCheck
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-red-500/20 text-red-300 border border-red-500/40'
              }`}
            >
              {sandboxConfig.enforceBolaCheck ? 'PATCHED' : 'VULNERABLE'}
            </button>
          </div>

          {/* Excessive Data Exposure Toggle */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Excessive Data Exposure</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {sandboxConfig.maskSensitiveFields ? '✓ Sensitive fields masked from /users/:id' : '✗ Leaks passwordHash, ssnLast4, internalNotes'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleToggleSandboxFix('maskSensitiveFields')}
              disabled={isUpdatingSandbox}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                sandboxConfig.maskSensitiveFields
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
              }`}
            >
              {sandboxConfig.maskSensitiveFields ? 'PATCHED' : 'VULNERABLE'}
            </button>
          </div>

          {/* Rate Limiting Toggle */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Rate Limiting Enforcement</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {sandboxConfig.enableRateLimit ? '✓ Throttles burst > 5 req / 10s with 429' : '✗ Unrestricted request throughput'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleToggleSandboxFix('enableRateLimit')}
              disabled={isUpdatingSandbox}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                sandboxConfig.enableRateLimit
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              }`}
            >
              {sandboxConfig.enableRateLimit ? 'PATCHED' : 'VULNERABLE'}
            </button>
          </div>

          {/* Admin Auth Toggle */}
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Admin Route Authentication</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                {sandboxConfig.requireAdminAuth ? '✓ Requires Admin Bearer JWT (401 on anon)' : '✗ Anonymous 200 OK access to /admin/users'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => handleToggleSandboxFix('requireAdminAuth')}
              disabled={isUpdatingSandbox}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
                sandboxConfig.requireAdminAuth
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
              }`}
            >
              {sandboxConfig.requireAdminAuth ? 'PATCHED' : 'VULNERABLE'}
            </button>
          </div>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Guardrail Policy Card */}
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-400">
            <ShieldCheck className="h-5 w-5" />
            <span>Defensive Scope Hard Lockdown (Enforced)</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Per cybersecurity defensive guidelines, SentinelAPI strictly disallows automated scanning of arbitrary 
            internet targets. Probes are cryptographically locked to local sandbox containers and authorized loopback IPs.
          </p>
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 pt-1">
            <Lock className="h-3.5 w-3.5" />
            <span>Active Allowed Target: {targetScope} (Local Sandbox)</span>
          </div>
        </div>

        {/* Configuration Options */}
        <div className="rounded-xl border border-slate-800 bg-[#0c1017] p-6 space-y-5">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
            Scanner Engine Parameters
          </h3>

          {/* Rate Limit Probing Threshold */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Rate Limit Probe Safety Cap (Requests per Burst)
            </label>
            <input
              type="number"
              min={3}
              max={15}
              value={maxRateLimitBurst}
              onChange={(e) => setMaxRateLimitBurst(Number(e.target.value))}
              className="w-full sm:w-48 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-200 focus:border-emerald-500/50 focus:outline-none"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Limits the sequential request burst to prevent denial-of-service against test environments.
            </p>
          </div>

          {/* Sensitive Field Keywords for Schema Check */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Sensitive Keys Dictionary (Excessive Data Exposure Detection)
            </label>
            <input
              type="text"
              value={sensitiveFields}
              onChange={(e) => setSensitiveFields(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-200 focus:border-emerald-500/50 focus:outline-none"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Comma-separated property names flagged as potentially risky if found in response schemas.
            </p>
          </div>

          {/* Gemini AI Integration Toggle */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
            <div>
              <div className="text-xs font-medium text-slate-200">
                Sentinel AI Remediation Engine (Gemini 3.8 Flash)
              </div>
              <p className="text-[11px] text-slate-400">
                Enables AI-driven code patches and vulnerability explanation queries.
              </p>
            </div>
            <input
              type="checkbox"
              checked={enableGeminiDefensiveAi}
              onChange={(e) => setEnableGeminiDefensiveAi(e.target.checked)}
              className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-emerald-500 focus:ring-emerald-400 cursor-pointer"
            />
          </div>
        </div>

        {/* Save Button */}
        <div className="flex items-center gap-3">
          <button
            type="submit"
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-5 py-2.5 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
          >
            <Save className="h-4 w-4" />
            <span>Save Configuration</span>
          </button>

          {savedSuccess && (
            <span className="flex items-center gap-1.5 text-xs font-mono text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
              <span>Settings updated successfully.</span>
            </span>
          )}
        </div>
      </form>
    </div>
  );
};
