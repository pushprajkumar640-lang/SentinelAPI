import React from 'react';
import { Shield, ArrowRight, Play, Terminal, Database, KeyRound, Gauge } from 'lucide-react';

interface LandingHeroProps {
  onStartScan: () => void;
  onOpenPresentation: () => void;
}

export const LandingHero: React.FC<LandingHeroProps> = ({
  onStartScan,
  onOpenPresentation,
}) => {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-[#0c1017]/80 p-6 sm:p-8 backdrop-blur-md mb-8">
      {/* Background Decorative Glow */}
      <div className="pointer-events-none absolute -top-24 -right-24 h-96 w-96 rounded-full bg-emerald-500/10 blur-3xl"></div>
      <div className="pointer-events-none absolute -bottom-24 -left-24 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl"></div>

      <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
        {/* Left Column: Heading & CTA */}
        <div className="space-y-4 max-w-2xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-mono text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping"></span>
            Defensive API Security Auditor &middot; OWASP API Top 10
          </div>

          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white leading-tight">
            SENTINEL<span className="text-emerald-400">API</span>
            <span className="block text-xl sm:text-2xl font-medium text-slate-300 mt-1">
              "Find the API vulnerability before the breach headline does."
            </span>
          </h1>

          <p className="text-sm sm:text-base text-slate-400 leading-relaxed">
            Automatically discover API security weaknesses before they reach production. 
            Analyzes OpenAPI specifications, executes safe authorization probes in isolated sandboxes, 
            and generates verifiable proof-of-concept reproductions with developer-ready code fixes.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              onClick={onStartScan}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-5 py-2.5 text-xs sm:text-sm font-semibold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-lg shadow-emerald-500/15"
            >
              <span>Start Security Scan</span>
              <ArrowRight className="h-4 w-4" />
            </button>

            <button
              onClick={onOpenPresentation}
              className="flex items-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2.5 text-xs sm:text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all cursor-pointer"
            >
              <Play className="h-4 w-4 fill-cyan-300" />
              <span>View Demo Walkthrough</span>
            </button>
          </div>

          {/* Feature Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3">
            <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900/60 border border-slate-800 rounded-lg px-2.5 py-1.5">
              <KeyRound className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              <span className="truncate">BOLA / IDOR</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900/60 border border-slate-800 rounded-lg px-2.5 py-1.5">
              <Database className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
              <span className="truncate">Excessive Data</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900/60 border border-slate-800 rounded-lg px-2.5 py-1.5">
              <Gauge className="h-3.5 w-3.5 text-amber-400 shrink-0" />
              <span className="truncate">Weak Rate Limits</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900/60 border border-slate-800 rounded-lg px-2.5 py-1.5">
              <Terminal className="h-3.5 w-3.5 text-purple-400 shrink-0" />
              <span className="truncate">Broken Auth</span>
            </div>
          </div>
        </div>

        {/* Right Column: Security Shield & Statistics */}
        <div className="w-full lg:w-80 flex flex-col items-center justify-center space-y-4">
          <div className="relative flex h-32 w-32 items-center justify-center">
            {/* Pulsing Concentric Rings */}
            <div className="absolute inset-0 rounded-full border border-emerald-500/20 animate-ping opacity-25"></div>
            <div className="absolute inset-2 rounded-full border border-cyan-500/30"></div>
            <div className="relative flex h-24 w-24 items-center justify-center rounded-2xl bg-gradient-to-tr from-slate-900 via-slate-800 to-slate-900 border border-emerald-500/40 shadow-xl shadow-emerald-500/10">
              <Shield className="h-12 w-12 text-emerald-400 drop-shadow-[0_0_15px_rgba(16,185,129,0.5)]" />
            </div>
          </div>

          {/* Quick Statistics Strip */}
          <div className="w-full grid grid-cols-2 gap-2 text-center">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-2.5">
              <div className="text-xl font-bold font-mono text-white">148</div>
              <div className="text-[11px] text-slate-400">APIs Scanned</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-2.5">
              <div className="text-xl font-bold font-mono text-emerald-400">392</div>
              <div className="text-[11px] text-slate-400">Vulns Detected</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-2.5">
              <div className="text-xl font-bold font-mono text-red-400">41</div>
              <div className="text-[11px] text-slate-400">Critical BOLA</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-2.5">
              <div className="text-xl font-bold font-mono text-cyan-400">74%</div>
              <div className="text-[11px] text-slate-400">Avg Score</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
