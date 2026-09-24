import React from 'react';
import {
  Shield,
  Play,
  Sparkles,
  Terminal,
  Activity,
  CheckCircle2,
  LogIn,
  LogOut,
  FolderKanban,
  UserCheck
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ProjectCardData } from './ProjectsListView';

interface NavbarProps {
  currentTab: string;
  activeProject: ProjectCardData | null;
  onOpenProjects: () => void;
  onLaunchDemoSandbox: () => void;
  onOpenPresentation: () => void;
  onToggleAiAssistant: () => void;
  isScanning: boolean;
  securityScore: number;
  hasScanned: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeProject,
  onOpenProjects,
  onLaunchDemoSandbox,
  onOpenPresentation,
  onToggleAiAssistant,
  isScanning,
  securityScore,
  hasScanned
}) => {
  const { user, dbUser, signInWithGoogle, signOut } = useAuth();

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800/80 bg-[#080a0f]/90 px-4 sm:px-6 backdrop-blur-md">
      {/* Left: Branding & Active Project Selector */}
      <div className="flex items-center gap-3 sm:gap-4">
        <div
          onClick={onOpenProjects}
          className="flex items-center gap-2.5 cursor-pointer group"
          title="Go to Projects Overview"
        >
          <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 via-cyan-500/20 to-emerald-500/10 border border-emerald-500/30 group-hover:border-emerald-400/50 transition-all">
            <Shield className="h-5 w-5 text-emerald-400" />
            <span className="absolute -top-1 -right-1 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-wider text-slate-100 text-base">
                SENTINEL<span className="text-emerald-400">API</span>
              </span>
              <span className="hidden lg:inline-flex items-center rounded-md bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">
                DEFENSIVE SCANNER
              </span>
            </div>
            <p className="hidden xl:block text-[10px] text-slate-400 font-mono truncate max-w-[200px]">
              Find the API vulnerability before the breach headline does.
            </p>
          </div>
        </div>

        {/* Project Selector Indicator */}
        <div className="flex items-center gap-1.5 pl-2 sm:pl-3 border-l border-slate-800">
          <button
            onClick={onOpenProjects}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/90 hover:bg-slate-800 px-2.5 py-1 text-xs text-slate-300 transition-all cursor-pointer"
            title="Switch or manage security projects"
          >
            <FolderKanban className="h-3.5 w-3.5 text-emerald-400" />
            <span className="font-medium max-w-[130px] truncate text-slate-200">
              {activeProject ? activeProject.name : 'All Projects'}
            </span>
            <span className="text-[10px] text-slate-500 font-mono">&darr;</span>
          </button>
        </div>
      </div>

      {/* Right: Actions & Auth */}
      <div className="flex items-center gap-2 sm:gap-2.5">
        {/* Score indicator */}
        <div className="hidden md:flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-xs">
          <span className="text-slate-400">Score:</span>
          {hasScanned ? (
            <span
              className={`font-mono font-bold ${
                securityScore >= 80
                  ? 'text-emerald-400'
                  : securityScore >= 60
                  ? 'text-amber-400'
                  : 'text-red-400'
              }`}
            >
              {securityScore} / 100
            </span>
          ) : (
            <span className="font-mono text-slate-500 font-medium">Not Scanned</span>
          )}
        </div>

        {/* Presentation Mode Button */}
        <button
          onClick={onOpenPresentation}
          className="hidden sm:flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-xs font-medium text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 transition-all cursor-pointer"
          title="Open 3-minute hackathon judge walkthrough"
        >
          <Play className="h-3 w-3 fill-cyan-300" />
          <span>Walkthrough</span>
        </button>

        {/* Sentinel AI Drawer Toggle */}
        <button
          onClick={onToggleAiAssistant}
          className="flex items-center gap-1.5 rounded-lg border border-purple-500/30 bg-purple-950/20 px-2.5 py-1 text-xs font-medium text-purple-300 hover:bg-purple-900/30 transition-all cursor-pointer"
          title="Open Sentinel AI Copilot"
        >
          <Sparkles className="h-3 w-3 text-purple-400" />
          <span className="hidden sm:inline">AI Copilot</span>
        </button>

        {/* User Auth Profile / Google Sign-In */}
        {user ? (
          <div className="flex items-center gap-2 pl-1.5 border-l border-slate-800">
            {user.photoURL ? (
              <img
                src={user.photoURL}
                alt={user.displayName || 'User'}
                className="h-7 w-7 rounded-full border border-emerald-500/40"
              />
            ) : (
              <div className="h-7 w-7 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-xs font-bold text-emerald-400">
                {(user.displayName || user.email || 'U')[0].toUpperCase()}
              </div>
            )}
            <button
              onClick={signOut}
              title="Sign Out"
              className="text-slate-400 hover:text-red-400 p-1 rounded hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <button
            onClick={() => signInWithGoogle().catch(() => {})}
            className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-all cursor-pointer"
            title="Sign in with Google Account"
          >
            <LogIn className="h-3.5 w-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
};
