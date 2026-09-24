import React from 'react';
import {
  LayoutDashboard,
  ScanLine,
  Layers,
  ShieldAlert,
  FileText,
  History,
  Settings,
  ShieldCheck,
  FolderKanban,
  Sparkles
} from 'lucide-react';
import { ProjectCardData } from './ProjectsListView';

export type NavTab =
  | 'projects'
  | 'dashboard'
  | 'scan'
  | 'endpoints'
  | 'vulnerabilities'
  | 'reports'
  | 'history'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  activeProject: ProjectCardData | null;
  endpointsCount: number;
  vulnerabilitiesCount: number;
  criticalCount: number;
  onLaunchDemoSandbox: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  activeProject,
  endpointsCount,
  vulnerabilitiesCount,
  criticalCount,
  onLaunchDemoSandbox
}) => {
  const navItems: Array<{
    id: NavTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string | number;
    badgeColor?: string;
  }> = [
    { id: 'projects', label: 'Projects', icon: FolderKanban },
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scan', label: 'Scan API', icon: ScanLine },
    {
      id: 'endpoints',
      label: 'Endpoints',
      icon: Layers,
      badge: endpointsCount > 0 ? endpointsCount : undefined
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: ShieldAlert,
      badge: vulnerabilitiesCount > 0 ? vulnerabilitiesCount : undefined,
      badgeColor:
        criticalCount > 0
          ? 'bg-red-500/20 text-red-400 border-red-500/30'
          : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <aside className="w-64 shrink-0 border-r border-slate-800/80 bg-[#0a0d13] flex flex-col justify-between py-5 px-3">
      <div className="space-y-6">
        {/* Active Project Card */}
        {activeProject ? (
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3 space-y-1">
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
              Active Project
            </div>
            <div className="text-xs font-bold text-slate-200 truncate" title={activeProject.name}>
              {activeProject.name}
            </div>
            <div className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span>●</span>
              <span>{activeProject.isDemo ? 'Demo Sandbox' : 'Authorized Project'}</span>
            </div>
          </div>
        ) : (
          <button
            onClick={() => onSelectTab('projects')}
            className="w-full text-left rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-3 space-y-1 hover:border-emerald-500/40 transition-colors cursor-pointer"
          >
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
              Project
            </div>
            <div className="text-xs font-bold text-slate-400 flex items-center justify-between">
              <span>Select Project</span>
              <span>&rarr;</span>
            </div>
          </button>
        )}

        {/* Navigation Section */}
        <div>
          <div className="px-3 mb-2 text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
            Security Operations
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    isActive
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon
                      className={`h-4 w-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}
                    />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && (
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                        item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Bottom Defensive Demo Shortcut */}
      <div className="space-y-3">
        <button
          onClick={onLaunchDemoSandbox}
          className="w-full flex items-center justify-center gap-1.5 rounded-xl border border-purple-500/30 bg-purple-950/20 hover:bg-purple-900/30 px-3 py-2 text-xs font-semibold text-purple-300 transition-all cursor-pointer shadow-sm"
        >
          <Sparkles className="h-3.5 w-3.5 text-purple-400" />
          <span>Launch Demo Sandbox</span>
        </button>

        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3 space-y-1.5">
          <div className="flex items-center gap-2 text-xs font-semibold text-emerald-300">
            <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>Defensive Scope Guard</span>
          </div>
          <p className="text-[10px] text-slate-400 leading-relaxed font-mono">
            Scanning strictly confined to authorized staging & test environments.
          </p>
        </div>
      </div>
    </aside>
  );
};
