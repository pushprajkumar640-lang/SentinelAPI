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
  Sparkles,
  Menu,
  X
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
  const [isMobileOpen, setIsMobileOpen] = React.useState(false);
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
    { id: 'endpoints', label: 'Endpoints', icon: Layers, badge: endpointsCount > 0 ? endpointsCount : undefined },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: ShieldAlert,
      badge: vulnerabilitiesCount > 0 ? vulnerabilitiesCount : undefined,
      badgeColor: criticalCount > 0 ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  const selectTab = (tab: NavTab) => {
    onSelectTab(tab);
    setIsMobileOpen(false);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setIsMobileOpen((open) => !open)}
        className="fixed left-4 top-[4.5rem] z-40 grid h-9 w-9 place-items-center rounded-lg border border-slate-700 bg-slate-950/95 text-slate-300 shadow-lg md:hidden"
        aria-label={isMobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
      >
        {isMobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
      </button>
      {isMobileOpen && <button type="button" aria-label="Close navigation menu" onClick={() => setIsMobileOpen(false)} className="fixed inset-0 z-30 bg-black/60 md:hidden" />}
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col justify-between border-r border-slate-800/80 bg-[#0a0d13] px-3 py-5 transition-transform duration-200 md:static md:translate-x-0 ${isMobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="space-y-6">
          {activeProject ? (
            <div className="space-y-1 rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">Active Project</div>
              <div className="truncate text-xs font-bold text-slate-200" title={activeProject.name}>{activeProject.name}</div>
              <div className="flex items-center gap-1 text-[10px] font-mono text-emerald-400"><span>●</span><span>{activeProject.isDemo ? 'Demo Sandbox' : 'Authorized Project'}</span></div>
            </div>
          ) : (
            <button onClick={() => selectTab('projects')} className="w-full cursor-pointer space-y-1 rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-3 text-left transition-colors hover:border-emerald-500/40">
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">Project</div>
              <div className="flex items-center justify-between text-xs font-bold text-slate-400"><span>Select Project</span><span>&rarr;</span></div>
            </button>
          )}

          <div>
            <div className="mb-2 px-3 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">Security Operations</div>
            <nav className="space-y-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button key={item.id} onClick={() => selectTab(item.id)} className={`flex w-full cursor-pointer items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-all ${isActive ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-sm' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'}`}>
                    <div className="flex items-center gap-3"><Icon className={`h-4 w-4 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} /><span>{item.label}</span></div>
                    {item.badge !== undefined && <span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono ${item.badgeColor || 'border-slate-700 bg-slate-800 text-slate-300'}`}>{item.badge}</span>}
                  </button>
                );
              })}
            </nav>
          </div>
        </div>

        <div className="space-y-3">
          <button onClick={onLaunchDemoSandbox} className="flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-purple-500/30 bg-purple-950/20 px-3 py-2 text-xs font-semibold text-purple-300 shadow-sm transition-all hover:bg-purple-900/30"><Sparkles className="h-3.5 w-3.5 text-purple-400" /><span>Launch Demo Sandbox</span></button>
          <div className="space-y-1.5 rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-3"><div className="flex items-center gap-2 text-xs font-semibold text-emerald-300"><ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400" /><span>Defensive Scope Guard</span></div><p className="text-[10px] font-mono leading-relaxed text-slate-400">Scanning strictly confined to authorized staging &amp; test environments.</p></div>
        </div>
      </aside>
    </>
  );
};