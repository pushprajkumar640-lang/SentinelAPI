import React from 'react';
import {
  FolderPlus,
  Shield,
  Layers,
  Award,
  AlertTriangle,
  Calendar,
  Sparkles,
  ArrowRight,
  Trash2,
  Lock,
  ExternalLink
} from 'lucide-react';

export interface ProjectCardData {
  id: string | number;
  name: string;
  description: string | null;
  isDemo?: boolean;
  totalEndpoints: number;
  scansCount: number;
  createdAt: string;
  updatedAt?: string;
  latestScan: {
    scanId: string;
    status: string;
    securityScore: number;
    ratingGrade: string;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    completedAt: string;
  } | null;
}

interface ProjectsListViewProps {
  projects: ProjectCardData[];
  onSelectProject: (project: ProjectCardData) => void;
  onOpenNewProjectModal: () => void;
  onLaunchDemoSandbox: () => void;
  onDeleteProject: (projectId: string | number) => void;
  loading: boolean;
}

export const ProjectsListView: React.FC<ProjectsListViewProps> = ({
  projects,
  onSelectProject,
  onOpenNewProjectModal,
  onLaunchDemoSandbox,
  onDeleteProject,
  loading
}) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 space-y-4">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent" />
        <p className="text-xs font-mono text-slate-400">Loading projects from PostgreSQL...</p>
      </div>
    );
  }

  // If user has no projects
  if (projects.length === 0) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center space-y-6">
        <div className="h-16 w-16 mx-auto rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
          <Shield className="h-8 w-8" />
        </div>

        <div className="space-y-2">
          <h2 className="text-2xl font-extrabold text-white tracking-tight">
            No security projects yet.
          </h2>
          <p className="text-sm text-slate-400 max-w-md mx-auto">
            Create an authorized security project to upload an OpenAPI specification, discover endpoints, and run automated zero-trust defensive vulnerability scans.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <button
            onClick={onOpenNewProjectModal}
            className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-6 py-3 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-lg shadow-emerald-500/10"
          >
            <FolderPlus className="h-4 w-4" />
            <span>+ Create Project</span>
          </button>

          <button
            onClick={onLaunchDemoSandbox}
            className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-xl border border-purple-500/30 bg-purple-950/20 hover:bg-purple-900/30 px-6 py-3 text-xs font-bold text-purple-300 transition-all cursor-pointer shadow-sm"
          >
            <Sparkles className="h-4 w-4 text-purple-400" />
            <span>Try Demo Sandbox</span>
          </button>
        </div>

        <div className="pt-6 border-t border-slate-800/80 max-w-md mx-auto text-left">
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider mb-2">
            Standard SaaS Defensive Workflow
          </div>
          <ul className="text-xs text-slate-400 space-y-1.5 font-mono">
            <li>&rarr; 1. Create your isolated security project</li>
            <li>&rarr; 2. Upload OpenAPI contract (JSON or YAML)</li>
            <li>&rarr; 3. Auto-discover endpoints and schema definitions</li>
            <li>&rarr; 4. Execute controlled BOLA & data leak scanner</li>
            <li>&rarr; 5. Review findings & export audit report</li>
          </ul>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Security Projects</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Select a project to inspect its discovered endpoints, scan history, and active findings
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onLaunchDemoSandbox}
            className="flex items-center gap-1.5 rounded-xl border border-purple-500/30 bg-purple-950/20 hover:bg-purple-900/30 px-3.5 py-2 text-xs font-semibold text-purple-300 transition-all cursor-pointer"
          >
            <Sparkles className="h-3.5 w-3.5 text-purple-400" />
            <span>Try Demo Sandbox</span>
          </button>

          <button
            onClick={onOpenNewProjectModal}
            className="flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 px-4 py-2 text-xs font-bold text-slate-950 hover:from-emerald-400 hover:to-teal-400 transition-all cursor-pointer shadow-md shadow-emerald-500/10"
          >
            <FolderPlus className="h-3.5 w-3.5" />
            <span>New Project</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {projects.map((project) => {
          const hasScan = Boolean(project.latestScan);
          const totalVulns = hasScan
            ? (project.latestScan?.criticalCount || 0) +
              (project.latestScan?.highCount || 0) +
              (project.latestScan?.mediumCount || 0) +
              (project.latestScan?.lowCount || 0)
            : 0;

          return (
            <div
              key={project.id}
              className="relative rounded-2xl border border-slate-800 bg-[#0c1017] p-5 shadow-sm hover:border-slate-700 transition-all flex flex-col justify-between group"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                      <Shield className="h-3.5 w-3.5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white group-hover:text-emerald-400 transition-colors line-clamp-1">
                        {project.name}
                      </h3>
                      {project.isDemo && (
                        <span className="inline-block text-[10px] font-mono text-purple-400 font-semibold">
                          [AUTHORIZED DEMO ENVIRONMENT]
                        </span>
                      )}
                    </div>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      if (confirm(`Are you sure you want to delete project "${project.name}"?`)) {
                        onDeleteProject(project.id);
                      }
                    }}
                    title="Delete project"
                    className="text-slate-500 hover:text-red-400 p-1 rounded hover:bg-slate-800 transition-all cursor-pointer"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>

                <p className="text-xs text-slate-400 line-clamp-2 mt-1 min-h-[2rem]">
                  {project.description || 'No description provided.'}
                </p>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-slate-800/80">
                  <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/60">
                    <div className="text-[10px] text-slate-500 font-mono">ENDPOINTS</div>
                    <div className="text-xs font-mono font-bold text-slate-200 mt-0.5">
                      {project.totalEndpoints > 0 ? `${project.totalEndpoints} discovered` : 'Not uploaded'}
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/60">
                    <div className="text-[10px] text-slate-500 font-mono">SECURITY SCORE</div>
                    <div className="text-xs font-mono font-bold mt-0.5">
                      {hasScan ? (
                        <span className={project.latestScan!.securityScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}>
                          {project.latestScan!.securityScore}/100 (Grade {project.latestScan!.ratingGrade})
                        </span>
                      ) : (
                        <span className="text-slate-500">Not Scanned</span>
                      )}
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/60">
                    <div className="text-[10px] text-slate-500 font-mono">VULNERABILITIES</div>
                    <div className="text-xs font-mono font-bold mt-0.5">
                      {hasScan ? (
                        <span className={totalVulns > 0 ? 'text-red-400' : 'text-emerald-400'}>
                          {totalVulns} detected
                        </span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </div>
                  </div>

                  <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/60">
                    <div className="text-[10px] text-slate-500 font-mono">SCANS</div>
                    <div className="text-xs font-mono font-bold text-slate-300 mt-0.5">
                      {project.scansCount} executed
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-500 flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  <span>
                    {hasScan
                      ? `Last scan: ${new Date(project.latestScan!.completedAt).toLocaleDateString()}`
                      : 'Never scanned'}
                  </span>
                </span>

                <button
                  onClick={() => onSelectProject(project)}
                  className="flex items-center gap-1 text-xs font-bold text-emerald-400 hover:text-emerald-300 transition-colors cursor-pointer"
                >
                  <span>Open Project</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
