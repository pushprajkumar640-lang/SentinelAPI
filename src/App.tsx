/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { ScanApiView } from './components/ScanApiView';
import { EndpointsView } from './components/EndpointsView';
import { VulnerabilitiesView } from './components/VulnerabilitiesView';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ReportsView } from './components/ReportsView';
import { ScanHistoryView, ScanRecordItem } from './components/ScanHistoryView';
import { SettingsView } from './components/SettingsView';
import { PresentationModeModal } from './components/PresentationModeModal';
import { AiAssistantDrawer } from './components/AiAssistantDrawer';
import { ProjectsListView, ProjectCardData } from './components/ProjectsListView';
import { NewProjectModal } from './components/NewProjectModal';
import { AuthView } from './components/AuthView';
import { PublicLanding } from './components/PublicLanding';
import { useAuth } from './context/AuthContext';
import { apiFetch } from './lib/api';
import {
  VulnerabilityFinding,
  ApiEndpoint,
  SecurityScoreBreakdown,
  ScanResult
} from './types/security';

// Default empty score when un-scanned
const DEFAULT_EMPTY_SCORE: SecurityScoreBreakdown = {
  currentScore: 100,
  baseScore: 100,
  ratingGrade: 'A',
  authCoveragePercentage: 100,
  deductions: {
    criticalDeduction: 0,
    criticalCount: 0,
    highDeduction: 0,
    highCount: 0,
    mediumDeduction: 0,
    mediumCount: 0,
    lowDeduction: 0,
    lowCount: 0
  }
};

export default function App() {
  const { user, loading: authLoading, getToken } = useAuth();
  const [authMode, setAuthMode] = useState<'signin' | 'signup' | null>(null);
  const [showPublicDashboard, setShowPublicDashboard] = useState(false);

  // Projects state
  const [projects, setProjects] = useState<ProjectCardData[]>([]);
  const [activeProject, setActiveProject] = useState<ProjectCardData | null>(null);
  const [loadingProjects, setLoadingProjects] = useState<boolean>(true);
  const [isNewProjectModalOpen, setIsNewProjectModalOpen] = useState<boolean>(false);

  // Active Project Data state
  const [currentTab, setCurrentTab] = useState<NavTab>('projects');
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [scans, setScans] = useState<ScanRecordItem[]>([]);
  const [score, setScore] = useState<SecurityScoreBreakdown>(DEFAULT_EMPTY_SCORE);
  const [hasScanned, setHasScanned] = useState<boolean>(false);

  // Modals & Drawers state
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [isPresentationOpen, setIsPresentationOpen] = useState<boolean>(false);
  const [isAiAssistantOpen, setIsAiAssistantOpen] = useState<boolean>(false);
  const [activeAiFinding, setActiveAiFinding] = useState<VulnerabilityFinding | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [dashboardSummary, setDashboardSummary] = useState<{
    scansCount: number;
    averageScore: number;
    vulnerabilitiesCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  } | null>(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState<string | null>(null);

  // Recalculate score from actual findings
  const recalculateScore = (activeFindings: VulnerabilityFinding[], totalEps: number) => {
    const unresolved = activeFindings.filter((f) => f.status !== 'RESOLVED');

    const criticalCount = unresolved.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = unresolved.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = unresolved.filter((f) => f.severity === 'MEDIUM').length;
    const lowCount = unresolved.filter((f) => f.severity === 'LOW').length;

    const criticalDeduction = criticalCount * 30;
    const highDeduction = highCount * 20;
    const mediumDeduction = mediumCount * 10;
    const lowDeduction = lowCount * 5;

    const totalDeductions =
      criticalDeduction + highDeduction + mediumDeduction + lowDeduction;
    const computedScore = Math.max(0, 100 - totalDeductions);

    let ratingGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';
    if (computedScore >= 90) ratingGrade = 'A';
    else if (computedScore >= 80) ratingGrade = 'B';
    else if (computedScore >= 70) ratingGrade = 'C';
    else if (computedScore >= 60) ratingGrade = 'D';

    setScore({
      currentScore: computedScore,
      baseScore: 100,
      ratingGrade,
      authCoveragePercentage: totalEps > 0 ? 88 : 100,
      deductions: {
        criticalDeduction,
        criticalCount,
        highDeduction,
        highCount,
        mediumDeduction,
        mediumCount,
        lowDeduction,
        lowCount
      }
    });
  };

  // Fetch projects from the authenticated PostgreSQL backend.
  const fetchProjects = useCallback(async () => {
    setLoadingProjects(true);
    try {
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      setDashboardLoading(true);
      setDashboardError(null);
      try {
        const summaryRes = await apiFetch('/api/dashboard/summary', { headers });
        if (summaryRes.ok) {
          const summaryData = await summaryRes.json();
          setDashboardSummary(summaryData.summary || null);
        } else {
          setDashboardError('Unable to load dashboard data');
        }
      } catch {
        setDashboardError('Unable to load dashboard data');
      } finally {
        setDashboardLoading(false);
      }

      let backendProjects: ProjectCardData[] = [];
      try {
        const res = await apiFetch('/api/projects', { headers });
        if (res.ok) {
          const data = await res.json();
          backendProjects = data.projects || [];
        }
      } catch (err) {
        console.warn('Backend projects fetch note:', err);
      }

      const allProjects = backendProjects;
      setProjects(allProjects);

      // If active project is still in list, keep it; otherwise null
      if (activeProject) {
        const stillExists = allProjects.find((p) => String(p.id) === String(activeProject.id));
        if (stillExists) setActiveProject(stillExists);
      }
    } catch (err) {
      console.error('Error loading projects:', err);
    } finally {
      setLoadingProjects(false);
    }
  }, [getToken, user, activeProject]);

  useEffect(() => {
    if (user) fetchProjects();
    else {
      setProjects([]);
      setLoadingProjects(false);
      setDashboardSummary(null);
      setDashboardError(null);
      setDashboardLoading(false);
    }
  }, [user, fetchProjects]);

  // Helper to ensure all findings have strictly unique IDs
  const ensureUniqueFindings = (items: VulnerabilityFinding[]): VulnerabilityFinding[] => {
    const seen = new Set<string>();
    return items.map((item, idx) => {
      let id = item.id;
      if (!id || seen.has(id)) {
        id = `${item.id || 'VULN'}-${idx}-${Math.random().toString(36).slice(2, 6)}`;
      }
      seen.add(id);
      return { ...item, id };
    });
  };

  // Load project-specific data from PostgreSQL.
  const loadProjectData = async (project: ProjectCardData) => {
    try {
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const [epsRes, scansRes] = await Promise.all([
        apiFetch(`/api/projects/${project.id}/endpoints`, { headers }),
        apiFetch(`/api/projects/${project.id}/scans`, { headers })
      ]);
      const endpointsData = epsRes.ok ? await epsRes.json() : { endpoints: [] };
      const scansData = scansRes.ok ? await scansRes.json() : { scans: [] };
      const loadedEndpoints: ApiEndpoint[] = endpointsData.endpoints || [];
      const loadedScans: ScanRecordItem[] = scansData.scans || [];
      const latestScan = loadedScans[0];
      const vulnsRes = await apiFetch(
        `/api/projects/${project.id}/vulnerabilities${latestScan?.id ? `?scanId=${latestScan.id}` : ''}`,
        { headers }
      );
      const vulnsData = vulnsRes.ok ? await vulnsRes.json() : { vulnerabilities: [] };
      const loadedFindings: VulnerabilityFinding[] = vulnsData.vulnerabilities || [];

      const safeFindings = ensureUniqueFindings(loadedFindings);
      setEndpoints(loadedEndpoints);
      setFindings(safeFindings);
      setScans(loadedScans);

      const hasPreviousScans = loadedScans.length > 0;
      setHasScanned(hasPreviousScans);

      if (hasPreviousScans) {
        recalculateScore(safeFindings, loadedEndpoints.length);
      } else {
        setScore(DEFAULT_EMPTY_SCORE);
      }
    } catch (err) {
      console.error('Error loading project details:', err);
    }
  };

  // Select a project
  const handleSelectProject = (project: ProjectCardData) => {
    setActiveProject(project);
    loadProjectData(project);
    setCurrentTab('dashboard');
  };

  // Create Project Callback
  const handleProjectCreated = (newProj: any) => {
    const cardData: ProjectCardData = {
      id: newProj.id || newProj.projectId,
      name: newProj.name,
      description: newProj.description,
      apiUrl: newProj.apiUrl,
      isDemo: false,
      totalEndpoints: 0,
      scansCount: 0,
      createdAt: newProj.createdAt || newProj.created_at || new Date().toISOString(),
      latestScan: null
    };
    setProjects((prev) => [cardData, ...prev]);
    handleSelectProject(cardData);
  };

  // Launch Demo Sandbox (creates an authorized sandboxed test project)
  const handleLaunchDemoSandbox = async () => {
    try {
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await apiFetch('/api/demo/setup', { method: 'POST', headers });
      if (res.ok) {
        const data = await res.json();
        const demoProj: ProjectCardData = {
          id: data.project.id,
          name: data.project.name,
          description: data.project.description,
          isDemo: true,
          totalEndpoints: data.totalEndpoints,
          scansCount: data.latestScan ? 1 : 0,
          createdAt: data.project.createdAt || new Date().toISOString(),
          latestScan: data.latestScan
        };

        setProjects((prev) => {
          const filtered = prev.filter((p) => String(p.id) !== String(demoProj.id));
          return [demoProj, ...filtered];
        });
        handleSelectProject(demoProj);
      }
    } catch (err) {
      console.error('Error setting up demo sandbox:', err);
    }
  };

  // Delete project
  const handleDeleteProject = async (projectId: string | number) => {
    try {
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await apiFetch(`/api/projects/${projectId}`, {
        method: 'DELETE',
        headers
      }).catch(() => {});

      setProjects((prev) => prev.filter((p) => String(p.id) !== String(projectId)));
      if (String(activeProject?.id) === String(projectId)) {
        setActiveProject(null);
        setCurrentTab('projects');
      }
    } catch (err) {
      console.error('Error deleting project:', err);
    }
  };

  // Specification Saved & Endpoints Discovered Callback
  const handleSpecSaved = (count: number, newEndpoints: ApiEndpoint[]) => {
    setEndpoints(newEndpoints);
    if (activeProject) {
      const updated = {
        ...activeProject,
        totalEndpoints: count
      };
      setActiveProject(updated);
      setProjects((prev) =>
        prev.map((p) => (String(p.id) === String(activeProject.id) ? updated : p))
      );
    }
  };

  // Scan Completed Callback
  const handleScanCompleted = (result: ScanResult) => {
    const safeFindings = ensureUniqueFindings(result.findings);
    setFindings(safeFindings);
    setScore(result.score);
    setHasScanned(true);

    const newScanRecord: ScanRecordItem = {
      id: `scan-${Date.now()}`,
      scanId: result.scanId,
      projectId: activeProject?.id || 1,
      status: 'COMPLETED',
      securityScore: result.score.currentScore,
      ratingGrade: result.score.ratingGrade,
      totalEndpoints: result.totalEndpoints,
      criticalCount: result.summary.critical,
      highCount: result.summary.high,
      mediumCount: result.summary.medium,
      lowCount: result.summary.low,
      durationSeconds: result.durationSeconds,
      startedAt: result.timestamp,
      completedAt: new Date().toISOString()
    };

    setScans((prev) => [newScanRecord, ...prev]);

    if (activeProject) {
      const updatedProject: ProjectCardData = {
        ...activeProject,
        scansCount: (activeProject.scansCount || 0) + 1,
        totalEndpoints: result.totalEndpoints,
        latestScan: {
          scanId: result.scanId,
          status: 'COMPLETED',
          securityScore: result.score.currentScore,
          ratingGrade: result.score.ratingGrade,
          criticalCount: result.summary.critical,
          highCount: result.summary.high,
          mediumCount: result.summary.medium,
          lowCount: result.summary.low,
          completedAt: new Date().toISOString()
        }
      };
      setActiveProject(updatedProject);
      setProjects((prev) =>
        prev.map((p) => (String(p.id) === String(activeProject.id) ? updatedProject : p))
      );
    }

    setCurrentTab('dashboard');
  };

  // Toggle resolve finding
  const handleToggleResolve = async (findingId: string) => {
    const target = findings.find((f) => f.id === findingId);
    if (!target) return;

    const newStatus = target.status === 'RESOLVED' ? 'OPEN' : 'RESOLVED';
    const updated = findings.map((f) =>
      f.id === findingId ? { ...f, status: newStatus as any } : f
    );
    setFindings(updated);
    recalculateScore(updated, endpoints.length);

    try {
      const token = await getToken();
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await apiFetch(`/api/vulnerabilities/${findingId}/status`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: newStatus })
      });
    } catch (err) {
      console.error('Error updating vulnerability status:', err);
    }
  };

  // Open AI Copilot for specific finding
  const handleOpenAiAssistant = (finding: VulnerabilityFinding) => {
    setActiveAiFinding(finding);
    setIsAiAssistantOpen(true);
  };

  if (authLoading) {
    return <div className="min-h-screen bg-[#06080c] flex items-center justify-center text-xs font-mono text-emerald-400">Restoring secure session...</div>;
  }

  if (!user) {
    if (showPublicDashboard) {
      return (
        <main className="min-h-screen overflow-y-auto bg-gradient-to-b from-[#06080c] to-[#080b11] p-4 text-slate-100 sm:p-6 lg:p-8">
          <div className="mx-auto max-w-6xl">
            <button type="button" onClick={() => setShowPublicDashboard(false)} className="mb-6 text-xs font-mono text-slate-400 transition-colors hover:text-emerald-300">&larr; Back to SentinelAPI</button>
            <DashboardView
              score={DEFAULT_EMPTY_SCORE}
              findings={[]}
              totalEndpoints={0}
              hasScanned={false}
              projectName="SentinelAPI Workspace"
              onSelectFinding={() => {}}
              onNavigateTab={() => {}}
            />
          </div>
        </main>
      );
    }
    return (
      <>
        <PublicLanding onOpenAuth={setAuthMode} onOpenDashboard={() => setShowPublicDashboard(true)} />
        {authMode && (
          <AuthView
            key={authMode}
            initialMode={authMode}
            onClose={() => setAuthMode(null)}
          />
        )}
      </>
    );
  }

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-[#06080c] text-slate-100 antialiased selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        activeProject={activeProject}
        onOpenProjects={() => setCurrentTab('projects')}
        onLaunchDemoSandbox={handleLaunchDemoSandbox}
        onOpenPresentation={() => setIsPresentationOpen(true)}
        onToggleAiAssistant={() => {
          setActiveAiFinding(null);
          setIsAiAssistantOpen(!isAiAssistantOpen);
        }}
        isScanning={isScanning}
        securityScore={score.currentScore}
        hasScanned={hasScanned}
      />

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          activeProject={activeProject}
          endpointsCount={endpoints.length}
          vulnerabilitiesCount={findings.length}
          criticalCount={findings.filter((f) => f.severity === 'CRITICAL').length}
          onLaunchDemoSandbox={handleLaunchDemoSandbox}
        />

        {/* Content View Container */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-b from-[#06080c] to-[#080b11] p-4 sm:p-6 lg:p-8">
          {/* Projects View */}
          {currentTab === 'projects' && (
            <ProjectsListView
              projects={projects}
              onSelectProject={handleSelectProject}
              onOpenNewProjectModal={() => setIsNewProjectModalOpen(true)}
              onLaunchDemoSandbox={handleLaunchDemoSandbox}
              onDeleteProject={handleDeleteProject}
              loading={loadingProjects}
            />
          )}

          {/* Project Dashboard View */}
          {currentTab === 'dashboard' && (
            activeProject ? (
              <DashboardView
                score={score}
                findings={findings}
                totalEndpoints={endpoints.length}
                hasScanned={hasScanned}
                projectName={activeProject.name}
                onSelectFinding={setSelectedFinding}
                onNavigateTab={(tab) => setCurrentTab(tab as NavTab)}
                dashboardSummary={dashboardSummary}
                dashboardLoading={dashboardLoading}
                dashboardError={dashboardError}
              />
            ) : (
              <ProjectsListView
                projects={projects}
                onSelectProject={handleSelectProject}
                onOpenNewProjectModal={() => setIsNewProjectModalOpen(true)}
                onLaunchDemoSandbox={handleLaunchDemoSandbox}
                onDeleteProject={handleDeleteProject}
                loading={loadingProjects}
              />
            )
          )}

          {/* Scan API View */}
          {currentTab === 'scan' && (
            <ScanApiView
              activeProject={activeProject}
              endpoints={endpoints}
              getToken={getToken}
              onScanCompleted={handleScanCompleted}
              onSpecSaved={handleSpecSaved}
              onNavigateTab={(tab) => setCurrentTab(tab as NavTab)}
              onOpenProjects={() => setCurrentTab('projects')}
              userId={user?.uid}
            />
          )}

          {/* Endpoints View */}
          {currentTab === 'endpoints' && (
            <EndpointsView
              endpoints={endpoints}
              findings={findings}
              onSelectFinding={setSelectedFinding}
            />
          )}

          {/* Vulnerabilities View */}
          {currentTab === 'vulnerabilities' && (
            <VulnerabilitiesView
              findings={findings}
              onSelectFinding={setSelectedFinding}
              onToggleResolve={handleToggleResolve}
              onOpenAiAssistant={handleOpenAiAssistant}
              onNavigateTab={(tab) => setCurrentTab(tab as NavTab)}
            />
          )}

          {/* Reports View */}
          {currentTab === 'reports' && (
            <ReportsView
              findings={findings}
              score={score}
              totalEndpoints={endpoints.length}
              apiName={activeProject?.name || 'Authorized Sandbox API'}
              apiUrl={activeProject?.apiUrl}
              apiVersion="v1.0.0"
              scanId={scans[0]?.scanId}
              scanDate={scans[0]?.completedAt || scans[0]?.startedAt}
            />
          )}

          {/* Scan History View */}
          {currentTab === 'history' && (
            <ScanHistoryView
              scans={scans}
              projectName={activeProject?.name}
              onNavigateScan={() => setCurrentTab('scan')}
            />
          )}

          {/* Settings View */}
          {currentTab === 'settings' && <SettingsView />}
        </main>
      </div>

      {/* New Project Modal */}
      <NewProjectModal
        isOpen={isNewProjectModalOpen}
        onClose={() => setIsNewProjectModalOpen(false)}
        onProjectCreated={handleProjectCreated}
        getToken={getToken}
        userId={user?.uid}
      />

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onToggleResolve={handleToggleResolve}
          onOpenAiAssistant={handleOpenAiAssistant}
          scanContext={{
            project: activeProject?.name,
            apiUrl: activeProject?.apiUrl,
            scanId: scans[0]?.scanId,
            securityScore: score.currentScore,
            endpointsScanned: endpoints.length,
            findings,
            severityCounts: {
              CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
              HIGH: findings.filter((f) => f.severity === 'HIGH').length,
              MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
              LOW: findings.filter((f) => f.severity === 'LOW').length
            }
          }}
        />
      )}

      {/* Presentation Mode Modal */}
      {isPresentationOpen && (
        <PresentationModeModal
          isOpen={isPresentationOpen}
          onClose={() => setIsPresentationOpen(false)}
          findings={findings}
          score={score}
          onSelectFinding={setSelectedFinding}
        />
      )}

      {/* Sentinel AI Drawer */}
      <AiAssistantDrawer
        isOpen={isAiAssistantOpen}
        onClose={() => setIsAiAssistantOpen(false)}
        activeFinding={activeAiFinding}
        scanContext={{
          project: activeProject?.name,
          apiUrl: activeProject?.apiUrl,
          scanId: scans[0]?.scanId,
          securityScore: score.currentScore,
          endpointsScanned: endpoints.length,
          findings,
          severityCounts: {
            CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
            HIGH: findings.filter((f) => f.severity === 'HIGH').length,
            MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
            LOW: findings.filter((f) => f.severity === 'LOW').length
          }
        }}
      />
    </div>
  );
}
