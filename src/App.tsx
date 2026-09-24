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
import { useAuth } from './context/AuthContext';
import {
  getUserProjectsFromFirestore,
  getProjectEndpointsFromFirestore,
  getProjectVulnerabilitiesFromFirestore,
  getProjectScansFromFirestore,
  deleteProjectFromFirestore,
  updateVulnerabilityStatusInFirestore
} from './lib/firestoreService';

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
  const { user, loading: authLoading, signInWithGoogle, signInDemoAuditor, getToken } = useAuth();

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

  // Recalculate score from actual findings
  const recalculateScore = (activeFindings: VulnerabilityFinding[], totalEps: number) => {
    const unresolved = activeFindings.filter((f) => f.status !== 'RESOLVED');

    const criticalCount = unresolved.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = unresolved.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = unresolved.filter((f) => f.severity === 'MEDIUM').length;
    const lowCount = unresolved.filter((f) => f.severity === 'LOW').length;

    const criticalDeduction = criticalCount * 25;
    const highDeduction = highCount * 15;
    const mediumDeduction = mediumCount * 8;
    const lowDeduction = lowCount * 3;

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

  // Fetch projects from Cloud Firestore (primary) and PostgreSQL (secondary)
  const fetchProjects = useCallback(async () => {
    setLoadingProjects(true);
    try {
      let firestoreProjects: ProjectCardData[] = [];

      // 1. Fetch from Firestore if user is authenticated
      if (user?.uid) {
        try {
          const fsProjects = await getUserProjectsFromFirestore(user.uid);
          firestoreProjects = fsProjects.map((p) => ({
            id: p.id,
            name: p.name,
            description: p.description,
            isDemo: false,
            totalEndpoints: p.totalEndpoints || 0,
            scansCount: p.scansCount || 0,
            createdAt: p.createdAt,
            updatedAt: p.createdAt,
            latestScan: p.latestScan || null
          }));
        } catch (fsErr) {
          console.warn('Firestore load note:', fsErr);
        }
      }

      // 2. Fetch from backend API
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      let backendProjects: ProjectCardData[] = [];
      try {
        const res = await fetch('/api/projects', { headers });
        if (res.ok) {
          const data = await res.json();
          backendProjects = data.projects || [];
        }
      } catch (err) {
        console.warn('Backend projects fetch note:', err);
      }

      // Merge projects avoiding duplicates
      const mergedMap = new Map<string, ProjectCardData>();
      for (const p of firestoreProjects) {
        mergedMap.set(String(p.id), p);
      }
      for (const p of backendProjects) {
        if (!mergedMap.has(String(p.id))) {
          mergedMap.set(String(p.id), p);
        }
      }

      const allProjects = Array.from(mergedMap.values());
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
    fetchProjects();
  }, [user]);

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

  // Load project-specific data from Firestore & backend
  const loadProjectData = async (project: ProjectCardData) => {
    try {
      const projIdStr = String(project.id);
      const uid = user?.uid;

      // 1. Try Firestore first if authenticated
      let loadedEndpoints: ApiEndpoint[] = [];
      let loadedFindings: VulnerabilityFinding[] = [];
      let loadedScans: ScanRecordItem[] = [];

      if (uid) {
        try {
          const [fsEndpoints, fsVulns, fsScans] = await Promise.all([
            getProjectEndpointsFromFirestore(projIdStr, uid),
            getProjectVulnerabilitiesFromFirestore(projIdStr, uid),
            getProjectScansFromFirestore(projIdStr, uid)
          ]);

          if (fsEndpoints.length > 0) loadedEndpoints = fsEndpoints;
          if (fsVulns.length > 0) loadedFindings = fsVulns;
          if (fsScans.length > 0) {
            loadedScans = fsScans.map((s) => ({
              id: s.id,
              scanId: s.scanId,
              projectId: s.projectId,
              status: s.status,
              securityScore: s.securityScore,
              ratingGrade: s.ratingGrade,
              totalEndpoints: s.endpointsScanned,
              criticalCount: s.criticalCount,
              highCount: s.highCount,
              mediumCount: s.mediumCount,
              lowCount: s.lowCount,
              durationSeconds: 1.5,
              startedAt: s.startedAt,
              completedAt: s.completedAt || s.startedAt
            }));
          }
        } catch (fsErr) {
          console.warn('Firestore load project data note:', fsErr);
        }
      }

      // 2. Fallback or augment with backend if empty
      if (loadedEndpoints.length === 0 || loadedFindings.length === 0) {
        const token = await getToken();
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const [epsRes, vulnsRes, scansRes] = await Promise.all([
          fetch(`/api/projects/${project.id}/endpoints`, { headers }),
          fetch(`/api/projects/${project.id}/vulnerabilities`, { headers }),
          fetch(`/api/projects/${project.id}/scans`, { headers })
        ]);

        if (epsRes.ok && loadedEndpoints.length === 0) {
          const epsData = await epsRes.json();
          loadedEndpoints = epsData.endpoints || [];
        }
        if (vulnsRes.ok && loadedFindings.length === 0) {
          const vulnsData = await vulnsRes.json();
          loadedFindings = vulnsData.vulnerabilities || [];
        }
        if (scansRes.ok && loadedScans.length === 0) {
          const scansData = await scansRes.json();
          loadedScans = scansData.scans || [];
        }
      }

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

      const res = await fetch('/api/demo/setup', { method: 'POST', headers });
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
      // 1. Delete from Firestore
      if (user?.uid) {
        await deleteProjectFromFirestore(user.uid, String(projectId)).catch(() => {});
      }

      // 2. Delete from backend API
      const token = await getToken();
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await fetch(`/api/projects/${projectId}`, {
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

    // Update in Firestore
    if (user?.uid) {
      updateVulnerabilityStatusInFirestore(user.uid, findingId, newStatus).catch(() => {});
    }

    // Update in backend
    try {
      const token = await getToken();
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      await fetch(`/api/vulnerabilities/${findingId}/status`, {
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
              apiVersion="v1.0.0"
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
      />
    </div>
  );
}
