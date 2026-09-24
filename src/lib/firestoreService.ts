import {
  collection,
  doc,
  setDoc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  deleteDoc,
  updateDoc,
  serverTimestamp,
  Timestamp
} from 'firebase/firestore';
import { db, auth } from './firebase';
import {
  VulnerabilityFinding,
  ApiEndpoint,
  SecurityScoreBreakdown,
  ScanResult
} from '../types/security';

export interface FirestoreProject {
  id: string;
  projectId: string;
  ownerId: string;
  name: string;
  description: string;
  createdAt: any;
  totalEndpoints?: number;
  scansCount?: number;
  latestScore?: number;
  latestRating?: string;
  latestScan?: any;
}

export interface FirestoreApiSpec {
  id: string;
  projectId: string;
  userId: string;
  title: string;
  version: string;
  description: string;
  baseUrl: string;
  rawSpec: string;
  format: 'json' | 'yaml';
  totalEndpoints: number;
  methodsCount: Record<string, number>;
  authTypes: string[];
  createdAt: any;
}

export interface FirestoreScanRecord {
  id: string;
  scanId: string;
  projectId: string;
  userId: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  startedAt: string;
  completedAt?: string;
  endpointsScanned: number;
  securityScore: number;
  ratingGrade: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  targetScope?: string;
  createdAt: any;
}

export interface FirestoreVulnerability {
  id: string;
  userId: string;
  projectId: string;
  scanId: string;
  endpoint: string;
  method: string;
  title: string;
  category: string;
  owaspCategory?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  evidence: string;
  reproduction: any;
  impact: string;
  remediation: any;
  status: 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'IN_REVIEW';
  detectedAt: string;
  createdAt: any;
}

export interface FirestoreReport {
  id: string;
  userId: string;
  projectId: string;
  scanId: string;
  title: string;
  apiName: string;
  apiVersion: string;
  securityScore: number;
  ratingGrade: string;
  totalEndpoints: number;
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: any[];
  generatedAt: string;
  createdAt: any;
}

// =========================================================================
// 1. USERS COLLECTION
// =========================================================================
export async function syncUserProfileToFirestore(user: {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
}) {
  try {
    const userRef = doc(db, 'users', user.uid);
    await setDoc(
      userRef,
      {
        uid: user.uid,
        email: user.email || 'developer@sentinelapi.internal',
        displayName: user.displayName || 'Security Lead',
        photoURL: user.photoURL || null,
        lastLogin: serverTimestamp()
      },
      { merge: true }
    );
  } catch (error) {
    console.error('Error saving user profile to Firestore:', error);
  }
}

// =========================================================================
// 2. PROJECTS COLLECTION
// =========================================================================
export async function createProjectInFirestore(
  userId: string,
  data: { name: string; description: string }
): Promise<FirestoreProject> {
  const projectRef = doc(collection(db, 'projects'));
  const projectId = projectRef.id;

  const projectData: FirestoreProject = {
    id: projectId,
    projectId,
    ownerId: userId,
    name: data.name.trim(),
    description: data.description.trim() || 'Defensive security testing project',
    createdAt: new Date().toISOString(),
    totalEndpoints: 0,
    scansCount: 0,
    latestScore: undefined,
    latestRating: undefined,
    latestScan: null
  };

  await setDoc(projectRef, {
    ...projectData,
    createdTimestamp: serverTimestamp()
  });

  return projectData;
}

export async function getUserProjectsFromFirestore(userId?: string): Promise<FirestoreProject[]> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return [];

    const q = query(
      collection(db, 'projects'),
      where('ownerId', '==', uid)
    );
    const snap = await getDocs(q);
    const projects: FirestoreProject[] = [];
    snap.forEach((d) => {
      const data = d.data();
      projects.push({
        id: d.id,
        projectId: data.projectId || d.id,
        ownerId: data.ownerId,
        name: data.name,
        description: data.description,
        createdAt: data.createdAt || (data.createdTimestamp?.toDate ? data.createdTimestamp.toDate().toISOString() : new Date().toISOString()),
        totalEndpoints: data.totalEndpoints || 0,
        scansCount: data.scansCount || 0,
        latestScore: data.latestScore,
        latestRating: data.latestRating,
        latestScan: data.latestScan || null
      });
    });

    // Sort client-side by createdAt descending to avoid requiring composite indexes
    return projects.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  } catch (error) {
    console.warn('Firestore load projects note:', error);
    return [];
  }
}

export async function deleteProjectFromFirestore(userId: string, projectId: string): Promise<void> {
  try {
    const projectRef = doc(db, 'projects', projectId);
    await deleteDoc(projectRef);

    // Also clean up project sub-records (endpoints, vulnerabilities, scans)
    const collectionsToClean = ['endpoints', 'vulnerabilities', 'scans', 'apiSpecifications', 'reports'];
    for (const col of collectionsToClean) {
      const q = query(
        collection(db, col),
        where('projectId', '==', projectId),
        where('userId', '==', userId)
      );
      const snap = await getDocs(q);
      const deletePromises = snap.docs.map((d) => deleteDoc(d.ref));
      await Promise.all(deletePromises);
    }
  } catch (error) {
    console.error('Error deleting project from Firestore:', error);
    throw error;
  }
}

// =========================================================================
// 3. API SPECIFICATIONS COLLECTION
// =========================================================================
export async function saveApiSpecificationToFirestore(
  userId: string,
  projectId: string,
  spec: {
    title: string;
    version: string;
    description: string;
    baseUrl: string;
    rawSpec: string;
    format: 'json' | 'yaml';
    totalEndpoints: number;
    methodsCount: Record<string, number>;
    authTypes: string[];
  }
): Promise<string> {
  const specRef = doc(collection(db, 'apiSpecifications'));
  const specId = specRef.id;

  await setDoc(specRef, {
    id: specId,
    projectId,
    userId,
    title: spec.title,
    version: spec.version,
    description: spec.description,
    baseUrl: spec.baseUrl,
    rawSpec: spec.rawSpec,
    format: spec.format,
    totalEndpoints: spec.totalEndpoints,
    methodsCount: spec.methodsCount,
    authTypes: spec.authTypes,
    createdAt: new Date().toISOString(),
    createdTimestamp: serverTimestamp()
  });

  // Update total endpoints on project document
  const projectRef = doc(db, 'projects', projectId);
  await updateDoc(projectRef, {
    totalEndpoints: spec.totalEndpoints,
    updatedAt: serverTimestamp()
  });

  return specId;
}

export async function getProjectSpecificationFromFirestore(projectId: string, userId?: string): Promise<FirestoreApiSpec | null> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return null;

    const q = query(
      collection(db, 'apiSpecifications'),
      where('userId', '==', uid),
      where('projectId', '==', projectId)
    );
    const snap = await getDocs(q);
    if (snap.empty) return null;
    const docData = snap.docs[0].data();
    return {
      id: snap.docs[0].id,
      ...docData
    } as FirestoreApiSpec;
  } catch (error) {
    console.warn('Firestore fetch specification note:', error);
    return null;
  }
}

// =========================================================================
// 4. ENDPOINTS COLLECTION
// =========================================================================
export async function saveEndpointsToFirestore(
  userId: string,
  projectId: string,
  specId: string,
  endpointsList: ApiEndpoint[]
): Promise<void> {
  // First clear existing endpoints for this project to maintain exact synchronization
  try {
    const q = query(
      collection(db, 'endpoints'),
      where('userId', '==', userId),
      where('projectId', '==', projectId)
    );
    const existing = await getDocs(q);
    const deleteBatch = existing.docs.map((d) => deleteDoc(d.ref));
    await Promise.all(deleteBatch);

    // Save new endpoints
    const saveBatch = endpointsList.map((ep) => {
      const epRef = doc(collection(db, 'endpoints'));
      return setDoc(epRef, {
        id: epRef.id,
        endpointId: ep.id || epRef.id,
        projectId,
        userId,
        specId,
        path: ep.path,
        method: ep.method,
        summary: ep.summary || '',
        description: ep.description || '',
        requiresAuth: ep.requiresAuth || false,
        authType: ep.authType || null,
        riskLevel: ep.riskLevel || 'LOW',
        parameters: ep.parameters || [],
        requestBodySchema: ep.requestBodySchema || null,
        responseSchema: ep.responseSchema || null,
        status: ep.status || 'UNTESTED',
        findingsCount: ep.findingsCount || 0,
        createdAt: new Date().toISOString()
      });
    });

    await Promise.all(saveBatch);
  } catch (error) {
    console.warn('Firestore saving endpoints note:', error);
    throw error;
  }
}

export async function getProjectEndpointsFromFirestore(projectId: string, userId?: string): Promise<ApiEndpoint[]> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return [];

    const q = query(
      collection(db, 'endpoints'),
      where('userId', '==', uid),
      where('projectId', '==', projectId)
    );
    const snap = await getDocs(q);
    const endpoints: ApiEndpoint[] = [];
    snap.forEach((d) => {
      const data = d.data();
      endpoints.push({
        id: data.endpointId || d.id,
        path: data.path,
        method: data.method,
        summary: data.summary || '',
        description: data.description || '',
        requiresAuth: !!data.requiresAuth,
        authType: data.authType || undefined,
        riskLevel: data.riskLevel || 'LOW',
        parameters: data.parameters || [],
        requestBodySchema: data.requestBodySchema || undefined,
        responseSchema: data.responseSchema || undefined,
        findingsCount: data.findingsCount || 0,
        status: data.status || 'SCANNED'
      });
    });
    return endpoints;
  } catch (error) {
    console.warn('Firestore fetch endpoints note:', error);
    return [];
  }
}

// =========================================================================
// 5. SCANS COLLECTION
// =========================================================================
export async function createScanInFirestore(
  userId: string,
  projectId: string,
  scanResult: ScanResult
): Promise<string> {
  try {
    const scanRef = doc(collection(db, 'scans'));
    const scanDbId = scanRef.id;

    const scanRecord: FirestoreScanRecord = {
      id: scanDbId,
      scanId: scanResult.scanId,
      projectId,
      userId,
      status: 'COMPLETED',
      startedAt: scanResult.timestamp,
      completedAt: new Date().toISOString(),
      endpointsScanned: scanResult.totalEndpoints,
      securityScore: scanResult.score.currentScore,
      ratingGrade: scanResult.score.ratingGrade,
      criticalCount: scanResult.summary.critical,
      highCount: scanResult.summary.high,
      mediumCount: scanResult.summary.medium,
      lowCount: scanResult.summary.low,
      targetScope: scanResult.targetScope,
      createdAt: new Date().toISOString()
    };

    await setDoc(scanRef, {
      ...scanRecord,
      createdTimestamp: serverTimestamp()
    });

    // Save associated vulnerabilities
    await saveVulnerabilitiesToFirestore(
      userId,
      projectId,
      scanResult.scanId,
      scanResult.findings
    );

    // Update project latest stats
    const projectRef = doc(db, 'projects', projectId);
    await updateDoc(projectRef, {
      scansCount: (await getProjectScansFromFirestore(projectId)).length + 1,
      latestScore: scanResult.score.currentScore,
      latestRating: scanResult.score.ratingGrade,
      latestScan: {
        scanId: scanResult.scanId,
        status: 'COMPLETED',
        securityScore: scanResult.score.currentScore,
        ratingGrade: scanResult.score.ratingGrade,
        criticalCount: scanResult.summary.critical,
        highCount: scanResult.summary.high,
        mediumCount: scanResult.summary.medium,
        lowCount: scanResult.summary.low,
        completedAt: new Date().toISOString()
      },
      updatedAt: serverTimestamp()
    });

    return scanDbId;
  } catch (error) {
    console.error('Error creating scan in Firestore:', error);
    throw error;
  }
}

export async function getProjectScansFromFirestore(projectId: string, userId?: string): Promise<FirestoreScanRecord[]> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return [];

    const q = query(
      collection(db, 'scans'),
      where('userId', '==', uid),
      where('projectId', '==', projectId)
    );
    const snap = await getDocs(q);
    const scans: FirestoreScanRecord[] = [];
    snap.forEach((d) => {
      const data = d.data();
      scans.push({
        id: d.id,
        scanId: data.scanId || d.id,
        projectId: data.projectId,
        userId: data.userId,
        status: data.status,
        startedAt: data.startedAt,
        completedAt: data.completedAt,
        endpointsScanned: data.endpointsScanned || 0,
        securityScore: data.securityScore ?? 100,
        ratingGrade: data.ratingGrade || 'A',
        criticalCount: data.criticalCount || 0,
        highCount: data.highCount || 0,
        mediumCount: data.mediumCount || 0,
        lowCount: data.lowCount || 0,
        targetScope: data.targetScope,
        createdAt: data.createdAt
      });
    });
    return scans.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  } catch (error) {
    console.warn('Firestore fetch scans note:', error);
    return [];
  }
}

// =========================================================================
// 6. VULNERABILITIES COLLECTION
// =========================================================================
export async function saveVulnerabilitiesToFirestore(
  userId: string,
  projectId: string,
  scanId: string,
  findings: VulnerabilityFinding[]
): Promise<void> {
  try {
    const saveBatch = findings.map((f) => {
      const vulnRef = doc(collection(db, 'vulnerabilities'));
      return setDoc(vulnRef, {
        id: vulnRef.id,
        vulnId: f.id,
        userId,
        projectId,
        scanId,
        endpoint: f.endpoint,
        method: f.method,
        title: f.title,
        category: f.category,
        owaspCategory: f.owaspCategory || '',
        severity: f.severity,
        description: f.description,
        evidence: f.evidence,
        reproduction: f.reproduction,
        impact: f.impact,
        remediation: f.remediation,
        aiExplanation: f.aiExplanation || null,
        status: f.status || 'OPEN',
        detectedAt: f.detectedAt,
        createdAt: new Date().toISOString()
      });
    });

    await Promise.all(saveBatch);
  } catch (error) {
    console.warn('Firestore saving vulnerabilities note:', error);
    throw error;
  }
}

export async function getProjectVulnerabilitiesFromFirestore(
  projectId: string,
  userId?: string,
  scanId?: string
): Promise<VulnerabilityFinding[]> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return [];

    let q = query(
      collection(db, 'vulnerabilities'),
      where('userId', '==', uid),
      where('projectId', '==', projectId)
    );

    if (scanId) {
      q = query(
        collection(db, 'vulnerabilities'),
        where('userId', '==', uid),
        where('projectId', '==', projectId),
        where('scanId', '==', scanId)
      );
    }

    const snap = await getDocs(q);
    const vulns: VulnerabilityFinding[] = [];
    snap.forEach((d) => {
      const data = d.data();
      vulns.push({
        id: data.vulnId || d.id,
        title: data.title,
        category: data.category,
        severity: data.severity,
        owaspCategory: data.owaspCategory || '',
        endpoint: data.endpoint,
        method: data.method,
        description: data.description,
        evidence: data.evidence,
        reproduction: data.reproduction,
        impact: data.impact,
        remediation: data.remediation,
        aiExplanation: data.aiExplanation || undefined,
        status: data.status || 'OPEN',
        detectedAt: data.detectedAt || new Date().toISOString()
      });
    });

    return vulns;
  } catch (error) {
    console.warn('Firestore fetch vulnerabilities note:', error);
    return [];
  }
}

export async function updateVulnerabilityStatusInFirestore(
  userId: string,
  vulnId: string,
  status: 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'IN_REVIEW'
): Promise<void> {
  try {
    const q = query(
      collection(db, 'vulnerabilities'),
      where('userId', '==', userId),
      where('vulnId', '==', vulnId)
    );
    const snap = await getDocs(q);
    if (!snap.empty) {
      await updateDoc(snap.docs[0].ref, {
        status,
        updatedAt: serverTimestamp()
      });
    }
  } catch (error) {
    console.error('Error updating vulnerability in Firestore:', error);
  }
}

// =========================================================================
// 7. SCAN REQUESTS COLLECTION
// =========================================================================
export async function logScanRequestInFirestore(
  userId: string,
  projectId: string,
  requestDetails: {
    targetScope: string;
    baseUrl: string;
    authorizationConfirmed: boolean;
    endpointsCount: number;
  }
): Promise<string> {
  try {
    const reqRef = doc(collection(db, 'scanRequests'));
    await setDoc(reqRef, {
      id: reqRef.id,
      userId,
      projectId,
      targetScope: requestDetails.targetScope,
      baseUrl: requestDetails.baseUrl,
      authorizationConfirmed: requestDetails.authorizationConfirmed,
      endpointsCount: requestDetails.endpointsCount,
      requestedAt: new Date().toISOString(),
      timestamp: serverTimestamp()
    });
    return reqRef.id;
  } catch (error) {
    console.error('Error logging scan request to Firestore:', error);
    return '';
  }
}

// =========================================================================
// 8. REPORTS COLLECTION
// =========================================================================
export async function saveReportToFirestore(
  userId: string,
  projectId: string,
  scanId: string,
  reportData: {
    title: string;
    apiName: string;
    apiVersion: string;
    securityScore: number;
    ratingGrade: string;
    totalEndpoints: number;
    findingsSummary: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    findings: any[];
  }
): Promise<string> {
  try {
    const repRef = doc(collection(db, 'reports'));
    const report: FirestoreReport = {
      id: repRef.id,
      userId,
      projectId,
      scanId,
      title: reportData.title,
      apiName: reportData.apiName,
      apiVersion: reportData.apiVersion,
      securityScore: reportData.securityScore,
      ratingGrade: reportData.ratingGrade,
      totalEndpoints: reportData.totalEndpoints,
      findingsSummary: reportData.findingsSummary,
      findings: reportData.findings,
      generatedAt: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    await setDoc(repRef, {
      ...report,
      createdTimestamp: serverTimestamp()
    });

    return repRef.id;
  } catch (error) {
    console.error('Error saving report to Firestore:', error);
    throw error;
  }
}

export async function getProjectReportsFromFirestore(projectId: string, userId?: string): Promise<FirestoreReport[]> {
  try {
    const uid = userId || auth.currentUser?.uid;
    if (!uid) return [];

    const q = query(
      collection(db, 'reports'),
      where('userId', '==', uid),
      where('projectId', '==', projectId)
    );
    const snap = await getDocs(q);
    const reports: FirestoreReport[] = [];
    snap.forEach((d) => {
      reports.push(d.data() as FirestoreReport);
    });
    return reports.sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());
  } catch (error) {
    console.warn('Firestore fetch reports note:', error);
    return [];
  }
}
