import { relations } from 'drizzle-orm';
import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex
} from 'drizzle-orm/pg-core';

// 1. Users Table
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(), // Firebase Auth UID
  email: text('email').notNull(),
  passwordHash: text('password_hash'),
  displayName: text('display_name'),
  photoUrl: text('photo_url'),
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => ({
  emailUnique: uniqueIndex('users_email_unique').on(table.email)
}));

// 2. Projects Table
export const projects = pgTable('projects', {
  id: serial('id').primaryKey(),
  userId: integer('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  name: text('name').notNull(),
  description: text('description'),
  apiUrl: text('api_url'),
  isDemo: boolean('is_demo').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull()
});

// 3. API Specs Table
export const apiSpecs = pgTable('api_specs', {
  id: serial('id').primaryKey(),
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  title: text('title').notNull(),
  version: text('version').notNull(),
  description: text('description'),
  baseUrl: text('base_url'),
  format: text('format').default('json').notNull(), // 'json' | 'yaml'
  rawSpec: text('raw_spec').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull()
});

// 4. Endpoints Table
export const endpoints = pgTable('endpoints', {
  id: serial('id').primaryKey(),
  apiSpecId: integer('api_spec_id')
    .references(() => apiSpecs.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  path: text('path').notNull(),
  method: text('method').notNull(),
  summary: text('summary'),
  authenticationRequired: boolean('authentication_required').default(false).notNull(),
  parameters: text('parameters'), // JSON string
  requestSchema: text('request_schema'), // JSON string
  responseSchema: text('response_schema'), // JSON string
  riskLevel: text('risk_level').default('LOW').notNull(), // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  createdAt: timestamp('created_at').defaultNow().notNull()
});

// 5. Scans Table
export const scans = pgTable('scans', {
  id: serial('id').primaryKey(),
  scanId: text('scan_id').notNull().unique(), // e.g. SCAN-xxxx
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  userId: integer('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  status: text('status').default('QUEUED').notNull(), // 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  securityScore: integer('security_score').default(100).notNull(),
  ratingGrade: text('rating_grade').default('A').notNull(),
  totalEndpoints: integer('total_endpoints').default(0).notNull(),
  endpointsScanned: integer('endpoints_scanned').default(0).notNull(),
  criticalCount: integer('critical_count').default(0).notNull(),
  highCount: integer('high_count').default(0).notNull(),
  mediumCount: integer('medium_count').default(0).notNull(),
  lowCount: integer('low_count').default(0).notNull(),
  durationSeconds: integer('duration_seconds').default(0).notNull(),
  startedAt: timestamp('started_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at')
});

export const sessions = pgTable('sessions', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  tokenHash: text('token_hash').notNull().unique(),
  expiresAt: timestamp('expires_at').notNull(),
  revokedAt: timestamp('revoked_at'),
  createdAt: timestamp('created_at').defaultNow().notNull()
});

// 6. Vulnerabilities Table
export const vulnerabilities = pgTable('vulnerabilities', {
  id: serial('id').primaryKey(),
  vulnId: text('vuln_id').notNull(), // e.g. VULN-BOLA-xxxx
  scanId: integer('scan_id')
    .references(() => scans.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  endpointId: integer('endpoint_id').references(() => endpoints.id, { onDelete: 'set null' }),
  title: text('title').notNull(),
  category: text('category').notNull(),
  severity: text('severity').notNull(), // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  owaspCategory: text('owasp_category'),
  endpoint: text('endpoint').notNull(),
  method: text('method').notNull(),
  description: text('description').notNull(),
  evidence: text('evidence').notNull(),
  reproduction: text('reproduction').notNull(), // JSON string
  impact: text('impact').notNull(),
  remediation: text('remediation').notNull(), // JSON string
  aiExplanation: text('ai_explanation'),
  status: text('status').default('OPEN').notNull(), // 'OPEN' | 'RESOLVED'
  detectedAt: timestamp('detected_at').defaultNow().notNull()
});

// 7. Scan Requests Table
export const scanRequests = pgTable('scan_requests', {
  id: serial('id').primaryKey(),
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  scanId: integer('scan_id').references(() => scans.id, { onDelete: 'set null' }),
  requestedBy: text('requested_by').notNull(),
  targetUrl: text('target_url').notNull(),
  authorizedConfirmed: boolean('authorized_confirmed').default(true).notNull(),
  status: text('status').default('PENDING').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull()
});

// 8. Reports Table
export const reports = pgTable('reports', {
  id: serial('id').primaryKey(),
  projectId: integer('project_id')
    .references(() => projects.id, { onDelete: 'cascade' })
    .notNull(),
  scanId: integer('scan_id')
    .references(() => scans.id, { onDelete: 'cascade' })
    .notNull(),
  title: text('title').notNull(),
  reportData: text('report_data').notNull(), // JSON string
  generatedAt: timestamp('generated_at').defaultNow().notNull()
});

// 9. Notifications Table
export const notifications = pgTable('notifications', {
  id: serial('id').primaryKey(),
  userId: integer('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  projectId: integer('project_id').references(() => projects.id, { onDelete: 'cascade' }),
  title: text('title').notNull(),
  message: text('message').notNull(),
  type: text('type').default('INFO').notNull(), // 'INFO' | 'WARNING' | 'ALERT'
  isRead: boolean('is_read').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull()
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  projects: many(projects),
  notifications: many(notifications)
}));

export const projectsRelations = relations(projects, ({ one, many }) => ({
  user: one(users, {
    fields: [projects.userId],
    references: [users.id]
  }),
  apiSpecs: many(apiSpecs),
  endpoints: many(endpoints),
  scans: many(scans),
  vulnerabilities: many(vulnerabilities),
  scanRequests: many(scanRequests),
  reports: many(reports)
}));

export const apiSpecsRelations = relations(apiSpecs, ({ one, many }) => ({
  project: one(projects, {
    fields: [apiSpecs.projectId],
    references: [projects.id]
  }),
  endpoints: many(endpoints)
}));

export const endpointsRelations = relations(endpoints, ({ one, many }) => ({
  apiSpec: one(apiSpecs, {
    fields: [endpoints.apiSpecId],
    references: [apiSpecs.id]
  }),
  project: one(projects, {
    fields: [endpoints.projectId],
    references: [projects.id]
  }),
  vulnerabilities: many(vulnerabilities)
}));

export const scansRelations = relations(scans, ({ one, many }) => ({
  project: one(projects, {
    fields: [scans.projectId],
    references: [projects.id]
  }),
  user: one(users, { fields: [scans.userId], references: [users.id] }),
  vulnerabilities: many(vulnerabilities),
  reports: many(reports),
  scanRequests: many(scanRequests)
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, { fields: [sessions.userId], references: [users.id] })
}));

export const vulnerabilitiesRelations = relations(vulnerabilities, ({ one }) => ({
  scan: one(scans, {
    fields: [vulnerabilities.scanId],
    references: [scans.id]
  }),
  project: one(projects, {
    fields: [vulnerabilities.projectId],
    references: [projects.id]
  }),
  endpoint: one(endpoints, {
    fields: [vulnerabilities.endpointId],
    references: [endpoints.id]
  })
}));

export const scanRequestsRelations = relations(scanRequests, ({ one }) => ({
  project: one(projects, {
    fields: [scanRequests.projectId],
    references: [projects.id]
  }),
  scan: one(scans, {
    fields: [scanRequests.scanId],
    references: [scans.id]
  })
}));

export const reportsRelations = relations(reports, ({ one }) => ({
  project: one(projects, {
    fields: [reports.projectId],
    references: [projects.id]
  }),
  scan: one(scans, {
    fields: [reports.scanId],
    references: [scans.id]
  })
}));

export const notificationsRelations = relations(notifications, ({ one }) => ({
  user: one(users, {
    fields: [notifications.userId],
    references: [users.id]
  }),
  project: one(projects, {
    fields: [notifications.projectId],
    references: [projects.id]
  })
}));
