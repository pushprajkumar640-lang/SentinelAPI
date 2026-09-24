export interface SandboxOrder {
  orderId: string;
  ownerUserId: string;
  customerName: string;
  items: Array<{ item: string; qty: number; price: number }>;
  totalAmount: number;
  deliveryAddress: string;
  paymentMethod: string;
  status: 'PENDING' | 'PREPARING' | 'DELIVERED' | 'CANCELLED';
  createdAt: string;
}

export interface SandboxUser {
  id: number;
  username: string;
  name: string;
  email: string;
  phone: string;
  role: 'CUSTOMER' | 'DRIVER' | 'ADMIN';
  // Sensitive/Excessive fields returned in vulnerable sandbox testbed:
  passwordHash: string;
  internalNotes: string;
  ssnLast4: string;
  stripeCustomerId: string;
  mfaSecret: string;
  creditRating: number;
}

export interface SandboxConfig {
  enforceBolaCheck: boolean;
  maskSensitiveFields: boolean;
  enableRateLimit: boolean;
  requireAdminAuth: boolean;
}

export const sandboxConfig: SandboxConfig = {
  enforceBolaCheck: false,
  maskSensitiveFields: false,
  enableRateLimit: false,
  requireAdminAuth: false
};

export function getSandboxConfig(): SandboxConfig {
  return { ...sandboxConfig };
}

export function updateSandboxConfig(updates: Partial<SandboxConfig>): SandboxConfig {
  Object.assign(sandboxConfig, updates);
  return { ...sandboxConfig };
}

export function resetSandboxConfig(): SandboxConfig {
  sandboxConfig.enforceBolaCheck = false;
  sandboxConfig.maskSensitiveFields = false;
  sandboxConfig.enableRateLimit = false;
  sandboxConfig.requireAdminAuth = false;
  return { ...sandboxConfig };
}

export const SANDBOX_USERS: Record<string, SandboxUser> = {
  '101': {
    id: 101,
    username: 'user_a',
    name: 'Rahul Sharma',
    email: 'rahul@demo.internal',
    phone: '+1-555-0199',
    role: 'CUSTOMER',
    passwordHash: '$2b$12$e8x4k2LPp8qH4vj4zL50ke7XjKl8q71N00a4P7h4H9K',
    internalNotes: 'VIP client; risk score tier 0; high lifetime value',
    ssnLast4: '8842',
    stripeCustomerId: 'cus_N924ka82Xop19',
    mfaSecret: 'JBSWY3DPEHPK3PXP',
    creditRating: 780,
  },
  '102': {
    id: 102,
    username: 'user_b',
    name: 'Elena Rostova',
    email: 'elena@demo.internal',
    phone: '+1-555-0248',
    role: 'CUSTOMER',
    passwordHash: '$2b$12$W91KxP72zVl9a1p43XyZ.eKmJ8q23P01Nm4K8h1Q8L',
    internalNotes: 'Account flagged for suspicious refund pattern 2 weeks ago',
    ssnLast4: '3195',
    stripeCustomerId: 'cus_M812la91Zqw33',
    mfaSecret: 'K4SWY3DPEHPK4AAA',
    creditRating: 640,
  }
};

export const SANDBOX_ORDERS: Record<string, SandboxOrder> = {
  '1001': {
    orderId: '1001',
    ownerUserId: 'user_a',
    customerName: 'Rahul Sharma (User A)',
    items: [
      { item: 'Artisan Sourdough Margherita Pizza', qty: 1, price: 18.50 },
      { item: 'Sparkling Mineral Water (San Pellegrino)', qty: 2, price: 5.75 }
    ],
    totalAmount: 30.00,
    deliveryAddress: '120 Market St, Suite 4B, San Francisco, CA',
    paymentMethod: 'Visa ending in 4242',
    status: 'DELIVERED',
    createdAt: '2026-09-24T06:30:00Z'
  },
  '1002': {
    orderId: '1002',
    ownerUserId: 'user_b',
    customerName: 'Elena Rostova (User B)',
    items: [
      { item: 'Spicy Truffle Ramen Bowl', qty: 2, price: 34.00 },
      { item: 'Steamed Pork Gyoza', qty: 1, price: 9.50 },
      { item: 'Matcha Green Tea Gelato', qty: 1, price: 5.00 }
    ],
    totalAmount: 48.50,
    deliveryAddress: '742 Evergreen Terrace, Springfield, OR',
    paymentMethod: 'Mastercard ending in 9182',
    status: 'DELIVERED',
    createdAt: '2026-09-24T06:45:00Z'
  }
};

export const SANDBOX_ADMIN_STAFF = [
  { id: 'adm_01', role: 'SUPERADMIN', name: 'DevOps Security Lead', email: 'sysadmin@internal.test', accessLevel: 5 },
  { id: 'adm_02', role: 'SUPPORT_LEAD', name: 'Customer Escalations Mgr', email: 'helpdesk@internal.test', accessLevel: 3 },
  { id: 'adm_03', role: 'BILLING_AUDITOR', name: 'Finance Controller', email: 'billing@internal.test', accessLevel: 4 }
];

// Helper to resolve test user token to identity
export function extractSandboxUserFromToken(authHeader?: string): { userId: string; role: string } | null {
  if (!authHeader) return null;
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token.includes('user_b')) {
    return { userId: 'user_b', role: 'CUSTOMER' };
  }
  if (token.includes('admin')) {
    return { userId: 'admin_1', role: 'ADMIN' };
  }
  if (token.includes('user_a') || token.length > 5) {
    return { userId: 'user_a', role: 'CUSTOMER' };
  }
  return null;
}
