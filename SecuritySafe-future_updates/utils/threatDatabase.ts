import type { ThreatDatabaseEntry } from './types';

export const threatDatabase: ThreatDatabaseEntry[] = [
  {
    id: 'td-001',
    type: 'url',
    value: 'axis-kyc.com',
    threatType: 'KYC Scam',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 1542,
    firstReported: '2024-01-15',
    lastReported: '2025-12-20',
    description: 'Fake Axis Bank KYC update page that steals login credentials and debit card details.',
    tags: ['banking', 'phishing', 'kyc', 'axis-bank'],
  },
  {
    id: 'td-002',
    type: 'url',
    value: 'sbi-secure.net',
    threatType: 'Bank Fraud',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 2341,
    firstReported: '2024-03-10',
    lastReported: '2025-12-22',
    description: 'Phishing website mimicking SBI internet banking. Steals user IDs, passwords, and OTPs.',
    tags: ['banking', 'phishing', 'sbi', 'internet-banking'],
  },
  {
    id: 'td-003',
    type: 'phone',
    value: '+918000123456',
    threatType: 'Customer Care Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 892,
    firstReported: '2024-06-01',
    lastReported: '2025-12-18',
    description: 'Fake Amazon customer care number. Fraudsters ask for remote access to "refund" money.',
    tags: ['customer-care', 'amazon', 'refund-scam', 'remote-access'],
  },
  {
    id: 'td-004',
    type: 'phone',
    value: '+917888912345',
    threatType: 'OTP Scam',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 3102,
    firstReported: '2024-02-14',
    lastReported: '2025-12-23',
    description: 'Fake SBI employee calling for OTP verification. Claims account will be blocked.',
    tags: ['banking', 'otp', 'sbi', 'impersonation'],
  },
  {
    id: 'td-005',
    type: 'whatsapp',
    value: '+919876543210',
    threatType: 'Job Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 1567,
    firstReported: '2024-04-20',
    lastReported: '2025-12-19',
    description: 'Fake work-from-home job offer. Asks for registration fee of ₹999.',
    tags: ['job-scam', 'whatsapp', 'work-from-home', 'registration-fee'],
  },
  {
    id: 'td-006',
    type: 'url',
    value: 'indi-post.com',
    threatType: 'Delivery Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 2103,
    firstReported: '2024-05-12',
    lastReported: '2025-12-21',
    description: 'Fake India Post website asking for customs fee payment. Steals card details.',
    tags: ['delivery', 'india-post', 'customs-fee', 'phishing'],
  },
  {
    id: 'td-007',
    type: 'url',
    value: 'hdfc-verify.com',
    threatType: 'KYC Scam',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 1876,
    firstReported: '2024-03-28',
    lastReported: '2025-12-22',
    description: 'Fake HDFC KYC update portal. Captures net banking credentials and phone number.',
    tags: ['banking', 'kyc', 'hdfc', 'phishing'],
  },
  {
    id: 'td-008',
    type: 'phone',
    value: '+919899988877',
    threatType: 'Investment Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 654,
    firstReported: '2024-07-05',
    lastReported: '2025-12-17',
    description: 'Fake investment advisor promising 10% monthly returns. Part of a ponzi scheme.',
    tags: ['investment', 'ponzi', 'stock-market', 'whatsapp-group'],
  },
  {
    id: 'td-009',
    type: 'url',
    value: 'lottery-winner.in',
    threatType: 'Lottery Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 987,
    firstReported: '2024-08-15',
    lastReported: '2025-12-15',
    description: 'Fake lottery website. Claims you won ₹25 lakhs but asks for processing fee.',
    tags: ['lottery', 'prize', 'processing-fee', 'phishing'],
  },
  {
    id: 'td-010',
    type: 'app',
    value: 'QuickLoan India',
    threatType: 'Loan Scam',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 4123,
    firstReported: '2024-09-01',
    lastReported: '2025-12-23',
    description: 'Fake loan app that steals contacts, photos, and threatens borrowers publicly.',
    tags: ['loan-app', 'harassment', 'data-theft', 'rbio-violation'],
  },
  {
    id: 'td-011',
    type: 'qr',
    value: 'UPI QR - Flipkart Payment',
    threatType: 'QR Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 534,
    firstReported: '2024-10-10',
    lastReported: '2025-12-20',
    description: 'Fake QR code shared by "buyer" on OLX. Scanning makes payment from your account.',
    tags: ['qr-scam', 'olx', 'reverse-qr', 'upi'],
  },
  {
    id: 'td-012',
    type: 'wallet',
    value: '0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B',
    threatType: 'Crypto Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 234,
    firstReported: '2024-11-05',
    lastReported: '2025-12-18',
    description: 'Fake crypto investment wallet address used in a ponzi scheme promising Bitcoin returns.',
    tags: ['crypto', 'bitcoin', 'ponzi', 'wallet'],
  },
  {
    id: 'td-013',
    type: 'url',
    value: 'govt-subsidy.site',
    threatType: 'Government Impersonation',
    severity: 'CRITICAL',
    status: 'confirmed',
    reportCount: 3421,
    firstReported: '2024-04-01',
    lastReported: '2025-12-23',
    description: 'Fake government subsidy portal. Steals Aadhaar, PAN, and bank account details.',
    tags: ['government', 'subsidy', 'aadhaar', 'pan', 'phishing'],
  },
  {
    id: 'td-014',
    type: 'phone',
    value: '+918888877766',
    threatType: 'SIM Swap',
    severity: 'CRITICAL',
    status: 'investigating',
    reportCount: 178,
    firstReported: '2025-11-20',
    lastReported: '2025-12-23',
    description: 'Caller impersonates telecom operator, claims SIM needs replacement, asks for OTP.',
    tags: ['sim-swap', 'telecom', 'otp', 'identity-theft'],
  },
  {
    id: 'td-015',
    type: 'social_profile',
    value: 'Neha Sharma Investment Expert',
    threatType: 'Investment Scam',
    severity: 'HIGH',
    status: 'confirmed',
    reportCount: 892,
    firstReported: '2024-06-15',
    lastReported: '2025-12-21',
    description: 'Fake Instagram profile pretending to be a stock market expert. Promises guaranteed returns.',
    tags: ['social-media', 'instagram', 'investment', 'influencer-scam'],
  },
];

export function searchDatabase(query: string): ThreatDatabaseEntry[] {
  const lower = query.toLowerCase();
  return threatDatabase.filter(
    (entry) =>
      entry.value.toLowerCase().includes(lower) ||
      entry.description.toLowerCase().includes(lower) ||
      entry.threatType.toLowerCase().includes(lower) ||
      entry.tags.some((t) => t.includes(lower))
  );
}

export function getThreatsByType(type: ThreatDatabaseEntry['type']): ThreatDatabaseEntry[] {
  return threatDatabase.filter((entry) => entry.type === type);
}

export function getCriticalThreats(): ThreatDatabaseEntry[] {
  return threatDatabase.filter((entry) => entry.severity === 'CRITICAL' && entry.status === 'confirmed');
}

export function getRecentThreats(days: number = 7): ThreatDatabaseEntry[] {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  return threatDatabase.filter((entry) => new Date(entry.lastReported) >= cutoff);
}
