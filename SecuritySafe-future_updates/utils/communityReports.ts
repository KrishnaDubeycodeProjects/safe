import type { CommunityReport } from './types';

export const communityReports: CommunityReport[] = [
  {
    id: 'cr-001',
    type: 'scam_number',
    value: '+917888912345',
    description: 'Caller said they are from SBI and my account will be blocked. Asked for OTP.',
    state: 'Maharashtra',
    city: 'Mumbai',
    timestamp: '2025-12-22T14:30:00Z',
    status: 'verified',
    upvotes: 45,
    downvotes: 2,
  },
  {
    id: 'cr-002',
    type: 'scam_website',
    value: 'axis-kyc.com',
    description: 'Received SMS asking to update KYC. Website looks exactly like Axis Bank.',
    state: 'Delhi',
    city: 'New Delhi',
    timestamp: '2025-12-22T10:15:00Z',
    status: 'verified',
    upvotes: 32,
    downvotes: 1,
  },
  {
    id: 'cr-003',
    type: 'scam_message',
    value: 'Your package is held at customs. Pay ₹25 to release.',
    description: 'Fake India Post delivery scam message. I was not expecting any package.',
    state: 'Karnataka',
    city: 'Bengaluru',
    timestamp: '2025-12-21T18:45:00Z',
    status: 'verified',
    upvotes: 28,
    downvotes: 0,
  },
  {
    id: 'cr-004',
    type: 'fake_job',
    value: 'Work from home - ₹50k/month',
    description: 'WhatsApp group offering data entry job. Asking ₹1500 for registration.',
    state: 'Uttar Pradesh',
    city: 'Lucknow',
    timestamp: '2025-12-21T09:20:00Z',
    status: 'verified',
    upvotes: 56,
    downvotes: 3,
  },
  {
    id: 'cr-005',
    type: 'investment_fraud',
    value: 'Stock Guru Pro Telegram Group',
    description: 'Guaranteed 20% monthly returns. Fake profit screenshots shared daily.',
    state: 'Gujarat',
    city: 'Ahmedabad',
    timestamp: '2025-12-20T16:00:00Z',
    status: 'verified',
    upvotes: 41,
    downvotes: 1,
  },
  {
    id: 'cr-006',
    type: 'qr_scam',
    value: 'QR code shared on OLX',
    description: 'Buyer asked me to scan QR to receive payment. Instead ₹5000 was deducted.',
    state: 'Tamil Nadu',
    city: 'Chennai',
    timestamp: '2025-12-20T11:30:00Z',
    status: 'pending',
    upvotes: 67,
    downvotes: 2,
  },
  {
    id: 'cr-007',
    type: 'social_scam',
    value: 'Instagram: @urgent_loan_provider',
    description: 'Fake instant loan provider. Asks for advance fee for loan processing.',
    state: 'West Bengal',
    city: 'Kolkata',
    timestamp: '2025-12-19T14:10:00Z',
    status: 'pending',
    upvotes: 23,
    downvotes: 0,
  },
  {
    id: 'cr-008',
    type: 'scam_number',
    value: '+918000123456',
    description: 'Fake Amazon customer care. Said my account is hacked and asked for remote access.',
    state: 'Rajasthan',
    city: 'Jaipur',
    timestamp: '2025-12-18T20:00:00Z',
    status: 'verified',
    upvotes: 39,
    downvotes: 1,
  },
  {
    id: 'cr-009',
    type: 'scam_website',
    value: 'flipkart-offer.in',
    description: 'SMS about winning Flipkart lucky draw. Link asks for card details for "verification".',
    state: 'Punjab',
    city: 'Chandigarh',
    timestamp: '2025-12-18T08:45:00Z',
    status: 'pending',
    upvotes: 18,
    downvotes: 0,
  },
  {
    id: 'cr-010',
    type: 'investment_fraud',
    value: 'CryptoKing Mining Platform',
    description: 'Promised daily 5% returns on crypto mining investment. Website shut down after 2 months.',
    state: 'Telangana',
    city: 'Hyderabad',
    timestamp: '2025-12-17T15:30:00Z',
    status: 'pending',
    upvotes: 34,
    downvotes: 1,
  },
];

export function getRecentReports(count: number = 10): CommunityReport[] {
  return [...communityReports]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, count);
}

export function getReportsByState(state: string): CommunityReport[] {
  return communityReports.filter(
    (r) => r.state?.toLowerCase() === state.toLowerCase()
  );
}

export function getVerifiedCount(): number {
  return communityReports.filter((r) => r.status === 'verified').length;
}

export function getTotalReportsByType(): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const report of communityReports) {
    counts[report.type] = (counts[report.type] || 0) + 1;
  }
  return counts;
}

export function getHotReports(threshold: number = 30): CommunityReport[] {
  return communityReports.filter((r) => r.upvotes >= threshold);
}
