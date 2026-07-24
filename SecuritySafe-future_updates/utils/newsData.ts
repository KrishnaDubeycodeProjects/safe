import type { NewsItem } from './types';

export const newsItems: NewsItem[] = [
  {
    id: 'news-001',
    title: 'Fake KYC SMS Campaign Targeting SBI Customers',
    summary: 'Massive SMS campaign pretending to be from SBI asking customers to update KYC via fake link. Over 500 complaints reported in 24 hours.',
    type: 'alert',
    severity: 'CRITICAL',
    date: '2025-12-23',
    source: 'SAFE Intelligence',
    involvedStates: ['Maharashtra', 'Delhi', 'Karnataka', 'Tamil Nadu'],
    involvedBanks: ['SBI'],
  },
  {
    id: 'news-002',
    title: 'New QR Scam on OLX and Marketplace Apps',
    summary: 'Scammers posing as buyers send QR codes for "payment". Scanning deducts money from your account instead. Spread across 15 states.',
    type: 'alert',
    severity: 'HIGH',
    date: '2025-12-22',
    source: 'Ministry of Home Affairs',
    involvedStates: ['All India'],
  },
  {
    id: 'news-003',
    title: 'Government Warns Against Fake Loan Apps',
    summary: 'RBI and CERT-In issue joint advisory against 34 fake loan apps that steal data and blackmail users.',
    type: 'advisory',
    severity: 'CRITICAL',
    date: '2025-12-20',
    source: 'RBI / CERT-In',
    involvedStates: ['All India'],
  },
  {
    id: 'news-004',
    title: 'Deepfake Scam: Fraudsters Impersonate Company CEOs',
    summary: 'New deepfake audio/video scam where fraudsters use AI to replicate executive voices and authorize fake fund transfers.',
    type: 'trend',
    severity: 'HIGH',
    date: '2025-12-19',
    source: 'SAFE Research',
  },
  {
    id: 'news-005',
    title: 'Weekly Safety Tip: Never Share UPI PIN',
    summary: 'UPI PIN is the master key to your bank account. No genuine person or organization will ever ask for it.',
    type: 'tip',
    date: '2025-12-18',
    source: 'SAFE',
  },
  {
    id: 'news-006',
    title: 'Telecom Scam: Fake SIM Replacement Requests',
    summary: 'Fraudsters call pretending to be from Jio/Airtel/VI, claim SIM needs replacement, ask for OTP to swap SIM.',
    type: 'alert',
    severity: 'HIGH',
    date: '2025-12-17',
    source: 'DoT (Department of Telecommunications)',
    involvedStates: ['Maharashtra', 'Gujarat', 'Rajasthan', 'Uttar Pradesh'],
  },
  {
    id: 'news-007',
    title: 'Investment Fraud Network Busted in Hyderabad',
    summary: 'Cyderabad Cyber Crime Police arrest 12 people running a fake investment scheme promising 20% monthly returns. 4,000+ victims identified.',
    type: 'report',
    severity: 'MEDIUM',
    date: '2025-12-16',
    source: 'Telangana Police',
    involvedStates: ['Telangana'],
  },
  {
    id: 'news-008',
    title: 'India Post Warns About Fake Customs Fee Messages',
    summary: 'India Post issues clarification that they never send SMS asking for customs fee payments through links.',
    type: 'advisory',
    severity: 'MEDIUM',
    date: '2025-12-15',
    source: 'India Post',
  },
  {
    id: 'news-009',
    title: 'Cyber Fraud Losses Cross ₹10,000 Crore in 2025',
    summary: 'Annual cyber fraud report shows 40% increase in digital arrest scams, UPI fraud, and investment scams.',
    type: 'report',
    date: '2025-12-14',
    source: 'National Cyber Crime Reporting Portal',
  },
  {
    id: 'news-010',
    title: 'How to Identify a Fake Customer Care Number',
    summary: 'Tip: Always verify customer care numbers from the official website. Google search results can show fake numbers promoted as ads.',
    type: 'tip',
    date: '2025-12-13',
    source: 'SAFE',
  },
];

export function getBreakingAlerts(): NewsItem[] {
  return newsItems.filter((item) => item.type === 'alert' && item.severity === 'CRITICAL');
}

export function getNewsByType(type: NewsItem['type']): NewsItem[] {
  return newsItems.filter((item) => item.type === type);
}

export function getLatestNews(count: number = 5): NewsItem[] {
  return [...newsItems]
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
    .slice(0, count);
}
