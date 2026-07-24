
export type Verdict = 'DANGEROUS' | 'SUSPICIOUS' | 'SAFE';

export interface ScanResult {
  type: InputType;
  threatType: ThreatCategory;
  score: number;
  verdict: Verdict;
  reason: string;
  actionSteps: string[];
  detailedAnalysis?: string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  source?: string;
}


export interface FraudCategory {
  id: string;
  title: string;
  icon: string;
  description: string;
  /** ids of LearnFraudType entries in this category, in display order */
  fraudTypeIds: string[];
}

export interface ThreatDatabaseEntry {
  id: string;
  type: 'phone' | 'url' | 'domain' | 'whatsapp' | 'email' | 'qr' | 'app' | 'wallet' | 'social_profile';
  value: string;
  threatType: ThreatCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'confirmed' | 'reported' | 'investigating' | 'resolved';
  reportCount: number;
  firstReported: string;
  lastReported: string;
  description: string;
  tags: string[];
}

export interface CommunityReport {
  id: string;
  type: 'scam_number' | 'scam_website' | 'scam_message' | 'fake_job' | 'investment_fraud' | 'qr_scam' | 'social_scam';
  value: string;
  description: string;
  reporterName?: string;
  state?: string;
  city?: string;
  timestamp: string;
  status: 'pending' | 'verified' | 'dismissed';
  upvotes: number;
  downvotes: number;
}

export interface SafeScoreData {
  overall: number;
  previousMonth?: number;
  categories: {
    passwordStrength: number;
    fraudAwareness: number;
    threatReports: number;
    securitySettings: number;
    learningCompletion: number;
    accountSecurity: number;
    riskExposure: number;
  };
  suggestions: string[];
  rating: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL';
}

export interface CheckupItem {
  id: string;
  category: 'passwords' | 'accounts' | '2fa' | 'email_exposure' | 'phone_exposure' | 'app_permissions' | 'social_media' | 'financial_safety';
  title: string;
  description: string;
  status: 'secure' | 'at_risk' | 'action_needed' | 'unknown';
  recommendation: string;
  severity: 'low' | 'medium' | 'high';
  icon: string;
}

export interface NewsItem {
  id: string;
  title: string;
  summary: string;
  type: 'alert' | 'advisory' | 'tip' | 'trend' | 'report';
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  date: string;
  source: string;
  link?: string;
  involvedStates?: string[];
  involvedBanks?: string[];
}

export interface FamilyMember {
  id: string;
  name: string;
  relation: 'self' | 'spouse' | 'parent' | 'child' | 'sibling' | 'grandparent' | 'other';
  age?: number;
  isSenior: boolean;
  isChild: boolean;
  threatCount: number;
  safeScore: number;
  lastActive: string;
  isOnline: boolean;
}

export interface AIResponse {
  question: string;
  answer: string;
  category: 'trust_website' | 'trust_seller' | 'investment_advice' | 'caller_verification' | 'message_check' | 'qr_safety' | 'report_guidance' | 'app_safety' | 'general';
  confidence: 'high' | 'medium' | 'low';
  relatedScams?: ThreatCategory[];
  emergencyRelevant: boolean;
}

export type ThreatCategory =
  | 'OTP Scam'
  | 'KYC Scam'
  | 'Bank Fraud'
  | 'Investment Scam'
  | 'Lottery Scam'
  | 'Job Scam'
  | 'Delivery Scam'
  | 'UPI Fraud'
  | 'QR Scam'
  | 'Customer Care Scam'
  | 'Government Impersonation'
  | 'Friend Impersonation'
  | 'SIM Swap'
  | 'Crypto Scam'
  | 'Deepfake Scam'
  | 'Identity Theft'
  | 'Loan Scam'
  | 'Social Media Scam'
  | 'Fake App Scam'
  | 'Invoice Scam'
  | 'Unknown Risk';