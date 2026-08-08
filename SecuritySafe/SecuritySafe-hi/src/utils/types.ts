export type InputType = 'url' | 'sms' | 'whatsapp' | 'email' | 'phone' | 'unknown';

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

export interface LearnFraudQuiz {
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
}

export interface LearnFraudType {
  id: string;
  /** Links this scam to a FraudCategory.id */
  categoryId: string;
  title: string;
  icon: string;
  howItWorks: string;
  realExample: string;
  redFlags: string[];
  protectionSteps: string[];
  quiz: LearnFraudQuiz;
  tags: string[];
}