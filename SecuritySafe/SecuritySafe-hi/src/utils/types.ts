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
  | 'Manipulated Media Scam'
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

export interface BlogImage {
  /** Image URL or data: URI. */
  url: string;
  /** Caption shown under the image. */
  title?: string;
}

/**
 * Blogs are admin-authored only, published immediately via the admin panel
 * (/mgmt-x7k9p2) and served live from the backend's /api/blogs endpoints —
 * see security-safe-chat-backend/main.py. There is no static content file
 * and no public submission flow.
 */
export interface BlogPost {
  /** Server-generated UUID. */
  id: string;
  title: string;
  tags: string[];
  images: BlogImage[];
  /**
   * Plain-text body. Paragraphs are separated by a blank line. Drop `[1]`,
   * `[2]`... at the point in the text where the matching entry from
   * `images` (1-indexed) should be inserted, along with its caption.
   */
  content_text: string;
  /** ISO 8601 timestamp set by the server on create. */
  created_at: string;
  /** ISO 8601 timestamp set by the server on create/update. */
  updated_at: string;
}