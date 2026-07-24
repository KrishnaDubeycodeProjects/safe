import type { AIResponse } from './types';

const faqDatabase: AIResponse[] = [
  {
    question: 'Can I trust this website?',
    answer: 'Before trusting any website, check: 1) URL starts with https:// 2) No spelling mistakes in domain name 3) Contact information is real 4) Check Google reviews. If you are unsure, paste the link in SAFE Scanner for instant analysis.',
    category: 'trust_website',
    confidence: 'high',
    relatedScams: ['KYC Scam', 'Bank Fraud'],
    emergencyRelevant: false,
  },
  {
    question: 'Can I trust this seller on OLX/Amazon/Flipkart?',
    answer: "Be careful with sellers who: ask to talk on WhatsApp, share QR codes for payment, demand advance payment, have no returns policy, or have very few reviews. Always use platform's official payment system. Never pay outside the app.",
    category: 'trust_seller',
    confidence: 'high',
    relatedScams: ['QR Scam', 'Delivery Scam'],
    emergencyRelevant: false,
  },
  {
    question: 'Should I invest here? They promise high returns.',
    answer: 'Stop! No legitimate investment guarantees high returns. Check: 1) Is the company SEBI registered? 2) Are they promising "guaranteed" returns? 3) Are they pressuring you to act fast? 4) Do they have a physical office? If answer to any is yes, it is likely a scam. Report immediately.',
    category: 'investment_advice',
    confidence: 'high',
    relatedScams: ['Investment Scam', 'Lottery Scam', 'Crypto Scam'],
    emergencyRelevant: true,
  },
  {
    question: 'Is this caller genuine? They said they are from the bank.',
    answer: 'Banks never call to ask for OTP, card number, CVV, or internet banking password. If someone claims to be from the bank: hang up, call the official bank number (from bank website or card back), and confirm. Never call back on the number they gave.',
    category: 'caller_verification',
    confidence: 'high',
    relatedScams: ['OTP Scam', 'KYC Scam', 'Bank Fraud', 'Customer Care Scam'],
    emergencyRelevant: true,
  },
  {
    question: 'Is this message fake? I received an SMS about my package.',
    answer: 'Yes, it is likely fake if: you are not expecting any package, the message has a link from an unknown website, asks for small payment (₹25-₹50), has spelling mistakes, or creates urgency. Real courier companies send tracking updates through their official app or website, not SMS links.',
    category: 'message_check',
    confidence: 'high',
    relatedScams: ['Delivery Scam'],
    emergencyRelevant: false,
  },
  {
    question: 'Is this QR code safe to scan?',
    answer: 'Be very careful! Only scan QR codes from trusted sources. Scammers put fake QR codes on parking meters, restaurants, and online marketplace. Remember: You scan QR codes to PAY, not to RECEIVE money. If someone asks you to scan QR to "get payment", it is a scam.',
    category: 'qr_safety',
    confidence: 'high',
    relatedScams: ['QR Scam'],
    emergencyRelevant: true,
  },
  {
    question: 'How do I report a cyber fraud?',
    answer: 'Immediate steps: 1) Call 1930 (National Cyber Crime Helpline) within golden hour 2) Report on cybercrime.gov.in 3) Contact your bank to freeze accounts/cards 4) Save all evidence (screenshots, messages, transaction IDs) 5) Visit nearest police station. Do not delay — the first hour is critical.',
    category: 'report_guidance',
    confidence: 'high',
    relatedScams: ['Bank Fraud', 'UPI Fraud', 'OTP Scam', 'Investment Scam'],
    emergencyRelevant: true,
  },
  {
    question: 'Can this app steal my data?',
    answer: 'Warning signs of a malicious app: asks for too many permissions (contacts, photos, SMS, camera when not needed), developed by unknown company, few downloads, bad reviews, requests financial information. Before installing: check developer name, read permissions, check Play Store reviews. For loan apps, verify if RBI approved.',
    category: 'app_safety',
    confidence: 'medium',
    relatedScams: ['Loan Scam', 'Fake App Scam', 'Identity Theft'],
    emergencyRelevant: false,
  },
  {
    question: 'What should I do if I already shared my OTP?',
    answer: 'Emergency! Call your bank immediately to block your account/debit card. Then call 1930 (National Cyber Helpline). Change all passwords. Check your bank account for unauthorized transactions. If money is stolen, bank may reverse if reported within 3 days of fraud under RBI guidelines.',
    category: 'general',
    confidence: 'high',
    relatedScams: ['OTP Scam', 'Bank Fraud'],
    emergencyRelevant: true,
  },
  {
    question: 'What is digital arrest scam?',
    answer: 'Digital arrest is a new scam where fraudsters video call pretending to be police/CBI/income tax officials. They show fake arrest warrants and threaten "digital arrest" unless you pay "security deposit". Remember: No government agency makes arrests via video call or demands money online. Hang up immediately and report.',
    category: 'general',
    confidence: 'high',
    relatedScams: ['Government Impersonation'],
    emergencyRelevant: true,
  },
  {
    question: 'How to set a strong password?',
    answer: 'Use minimum 12 characters with uppercase, lowercase, numbers, and special symbols. Do not use personal info (name, birthday, phone). Use different passwords for each account. Best practice: use a password manager like Google Password Manager or Bitwarden. Enable 2FA wherever possible.',
    category: 'general',
    confidence: 'high',
    emergencyRelevant: false,
  },
  {
    question: 'What is SIM swap fraud and how to prevent it?',
    answer: 'SIM swap happens when fraudsters get a duplicate SIM issued in your name. They call your telecom provider, pretend to be you, and ask for SIM replacement. Once they have your SIM, they get all OTPs. Prevention: set a SIM lock PIN with your telecom provider, never share OTP for SIM replacement, if your SIM stops working suddenly — contact telecom immediately.',
    category: 'general',
    confidence: 'high',
    relatedScams: ['SIM Swap', 'Identity Theft'],
    emergencyRelevant: true,
  },
];

export function findAnswer(query: string): AIResponse | null {
  const lower = query.toLowerCase();
  const keywords = lower.split(/\s+/);

  let bestMatch: AIResponse | null = null;
  let bestScore = 0;

  for (const faq of faqDatabase) {
    const faqLower = faq.question.toLowerCase();
    const matchCount = keywords.filter((kw) => faqLower.includes(kw)).length;
    const score = matchCount / keywords.length;

    if (score > bestScore) {
      bestScore = score;
      bestMatch = faq;
    }
  }

  return bestScore > 0.3 ? bestMatch : null;
}

export function getEmergencyQuestions(): AIResponse[] {
  return faqDatabase.filter((faq) => faq.emergencyRelevant);
}

export function getQuestionsByCategory(category: AIResponse['category']): AIResponse[] {
  return faqDatabase.filter((faq) => faq.category === category);
}

export const allQuestions = faqDatabase.map((faq) => faq.question);

