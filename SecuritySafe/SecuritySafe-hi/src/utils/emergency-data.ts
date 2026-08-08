export interface EmergencyStep {
  id: string;
  title: string;
  description: string;
  detail?: string;
  action?: {
    type: 'call' | 'link' | 'info';
    text: string;
    number?: string;
    url?: string;
    warning?: boolean;
  };
}

export interface Fallback {
  trigger: string;
  action: string;
  actionLink?: {
    url: string;
    text: string;
  };
}

export interface ChecklistItem {
  id: string;
  text: string;
}

export interface EmergencyPage {
  id: string;
  icon: string;
  title: string;
  subtitle: string;
  urgencyBadge?: string;
  urgencyWarning?: boolean;
  steps: EmergencyStep[];
  fallbacks: Fallback[];
  evidence: ChecklistItem[];
  documents: string[];
  // Optional sections
  legalRights?: string[];
  redFlags?: string[];
  howToIdentify?: string[];
  footerNote?: string;
}

export const emergencyPages: Record<string, EmergencyPage> = {
  financial: {
    id: 'financial',
    icon: '💰',
    title: 'Online Financial Fraud',
    subtitle: 'UPI fraud, unauthorized debit, fake bank call, OTP scam, phishing payment link, QR code scam, refund scam, KYC update fraud',
    urgencyBadge: '⏱️ ACT WITHIN 60 MINUTES',
    urgencyWarning: false,
    steps: [
      {
        id: 'f1',
        title: 'Call Your Bank Immediately',
        description: 'Call your bank\'s 24/7 fraud helpline (number on back of card or bank app). Say: "I want to report an unauthorized transaction and request an immediate freeze."',
        detail: 'Ask for a complaint/reference number — note it down. The first 60 minutes are critical — many banks can reverse transactions only within this window.',
        action: { type: 'info', text: '⏱️ Golden Hour: First 60 minutes are critical' }
      },
      {
        id: 'f2',
        title: 'Call 1930 — Cyber Crime Helpline',
        description: 'Call immediately after the bank call. This helpline is directly linked to banks/payment systems and can trigger an instant transaction hold.',
        detail: 'Available 24/7. They will guide you through the next steps.',
        action: { type: 'call', number: '1930', text: 'Call 1930 Now' }
      },
      {
        id: 'f3',
        title: 'File Complaint on Cyber Crime Portal',
        description: 'File at cybercrime.gov.in under "Report Financial Fraud" — do this within 24 hours for the best chance of fund recovery via RBI\'s lien-marking system.',
        detail: 'Attach all screenshots and transaction details.',
        action: { type: 'link', url: 'https://cybercrime.gov.in', text: 'Visit cybercrime.gov.in' }
      },
      {
        id: 'f4',
        title: 'Send Written Email to Your Bank',
        description: 'Not just a phone call — send a formal email stating the date, amount, and that you are invoking RBI\'s "zero/limited liability" customer protection circular.',
        detail: 'This creates a legal record and forces the bank to act within a set timeline.'
      },
      {
        id: 'f5',
        title: 'Block Cards & Change PINs',
        description: 'Block/replace your debit/credit card immediately. Change your net-banking password and UPI PIN.',
        detail: 'Do this even if you think only one transaction was fraudulent.'
      },
      {
        id: 'f6',
        title: 'Report in UPI App (if applicable)',
        description: 'If fraud happened via GPay/PhonePe/Paytm, report the transaction inside the app too. Most have a "Report Fraud" option per transaction.',
        detail: 'Check all linked accounts for any other unauthorized activity.'
      }
    ],
    fallbacks: [
      {
        trigger: 'If bank doesn\'t respond or refuses to act within 7-10 working days',
        action: 'File a written complaint with the Banking Ombudsman at cms.rbi.org.in. RBI mandates banks resolve such complaints within a set timeline.',
        actionLink: { url: 'https://cms.rbi.org.in', text: 'Visit RBI Ombudsman' }
      },
      {
        trigger: 'If amount is large or fraud appears organized/repeated',
        action: 'Visit your nearest police station / cyber cell in person and file an FIR, attaching your cybercrime.gov.in acknowledgment number.'
      }
    ],
    evidence: [
      { id: 'fe1', text: 'Screenshot of the transaction / SMS / UPI alert' },
      { id: 'fe2', text: 'Transaction ID / UTR number' },
      { id: 'fe3', text: 'Call recordings with the scammer' },
      { id: 'fe4', text: 'Screenshots of chat with the scammer' },
      { id: 'fe5', text: 'Bank statement showing the fraudulent entry' }
    ],
    documents: [
      'Aadhaar / PAN card (ID proof)',
      'Bank statement (last 3 months)',
      'All screenshot evidence',
      '1930 complaint reference number',
      'Cybercrime.gov.in acknowledgment copy'
    ],
    footerNote: '💡 The sooner you report, the higher the chance of recovering your money. Don\'t wait.'
  },

  sextortion: {
    id: 'sextortion',
    icon: '📸',
    title: 'Intimate Image Blackmail',
    subtitle: 'Sextortion, leaked private photos, webcam blackmail, NCII',
    urgencyBadge: '🛑 DO NOT PAY',
    urgencyWarning: true,
    steps: [
      {
        id: 's1',
        title: 'DO NOT PAY',
        description: 'Paying almost never stops it. It usually invites repeat demands. Do not send any more money or images.',
        detail: 'Scammers rely on fear. Payment confirms you are willing to pay, making you a target for life.',
        action: { type: 'info', text: '🛑 STOP: Do not transfer money', warning: true }
      },
      {
        id: 's2',
        title: 'Preserve Evidence (Do Not Delete)',
        description: 'Do not delete the chat, images, or the blackmailer\'s profile. Screenshot everything first.',
        detail: 'Capture their username, profile link, messages, and any payment demands. Only block AFTER screenshotting.'
      },
      {
        id: 's3',
        title: 'Use StopNCII.org',
        description: 'A free, confidential global tool. Create a digital "hash" of the image so platforms (Meta, TikTok) can detect and block it.',
        detail: 'You do NOT send the actual image to them. It creates a digital fingerprint locally on your device.',
        action: { type: 'link', url: 'https://stopncii.org', text: 'Visit StopNCII.org' }
      },
      {
        id: 's4',
        title: 'Report on Cyber Crime Portal',
        description: 'File under "Report Women/Child Related Crime". Allows anonymous reporting if you are not ready to reveal identity.',
        action: { type: 'link', url: 'https://cybercrime.gov.in', text: 'File Anonymous Report' }
      },
      {
        id: 's5',
        title: 'Call 1930',
        description: 'They have officers trained specifically for sextortion and NCII (Non-Consensual Intimate Imagery) cases.',
        action: { type: 'call', number: '1930', text: 'Call 1930 Now' }
      },
      {
        id: 's6',
        title: 'Report on Platform',
        description: 'Use Instagram/Facebook/WhatsApp "Report" feature. Select "Non-consensual intimate imagery" or "Sexual exploitation".',
        detail: 'This can get content taken down within hours if flagged correctly.'
      }
    ],
    fallbacks: [
      {
        trigger: 'If content is already public',
        action: 'Use each platform\'s takedown request AND file with cybercrime.gov.in simultaneously. Request expedited removal citing active police complaint.'
      },
      {
        trigger: 'If blackmailer uses new numbers/accounts',
        action: 'Report each new contact to 1930 referencing your ORIGINAL complaint number. Do not start fresh cases.'
      }
    ],
    evidence: [
      { id: 'se1', text: 'Screenshots of all threats/messages (with timestamps)' },
      { id: 'se2', text: 'Blackmailer\'s profile link/username/phone number' },
      { id: 'se3', text: 'Payment demand details (UPI ID, Wallet address)' },
      { id: 'se4', text: 'StopNCII case reference (if used)' }
    ],
    documents: [
      'ID Proof (Optional for anonymous filing)',
      'Screenshot evidence',
      'Platform report reference numbers',
      '1930 complaint reference'
    ],
    footerNote: '💙 You are not alone. Tell someone you trust. Isolation helps the scammer. You did nothing wrong.'
  },

  hacking: {
    id: 'hacking',
    icon: '🔐',
    title: 'Account Hacking & Identity Theft',
    subtitle: 'Hacked social media, cloned profiles, email compromise, Aadhaar misuse',
    steps: [
      {
        id: 'h1',
        title: 'Try Official Recovery First',
        description: 'Most platforms (Instagram, Facebook, Google) have a "My account was hacked" flow. Use this before anything else.',
        detail: 'It is often the fastest way to regain access.',
        action: { type: 'info', text: '🔍 Check platform help center first' }
      },
      {
        id: 'h2',
        title: 'Secure Linked Accounts',
        description: 'Change passwords on all linked accounts, especially EMAIL. Enable Two-Factor Authentication (2FA) immediately.',
        detail: 'Email is usually the recovery point for everything else. Secure it first.'
      },
      {
        id: 'h3',
        title: 'Alert Your Contacts',
        description: 'Post a warning on other social media or WhatsApp status that your account was compromised.',
        detail: 'Prevent friends/family from falling for scam messages sent "from you".'
      },
      {
        id: 'h4',
        title: 'Report Impersonation',
        description: 'If a fake profile is using your photos, use the platform\'s dedicated "Report Impersonation" form.',
        detail: 'This is different from a regular content report. It usually requires ID verification.',
        action: { type: 'link', url: 'https://www.facebook.com/help/contact/169655056731309', text: 'Facebook Impersonation Form' }
      },
      {
        id: 'h5',
        title: 'File Cyber Crime Complaint',
        description: 'File on cybercrime.gov.in under "Report Other Cyber Crime" → Hacking/Impersonation.',
        action: { type: 'link', url: 'https://cybercrime.gov.in', text: 'Visit cybercrime.gov.in' }
      }
    ],
    fallbacks: [
      {
        trigger: 'If locked out permanently',
        action: 'Request platform\'s law-enforcement escalation portal (Meta/Google have these) by attaching your police complaint.'
      },
      {
        trigger: 'If Aadhaar/PAN misuse suspected',
        action: 'Lock Aadhaar biometric via UIDAI app immediately. Check CIBIL score for unauthorized loans.'
      }
    ],
    evidence: [
      { id: 'he1', text: 'Screenshot of hacked/fake profile' },
      { id: 'he2', text: 'Login alert emails ("New device login")' },
      { id: 'he3', text: 'Ransom/demand messages from hacker' },
      { id: 'he4', text: 'Original account creation email (proof of ownership)' }
    ],
    documents: [
      'ID Proof',
      'Original account proof (old screenshots, emails)',
      'Screenshot evidence',
      'Cyber crime complaint copy'
    ],
    footerNote: '🔒 Prevention: Always enable 2FA (Two-Factor Authentication) on email and social media.'
  },

  investment: {
    id: 'investment',
    icon: '📈',
    title: 'Investment, Job & Loan Scams',
    subtitle: 'Fake trading apps, task scams, loan app harassment, Ponzi schemes',
    steps: [
      {
        id: 'i1',
        title: 'STOP All Payments',
        description: 'Scammers often ask for "one more small fee to unlock withdrawal". This never ends. Stop paying immediately.',
        action: { type: 'info', text: '🛑 STOP: Do not send more money', warning: true }
      },
      {
        id: 'i2',
        title: 'Screenshot Everything',
        description: 'Capture the app/website, chat history, and payment proofs BEFORE the app disappears.',
        detail: 'Many scam apps get taken down once exposed. Act fast.'
      },
      {
        id: 'i3',
        title: 'Report to 1930 & Cyber Portal',
        description: 'File under "Report Financial Fraud" or "Investment Fraud".',
        action: { type: 'call', number: '1930', text: 'Call 1930' }
      },
      {
        id: 'i4',
        title: 'Report Loan App Harassment',
        description: 'If a loan app is blackmailing you with morphed images: Do NOT pay. Report to 1930 and report the app to Google Play/Apple Store.',
        detail: 'RBI has banned many unauthorized digital lending apps.'
      },
      {
        id: 'i5',
        title: 'Report Receiving UPI/Bank',
        description: 'Provide the scammer\'s UPI ID or bank account to 1930. Banks can sometimes freeze the receiving account if reported fast.'
      }
    ],
    redFlags: [
      'Guaranteed high returns with zero risk',
      'Pressure to invest quickly ("Limited offer")',
      'Requests to download APK files outside Play Store',
      'Unregistered investment advisors',
      'Payments to personal bank accounts instead of company accounts'
    ],
    fallbacks: [
      {
        trigger: 'If money was sent via Crypto',
        action: 'File with cybercrime.gov.in and explicitly mention wallet address/exchange. Specialized cyber cells handle crypto tracing.'
      }
    ],
    evidence: [
      { id: 'ie1', text: 'App name and screenshots of interface' },
      { id: 'ie2', text: 'All chat/payment screenshots' },
      { id: 'ie3', text: 'Receiving UPI ID, bank account, or wallet address' },
      { id: 'ie4', text: 'Website URL or APK file name' }
    ],
    documents: [
      'ID Proof',
      'Bank/Payment statement',
      'Screenshot evidence',
      '1930 complaint reference'
    ],
    footerNote: '💡 Verify: Check if the investment platform is registered with SEBI or RBI before investing.'
  },

  phishing: {
    id: 'phishing',
    icon: '🔗',
    title: 'Phishing, SIM Swap & Malicious Links',
    subtitle: 'Fake SMS, malicious APKs, SIM cloning, fake KYC links',
    steps: [
      {
        id: 'p1',
        title: 'Do Not Click / Enter Details',
        description: 'If you haven\'t clicked or entered details yet, stop. Do not interact with the link.',
        action: { type: 'info', text: '🛑 STOP: Do not click further', warning: true }
      },
      {
        id: 'p2',
        title: 'If You Entered Bank/OTP Details',
        description: 'Immediately call your bank to block cards/freeze net banking. Treat as Financial Fraud.',
        detail: 'Time is critical. Call bank first, then 1930.',
        action: { type: 'call', number: '1930', text: 'Call 1930' }
      },
      {
        id: 'p3',
        title: 'If You Installed an APK',
        description: 'Put phone in Airplane Mode. Uninstall the app. Run security scan. Change passwords from a DIFFERENT clean device.',
        detail: 'Malicious APKs can steal data in background.'
      },
      {
        id: 'p4',
        title: 'If SIM Stopped Working (SIM Swap)',
        description: 'Contact telecom operator immediately to verify/block. Alert your bank instantly.',
        detail: 'SIM swap is usually a precursor to bank fraud.'
      },
      {
        id: 'p5',
        title: 'Report Phishing Link/SMS',
        description: 'Report to 1930 and forward SMS to telecom spam number (e.g., 1909).'
      }
    ],
    howToIdentify: [
      'Urgent language ("Act now or account blocked")',
      'Generic greetings ("Dear Customer")',
      'Suspicious sender number or email address',
      'Links that don\'t match official domain (e.g., bank-name-support.com)',
      'Requests for OTP, PIN, or Password'
    ],
    fallbacks: [
      {
        trigger: 'If SIM swap led to financial loss',
        action: 'Escalate as combined Financial Fraud + SIM Swap case. File with 1930 and bank simultaneously.'
      }
    ],
    evidence: [
      { id: 'pe1', text: 'Screenshot of phishing SMS/email/link' },
      { id: 'pe2', text: 'Time of click and forms filled' },
      { id: 'pe3', text: 'Telecom complaint reference (for SIM swap)' },
      { id: 'pe4', text: 'Malicious APK file name (if installed)' }
    ],
    documents: [
      'ID Proof',
      'Screenshot evidence',
      'Telecom/Bank reference numbers',
      '1930 complaint copy'
    ],
    footerNote: '🔒 Tip: Never share OTP, PIN, or Password. No bank or government agency will ever ask for these.'
  },

  bullying: {
    id: 'bullying',
    icon: '👤',
    title: 'Cyberbullying, Harassment & Stalking',
    subtitle: 'Online harassment, cyberstalking, doxxing, threats, defamation',
    steps: [
      {
        id: 'c1',
        title: 'Do Not Engage',
        description: 'Do not respond to the harasser. This often escalates the behavior.',
        action: { type: 'info', text: '🛑 STOP: Do not reply', warning: true }
      },
      {
        id: 'c2',
        title: 'Screenshot Everything',
        description: 'Capture every instance of harassment with timestamps and visible usernames.',
        detail: 'Evidence is crucial for legal action.'
      },
      {
        id: 'c3',
        title: 'Block & Report on Platform',
        description: 'Use the platform\'s block and report harassment feature.'
      },
      {
        id: 'c4',
        title: 'File Cyber Crime Complaint',
        description: 'File on cybercrime.gov.in under "Report Other Cyber Crime" → Cyber Bullying/Stalking.',
        action: { type: 'link', url: 'https://cybercrime.gov.in', text: 'Visit cybercrime.gov.in' }
      },
      {
        id: 'c5',
        title: 'File FIR if Physical Threats',
        description: 'If threats include physical harm or your address/location has been shared (doxxing), file an FIR in person immediately.',
        detail: 'This is treated more seriously than online-only harassment.'
      }
    ],
    legalRights: [
      'IT Act Section 66E: Privacy violation',
      'IT Act Section 67: Publishing obscene material',
      'IPC Section 509: Word/gesture intended to insult modesty',
      'IPC Section 354D: Stalking',
      'IPC Section 506: Criminal intimidation'
    ],
    fallbacks: [
      {
        trigger: 'If harassment continues across new accounts',
        action: 'Keep filing each new instance under the SAME original complaint number. This builds a pattern-of-harassment case.'
      }
    ],
    evidence: [
      { id: 'ce1', text: 'All screenshots with timestamps' },
      { id: 'ce2', text: 'List of accounts/numbers used by harasser' },
      { id: 'ce3', text: 'Witness statements (mutual contacts who saw it)' },
      { id: 'ce4', text: 'Platform report reference numbers' }
    ],
    documents: [
      'ID Proof',
      'Screenshot evidence',
      'Witness statements (if any)',
      'Cyber crime complaint copy'
    ],
    footerNote: '💙 You are not alone. Reach out to trusted friends, family, or mental health helplines if needed.'
  }
};

export const emergencyContacts = [
  { label: 'Cyber Crime', number: '1930'},
  { label: 'Rescue', number: '112' },
  { label: 'Women', number: '1091' },
  { label: 'Child', number: '1098' }
];

export const universalSteps = [
  { id: 'u1', text: 'Don\'t panic. Take a deep breath.' },
  { id: 'u2', text: 'Don\'t delete anything — chats, messages, transactions.' },
  { id: 'u3', text: 'Take screenshots of everything right now.' },
  { id: 'u4', text: 'Note down all reference numbers and timestamps.' }
];

export const homeCategories = [
  {
    id: 'financial',
    icon: '💰',
    title: 'Money Stolen / UPI Fraud',
    description: 'Unauthorized transactions, OTP scam, fake bank calls, QR code fraud',
    keywords: ['UPI', 'Bank', 'Card', 'OTP', 'Payment']
  },
  {
    id: 'sextortion',
    icon: '📸',
    title: 'Private Photos Blackmail',
    description: 'Threats to leak intimate images, webcam blackmail, revenge content',
    keywords: ['Sextortion', 'NCII', 'Blackmail', 'MMS']
  },
  {
    id: 'hacking',
    icon: '🔐',
    title: 'Account Hacked / Cloned',
    description: 'Social media hacked, fake profile using your photos, identity theft',
    keywords: ['Hacked', 'Cloned', 'Fake Profile', 'Aadhaar']
  },
  {
    id: 'investment',
    icon: '📈',
    title: 'Investment / Job / Loan Scam',
    description: 'Fake trading apps, work-from-home scams, loan app harassment',
    keywords: ['Trading', 'Crypto', 'Task Scam', 'Loan App']
  },
  {
    id: 'phishing',
    icon: '🔗',
    title: 'Fake Link / SIM Swap',
    description: 'Phishing SMS, fake delivery links, malicious apps, SIM cloned',
    keywords: ['Phishing', 'SIM Swap', 'Fake Link', 'APK']
  },
  {
    id: 'bullying',
    icon: '👤',
    title: 'Harassment / Stalking',
    description: 'Repeated threats, cyberstalking, doxxing, online defamation',
    keywords: ['Harassment', 'Stalking', 'Threats', 'Doxxing']
  }
];