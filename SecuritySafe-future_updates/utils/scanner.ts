import type { InputType, ScanResult, ThreatCategory, Verdict } from './types';

export function detectInputType(input: string): InputType {
  const trimmed = input.trim();

  const urlPattern = /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-\.~:/?#[\]@!$&'()*+,;=]*)?$/i;
  if (urlPattern.test(trimmed) && trimmed.includes('.')) return 'url';

  const phonePattern = /^(\+91|91|0)?[6-9]\d{9}$/;
  if (phonePattern.test(trimmed.replace(/[\s\-()]/g, ''))) return 'phone';

  if (trimmed.includes('@') && trimmed.includes('.') && !trimmed.includes(' ')) return 'email';

  if (trimmed.length > 10 && /\b(?:whatsapp|wa\.me|chat\.whatsapp)\b/i.test(trimmed)) return 'whatsapp';

  return 'sms';
}

function extractUrls(text: string): string[] {
  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  return text.match(urlRegex) || [];
}

function extractPhones(text: string): string[] {
  const phoneRegex = /(\+91|91|0)?[6-9]\d{9}/g;
  return text.match(phoneRegex) || [];
}

function countMatches(text: string, patterns: RegExp[]): number {
  let count = 0;
  for (const pattern of patterns) {
    const matches = text.match(pattern);
    if (matches) count += matches.length;
  }
  return count;
}

interface AnalysisResult {
  threatType: ThreatCategory;
  score: number;
  verdict: Verdict;
  reason: string;
  actionSteps: string[];
}

const scamKeywords = [
  /otp/i, /kyc/i, /update.*(account|bank|pan|aadhaar|aadhar)/i,
  /click.*(link|here)/i, /verify/i, /urgent/i, /immediate/i,
  /limited.*time/i, /account.*(block|suspend|close)/i,
  /claim.*(prize|reward|lottery)/i, /you.*(won|win)/i,
  /lucky/i, /free/i, /cashback/i, /refund/i,
  /loan.*(approve|sanction)/i, /job.*(offer|opportunity)/i,
  /work.*(home|from.*home)/i, /part.*time/i,
  /customer.*care/i, /technical.*support/i,
  /payment.*(failed|pending)/i, /transaction.*(fail|cancel)/i,
  /investment.*(return|guaranteed)/i, /doubler?.*money/i,
  /bank.*(account|detail)/i, /debit.*card/i, /credit.*card/i,
  /insurance.*(claim|policy)/i, /govt|sarkar/i,
  /aadhaar|aadhar|pan.*card/i, /electricity.*bill/i,
  /gas.*(connection|cylinder)/i, /broadband.*bill/i,
  /dear.*(customer|user|sir|madam)/i,
];

function analyzeInput(input: string): AnalysisResult {
  const text = input.trim();
  const urls = extractUrls(text);
  const phones = extractPhones(text);
  const keywordCount = countMatches(text, scamKeywords);

  let threatType: ThreatCategory = 'Unknown Risk';
  let score = 10;
  const reasons: string[] = [];
  const steps: string[] = [];

  if (/otp|one.?time.?password/i.test(text)) {
    threatType = 'OTP Scam';
    reasons.push('This message is asking for OTP which is a common scam tactic.');
    steps.push('Never share OTP with anyone, even if they claim to be from bank or government.');
    steps.push('Banks and government agencies NEVER ask for OTP.');
    steps.push('Block and report this number immediately.');
  }

  if (/kyc.*(expir|update|fail|pending|verif)/i.test(text)) {
    threatType = 'KYC Scam';
    reasons.push('Fake KYC expiry messages are used to steal your personal information.');
    steps.push('Don\'t click any link in this message.');
    steps.push('Your KYC does not expire via SMS or email link.');
    steps.push('Contact your bank directly using official number.');
  }

  if (/(job|work).*(home|part.?time|online|earning)/i.test(text)) {
    threatType = 'Job Scam';
    reasons.push('This looks like a fake job offer designed to take your money.');
    steps.push('Real companies never ask money for job processing.');
    steps.push('Don\'t pay for "registration" or "training".');
    steps.push('Verify the company on official website before applying.');
  }

  if (/(lottery|won|winner|prize|lucky|reward)/i.test(text)) {
    threatType = 'Lottery Scam';
    reasons.push('Lottery scams trick you into paying fees to claim fake prizes.');
    steps.push('You cannot win a lottery you never entered.');
    steps.push('Never pay money to claim a prize.');
    steps.push('Block and report this message.');
  }

  if (/(delivery|courier|parcel|package|shipment)/i.test(text) && /(link|click|update|fee|charge)/i.test(text)) {
    threatType = 'Delivery Scam';
    reasons.push('Fake delivery messages trick you into paying extra charges.');
    steps.push('Check your actual orders on official website or app.');
    steps.push('Don\'t pay any "delivery fee" through unknown links.');
    steps.push('Track packages only on official courier websites.');
  }

  if (/(investment|return|profit|dividend|share.?market|stock|doubler)/i.test(text)) {
    threatType = 'Investment Scam';
    reasons.push('This promises unrealistic returns to trap your money.');
    steps.push('No legitimate investment guarantees high returns.');
    steps.push('Don\'t invest based on SMS or WhatsApp messages.');
    steps.push('Consult SEBI registered advisors only.');
  }

  if (/(bank|account|debit|credit).*(block|suspend|close|deactivat)/i.test(text)) {
    threatType = 'Bank Fraud';
    reasons.push('Fraudsters create panic about account blocking to steal details.');
    steps.push('Your bank account is not going to be blocked.');
    steps.push('Never share card number, CVV, or OTP.');
    steps.push('Call your bank\'s official customer care number to verify.');
  }

  if (/(upi|gpay|phonepe|paytm).*(refund|cashback|credit)/i.test(text) && /(link|click|code|number)/i.test(text)) {
    threatType = 'UPI Fraud';
    reasons.push('Fake UPI refunds are used to trick you into sending money.');
    steps.push('UPI refunds don\'t require you to click any link.');
    steps.push('Never share UPI PIN or scan unknown QR codes.');
    steps.push('Check your UPI app for actual transactions.');
  }

  if (/qr.*(scan|code)/i.test(text) || /scan.*qr/i.test(text)) {
    threatType = 'QR Scam';
    reasons.push('Scammers use QR codes to steal money from your account.');
    steps.push('Never scan QR codes from unknown people.');
    steps.push('QR codes are for receiving, not sending money.');
    steps.push('If someone asks you to scan QR to "get payment", it is a scam.');
  }

  if (/(customer.?care|technical.?support|helpdesk|toll.?free)/i.test(text)) {
    threatType = 'Customer Care Scam';
    reasons.push('Fake customer care numbers connect you to scammers.');
    steps.push('Always use customer care numbers from official website.');
    steps.push('Google search results may show fake customer care numbers.');
    steps.push('Real customer care never asks for remote access or OTP.');
  }

  if (/(govt|government|sarkar|scheme|subsidy|pension)/i.test(text)) {
    threatType = 'Government Impersonation';
    reasons.push('Scammers pretend to be government officials to steal your data.');
    steps.push('Government schemes never ask for bank details via SMS.');
    steps.push('Don\'t share Aadhaar or PAN number with unknown callers.');
    steps.push('Visit official government portals for scheme information.');
  }

  if (threatType === 'Unknown Risk') {
    if (urls.length > 0) {
      reasons.push('This message contains a link. Unknown links can lead to phishing websites.');
      steps.push('Don\'t click on links from unknown senders.');
      steps.push('Hover to see the real URL before clicking.');
    } else if (keywordCount > 0) {
      reasons.push('This message has suspicious patterns commonly used in scams.');
      steps.push('Be cautious with unknown messages asking for action.');
      steps.push('Verify the sender through official channels.');
    } else {
      reasons.push('No obvious scam patterns detected, but always stay cautious.');
      steps.push('Verify unexpected messages through official channels.');
      steps.push('Never share personal information with unknown people.');
    }
    if (steps.length < 3) {
      steps.push('If something feels wrong, trust your instinct.');
      steps.push('Report suspicious messages to cybercrime.gov.in.');
    }
  }

  score = Math.max(1, Math.min(10, Math.round(10 - (keywordCount * 2.5) - (urls.length * 1.5))));
  if (phones.length > 0 && /(bank|account|otp|kyc)/i.test(text)) {
    score = Math.max(1, score - 2);
  }

  score = Math.max(1, Math.min(10, score));

  let verdict: Verdict;
  if (score <= 3) {
    verdict = 'DANGEROUS';
  } else if (score <= 6) {
    verdict = 'SUSPICIOUS';
  } else {
    verdict = 'SAFE';
  }

  const uniqueSteps = [...new Set(steps)].slice(0, 5);
  const uniqueReasons = [...new Set(reasons)];

  return {
    threatType,
    score,
    verdict,
    reason: uniqueReasons.length > 0 ? uniqueReasons[0] : 'Analysis complete. Stay vigilant.',
    actionSteps: uniqueSteps,
  };
}

export async function scanInput(input: string): Promise<ScanResult> {
  return scanInputText(input);
}

export async function scanInputText(text: string): Promise<ScanResult> {
  try {
    const response = await fetch('http://localhost:8000/api/scan/text', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ text })
    });
    if (!response.ok) {
      throw new Error('API server returned error');
    }
    const data = await response.json();
    
    const detectedType = detectInputType(text);
    const risk = data.combined_prob;
    const score = Math.max(1, Math.min(10, Math.round((1 - risk) * 10)));
    const verdict: Verdict = score <= 3 ? 'DANGEROUS' : score <= 6 ? 'SUSPICIOUS' : 'SAFE';
    
    let threatCategory: ThreatCategory = 'Unknown Risk';
    if (data.keywords && data.keywords.length > 0) {
      const kw = data.keywords[0].toLowerCase();
      if (['otp', 'password', 'pin'].includes(kw)) threatCategory = 'OTP Scam';
      else if (['kyc', 'aadhar', 'pan'].includes(kw)) threatCategory = 'KYC Scam';
      else if (['bank', 'account'].includes(kw)) threatCategory = 'Bank Fraud';
      else if (['lottery', 'winner', 'prize'].includes(kw)) threatCategory = 'Lottery Scam';
      else if (['job', 'work'].includes(kw)) threatCategory = 'Job Scam';
      else if (['delivery', 'parcel'].includes(kw)) threatCategory = 'Delivery Scam';
      else if (['upi', 'paytm', 'phonepe'].includes(kw)) threatCategory = 'UPI Fraud';
    } else {
      // Fallback categorization based on text matching
      if (/otp/i.test(text)) threatCategory = 'OTP Scam';
      else if (/kyc/i.test(text)) threatCategory = 'KYC Scam';
      else if (/bank|account/i.test(text)) threatCategory = 'Bank Fraud';
      else if (/lottery|prize/i.test(text)) threatCategory = 'Lottery Scam';
      else if (/job|work/i.test(text)) threatCategory = 'Job Scam';
      else if (/delivery|parcel/i.test(text)) threatCategory = 'Delivery Scam';
      else if (/upi/i.test(text)) threatCategory = 'UPI Fraud';
    }
    
    const advice = data.rag?.advice || (verdict === 'DANGEROUS' ? 
      ['Do not share OTPs, card details, or UPI PINs.', 'Avoid clicking links from unknown senders.'] : 
      ['Stay cautious when replying to unknown senders.', 'Verify information via official website.']);

    return {
      type: detectedType,
      threatType: threatCategory,
      score,
      verdict,
      reason: data.rag?.explanation || data.explanation || (verdict === 'DANGEROUS' ? '🚨 Scam indicators detected. Do not click links or share information.' : '✅ This message appears to be safe.'),
      actionSteps: advice
    };
  } catch (err) {
    console.warn('FastAPI backend down, falling back to local heuristics:', err);
    const detectedType = detectInputType(text);
    const analysis = analyzeInput(text);
    return {
      type: detectedType,
      threatType: analysis.threatType,
      score: analysis.score,
      verdict: analysis.verdict,
      reason: analysis.reason,
      actionSteps: analysis.actionSteps
    };
  }
}

export async function scanInputAudio(file: File, lang: string = 'en-in'): Promise<{ transcription: string; result: ScanResult }> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('lang', lang);

  const response = await fetch('http://localhost:8000/api/scan/audio', {
    method: 'POST',
    body: formData
  });
  if (!response.ok) {
    throw new Error('Audio API call failed');
  }
  const data = await response.json();
  
  const risk = data.analysis.combined_prob;
  const score = Math.max(1, Math.min(10, Math.round((1 - risk) * 10)));
  const verdict: Verdict = score <= 3 ? 'DANGEROUS' : score <= 6 ? 'SUSPICIOUS' : 'SAFE';
  
  const advice = data.analysis.rag?.advice || (verdict === 'DANGEROUS' ? 
    ['Do not answer unknown calls or share personal information.', 'Hang up immediately if threatened.'] : 
    ['Always double-check caller identity via official numbers.']);

  const scanResult: ScanResult = {
    type: 'phone',
    threatType: verdict === 'DANGEROUS' ? 'Customer Care Scam' : 'Unknown Risk',
    score,
    verdict,
    reason: data.analysis.rag?.explanation || 'Voice transcription analysis complete.',
    actionSteps: advice
  };

  return {
    transcription: data.transcription,
    result: scanResult
  };
}

export async function scanInputVideo(file: File): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch('http://localhost:8000/api/scan/video', {
    method: 'POST',
    body: formData
  });
  if (!response.ok) {
    throw new Error('Video API call failed');
  }
  const data = await response.json();
  
  const score = Math.max(1, Math.min(10, Math.round((1 - data.score) * 10)));
  const verdict: Verdict = score <= 3 ? 'DANGEROUS' : score <= 6 ? 'SUSPICIOUS' : 'SAFE';
  
  return {
    type: 'unknown',
    threatType: verdict === 'DANGEROUS' ? 'Deepfake Scam' : 'Unknown Risk',
    score,
    verdict,
    reason: verdict === 'DANGEROUS' ? 
      `🚨 Highly suspicious frame anomalies detected. The video is likely a deepfake (deepfake score: ${Math.round(data.score * 100)}%).` : 
      `✅ No deepfake indicators detected in this video file (deepfake score: ${Math.round(data.score * 100)}%).`,
    actionSteps: verdict === 'DANGEROUS' ? 
      ['Do not rely on this video for verification.', 'Check for audio synchronization issues or face warping.', 'Report the video as synthetic fraud.'] : 
      ['The video appears to be recorded naturally.', 'Always exercise caution in sensitive communications.']
  };
}
export async function scanInputImage(file: File): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('http://localhost:8000/api/scan/image', {
      method: 'POST',
      body: formData
    });
    
    if (!response.ok) {
      throw new Error('Image API call failed');
    }
    
    const data = await response.json();
    
    const risk = data.combined_prob || data.score || 0.5;
    const score = Math.max(1, Math.min(10, Math.round((1 - risk) * 10)));
    const verdict: Verdict = score <= 3 ? 'DANGEROUS' : score <= 6 ? 'SUSPICIOUS' : 'SAFE';
    
    let threatCategory: ThreatCategory = 'Unknown Risk';
    
    // Determine threat category from API response
    if (data.keywords && data.keywords.length > 0) {
      const kw = data.keywords[0].toLowerCase();
      if (['otp', 'password', 'pin'].includes(kw)) threatCategory = 'OTP Scam';
      else if (['kyc', 'aadhar', 'pan'].includes(kw)) threatCategory = 'KYC Scam';
      else if (['bank', 'account'].includes(kw)) threatCategory = 'Bank Fraud';
      else if (['lottery', 'winner', 'prize'].includes(kw)) threatCategory = 'Lottery Scam';
      else if (['job', 'work'].includes(kw)) threatCategory = 'Job Scam';
      else if (['delivery', 'parcel'].includes(kw)) threatCategory = 'Delivery Scam';
      else if (['upi', 'paytm', 'phonepe'].includes(kw)) threatCategory = 'UPI Fraud';
      else if (['qr', 'barcode'].includes(kw)) threatCategory = 'QR Scam';
      else if (['fake', 'phishing'].includes(kw)) threatCategory = 'Phishing Screenshot';
    }
    
    // Check if it's a phishing website screenshot
    if (data.is_phishing || data.phishing_score > 0.7) {
      threatCategory = 'Phishing Screenshot';
    }
    
    const advice = data.rag?.advice || data.actionSteps || (verdict === 'DANGEROUS' ? 
      ['This image contains suspicious content.', 'Do not click any links visible in the screenshot.', 'Verify the source through official channels.', 'Report this to cybercrime.gov.in.'] : 
      ['This image appears to be safe.', 'Always verify unexpected messages through official channels.', 'Be cautious with screenshots from unknown sources.']);

    return {
      type: 'image',
      threatType: threatCategory,
      score,
      verdict,
      reason: data.rag?.explanation || data.explanation || (verdict === 'DANGEROUS' ? 
        '🚨 Suspicious content detected in this image. It may contain phishing elements or scam indicators.' : 
        '✅ No obvious scam indicators detected in this image.'),
      actionSteps: advice,
      keywords: data.keywords || []
    };
  } catch (err) {
    console.warn('Image API down, using fallback analysis:', err);
    
    // Fallback: Basic analysis based on file properties
    const fileSizeMB = file.size / (1024 * 1024);
    const fileName = file.name.toLowerCase();
    
    let threatCategory: ThreatCategory = 'Unknown Risk';
    let score = 5;
    let verdict: Verdict = 'SUSPICIOUS';
    const reasons: string[] = [];
    const steps: string[] = [];
    
    // Check file name for suspicious patterns
    if (fileName.includes('screenshot') || fileName.includes('whatsapp') || fileName.includes('sms')) {
      reasons.push('This appears to be a message screenshot. Screenshots can be easily manipulated.');
      steps.push('Verify the information through official channels.');
      steps.push('Don\'t trust screenshots alone as proof.');
      score = 4;
    }
    
    // Check for very large files (could be suspicious)
    if (fileSizeMB > 5) {
      reasons.push('Unusually large image file detected.');
      steps.push('Be cautious with large files from unknown sources.');
      score = Math.max(1, score - 1);
    }
    
    if (reasons.length === 0) {
      reasons.push('Image analysis unavailable. The backend service is not running.');
      steps.push('Ensure the Python API backend is running (uvicorn app:app --port 8000).');
      steps.push('Try again when the service is available.');
      steps.push('In the meantime, manually verify any suspicious content.');
      score = 5;
    }
    
    if (score <= 3) verdict = 'DANGEROUS';
    else if (score <= 6) verdict = 'SUSPICIOUS';
    else verdict = 'SAFE';

    return {
      type: 'image',
      threatType: threatCategory,
      score,
      verdict,
      reason: reasons[0],
      actionSteps: steps.slice(0, 5),
      keywords: []
    };
  }
}