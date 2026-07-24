import type { SafeScoreData } from './types';

export function calculateSafeScore(): SafeScoreData {
  const categories = {
    passwordStrength: 7,
    fraudAwareness: 5,
    threatReports: 3,
    securitySettings: 6,
    learningCompletion: 4,
    accountSecurity: 8,
    riskExposure: 6,
  };

  const weights = {
    passwordStrength: 0.15,
    fraudAwareness: 0.15,
    threatReports: 0.15,
    securitySettings: 0.1,
    learningCompletion: 0.1,
    accountSecurity: 0.2,
    riskExposure: 0.15,
  };

  const overall = Math.round(
    Object.entries(categories).reduce(
      (sum, [key, val]) => sum + val * (weights as Record<string, number>)[key],
      0
    )
  );

  const suggestions: string[] = [];
  if (categories.passwordStrength < 8) {
    suggestions.push('Use unique passwords for each account and enable a password manager.');
  }
  if (categories.fraudAwareness < 7) {
    suggestions.push('Complete all fraud awareness modules in the Learning Center.');
  }
  if (categories.threatReports < 5) {
    suggestions.push('Report suspicious messages and numbers to help the community.');
  }
  if (categories.securitySettings < 7) {
    suggestions.push('Review and update your social media privacy settings.');
  }
  if (categories.learningCompletion < 6) {
    suggestions.push('Take the fraud prevention quizzes to test your knowledge.');
  }
  if (categories.accountSecurity < 8) {
    suggestions.push('Enable two-factor authentication on all important accounts.');
  }
  if (categories.riskExposure > 4) {
    suggestions.push('Check if your email or phone has been exposed in a data breach.');
  }

  let rating: SafeScoreData['rating'];
  if (overall >= 8) rating = 'EXCELLENT';
  else if (overall >= 6) rating = 'GOOD';
  else if (overall >= 4) rating = 'FAIR';
  else if (overall >= 2) rating = 'POOR';
  else rating = 'CRITICAL';

  return {
    overall,
    previousMonth: 5,
    categories,
    suggestions,
    rating,
  };
}

export function getRatingColor(rating: SafeScoreData['rating']): string {
  const colors: Record<SafeScoreData['rating'], string> = {
    EXCELLENT: 'var(--green)',
    GOOD: '#4ade80',
    FAIR: 'var(--amber)',
    POOR: '#fb923c',
    CRITICAL: 'var(--red)',
  };
  return colors[rating];
}

export function getRatingEmoji(rating: SafeScoreData['rating']): string {
  const emojis: Record<SafeScoreData['rating'], string> = {
    EXCELLENT: '🛡️',
    GOOD: '👍',
    FAIR: '⚠️',
    POOR: '🔴',
    CRITICAL: '🚨',
  };
  return emojis[rating];
}
