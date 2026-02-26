import { CompiledPattern } from '../types/patterns.js';

export const HIGH_CONFIDENCE_PATTERNS: CompiledPattern[] = [
  {
    name: 'AWS_ACCESS_KEY',
    regex: /AKIA[0-9A-Z]{16}/g,
    confidence: 'high',
    description: 'AWS access key ID',
  },
  {
    name: 'GITHUB_TOKEN',
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    confidence: 'high',
    description: 'GitHub personal access or server token',
  },
  {
    name: 'GITHUB_FINE_GRAINED_TOKEN',
    regex: /github_pat_[A-Za-z0-9_]{82,}/g,
    confidence: 'high',
    description: 'GitHub fine-grained personal access token',
  },
  {
    name: 'STRIPE_LIVE_KEY',
    regex: /sk_live_[A-Za-z0-9]{24,}/g,
    confidence: 'high',
    description: 'Stripe live secret key',
  },
  {
    name: 'STRIPE_PUBLISHABLE_KEY',
    regex: /pk_live_[A-Za-z0-9]{24,}/g,
    confidence: 'high',
    description: 'Stripe live publishable key',
  },
  {
    name: 'SLACK_WEBHOOK',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    confidence: 'high',
    description: 'Slack incoming webhook URL',
  },
  {
    name: 'SENDGRID_KEY',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{42,}/g,
    confidence: 'high',
    description: 'SendGrid API key',
  },
  {
    name: 'TWILIO_AUTH_TOKEN',
    regex: /SK[0-9a-f]{32}/g,
    confidence: 'high',
    description: 'Twilio API key SID',
  },
  {
    name: 'PRIVATE_KEY_BLOCK',
    regex: /-----BEGIN [A-Z ]+PRIVATE KEY-----/g,
    confidence: 'high',
    description: 'PEM private key header',
  },
  {
    name: 'JWT',
    regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    confidence: 'high',
    description: 'JSON Web Token',
  },
];

export const MEDIUM_CONFIDENCE_PATTERNS: CompiledPattern[] = [
  {
    name: 'AWS_SECRET_KEY',
    regex: /(?<=aws_secret_access_key\s*[=:]\s*['"]?)[A-Za-z0-9/+=]{40}/gi,
    confidence: 'medium',
    description: 'AWS secret access key (context-anchored)',
  },
  {
    name: 'AZURE_STORAGE_KEY',
    regex: /(?<=AccountKey=)[A-Za-z0-9+/]{80,}==/g,
    confidence: 'medium',
    description: 'Azure storage account key (context-anchored)',
  },
  {
    name: 'CONNECTION_STRING',
    regex: /(mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+@[^\s'"]+/g,
    confidence: 'medium',
    description: 'Database connection string with credentials',
  },
  {
    name: 'GENERIC_API_KEY',
    regex: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['"][^\s'"]{8,}['"]/gi,
    confidence: 'medium',
    description: 'API key or secret assigned to recognized variable name',
  },
  {
    name: 'GENERIC_SECRET',
    regex: /(?:password|passwd|token|secret|credential)\s*[=:]\s*['"][^\s'"]{8,}['"]/gi,
    confidence: 'medium',
    description: 'Secret value assigned to recognized variable name',
  },
];

/** Known-safe patterns exempt from entropy detection */
export const SAFE_PATTERNS: RegExp[] = [
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
  /(?:commit|ref|sha|hash)\s*[=:]*\s*[0-9a-f]{40}/gi,
];
