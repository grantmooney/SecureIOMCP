/**
 * @module security/patterns
 * @description Built-in secret detection pattern library for SecureIOMCP.
 *
 * This module contains the pre-compiled regex patterns used by the
 * {@link RedactionEngine} to detect secrets in file content. Patterns are
 * organized into three categories:
 *
 * - **High-confidence** — Patterns with distinct prefixes or formats that have
 *   very low false-positive rates. These are always applied.
 * - **Medium-confidence** — Context-anchored patterns that require a variable name
 *   or protocol prefix to reduce false positives.
 * - **Safe patterns** — Known-safe formats (UUIDs, git SHAs, SRI hashes) that are
 *   exempted from entropy-based detection.
 */

import { CompiledPattern } from '../types/patterns.js';

/**
 * High-confidence secret detection patterns.
 *
 * These patterns match secrets with **distinct, well-known prefixes** that
 * virtually guarantee a true positive. They are applied unconditionally.
 *
 * | Pattern | Prefix/Format | Example |
 * |---------|--------------|---------|
 * | AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
 * | GitHub Token | `gh[ps]_...` | `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef` |
 * | GitHub Fine-Grained | `github_pat_...` | `github_pat_...` (82+ chars) |
 * | Stripe Live Key | `sk_live_...` | `sk_live_abcdefghijklmnopqrstuvwx` |
 * | Stripe Publishable | `pk_live_...` | `pk_live_abcdefghijklmnopqrstuvwx` |
 * | Slack Webhook | `https://hooks.slack.com/...` | Full webhook URL |
 * | SendGrid Key | `SG....` | `SG.xxxxxx.yyyyyy` |
 * | Twilio API Key | `SK[0-9a-f]{32}` | `SK` + 32 hex chars |
 * | Private Key Block | `-----BEGIN ... PRIVATE KEY-----` | PEM header |
 * | JWT | `eyJ...eyJ...` | Three base64url segments |
 */
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

/**
 * Medium-confidence secret detection patterns.
 *
 * These patterns use **context anchoring** (variable names, protocol prefixes)
 * to reduce false positives. They match the secret value only when it appears
 * in a recognizable assignment or URL context.
 *
 * | Pattern | Context | Example |
 * |---------|---------|---------|
 * | AWS Secret Key | `aws_secret_access_key=` prefix | `aws_secret_access_key = "ABCD..."` |
 * | Azure Storage Key | `AccountKey=` prefix | `AccountKey=base64...==` |
 * | Connection String | `protocol://user:pass@host` | `postgres://admin:pass@db:5432/mydb` |
 * | Generic API Key | Variable name anchor | `api_key = "abc123..."` |
 * | Generic Secret | Variable name anchor | `password = "s3cret!"` |
 */
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

/**
 * Known-safe patterns exempt from entropy detection.
 *
 * These patterns match high-entropy strings that are **not** secrets:
 * - **UUIDs** — `550e8400-e29b-41d4-a716-446655440000`
 * - **Git commit SHAs** — 40-character hex strings preceded by context words
 * - **Subresource Integrity (SRI) hashes** — `sha256-...`, `sha384-...`, `sha512-...`
 *
 * When a string matches any safe pattern, it is exempted from entropy-based
 * redaction even if its Shannon entropy exceeds the threshold.
 */
export const SAFE_PATTERNS: RegExp[] = [
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
  /(?:commit|ref|sha|hash)\s*[=:]*\s*[0-9a-f]{40}/gi,
  /sha(?:256|384|512)-[A-Za-z0-9+/=_-]+/gi,
];
