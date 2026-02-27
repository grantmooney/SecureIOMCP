/**
 * @module security/redaction-engine
 * @description Secret detection and redaction engine for SecureIOMCP.
 *
 * The {@link RedactionEngine} applies pattern-based and entropy-based secret detection
 * to text content line-by-line. When a secret is detected, it is replaced with a
 * `[REDACTED:<pattern_name>]` marker, and the match details are recorded.
 *
 * Three detection tiers:
 * 1. **High-confidence patterns** — Distinct prefixes like `AKIA...`, `ghp_...`, `sk_live_...`
 * 2. **Medium-confidence patterns** — Context-anchored (e.g., `aws_secret_access_key=...`)
 * 3. **Entropy detection** — Shannon entropy > 4.5 on quoted strings of 20+ characters
 *
 * False positive prevention uses safe patterns (UUIDs, git SHAs, SRI hashes) to
 * exempt known-safe high-entropy strings from redaction.
 */

import { CompiledPattern, RedactionMatch } from '../types/patterns.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS, SAFE_PATTERNS } from './patterns.js';

/**
 * Result of redacting a single line of text.
 */
export interface RedactResult {
  /** The line text after redaction (secrets replaced with `[REDACTED:...]` markers). */
  text: string;
  /** Details of all matches found in the original line. */
  matches: RedactionMatch[];
}

/**
 * Secret detection and redaction engine.
 *
 * Applies a library of compiled regex patterns and optional Shannon entropy
 * analysis to detect secrets in text content. Designed for line-by-line
 * processing during file reads, search operations, and write content scanning.
 *
 * The engine is stateless per-line — each call to {@link redactLine} is independent.
 * Patterns are applied in order: high-confidence first, then medium-confidence,
 * then custom patterns, then entropy detection (if enabled).
 *
 * @example
 * ```typescript
 * const engine = new RedactionEngine({ entropyDetection: true });
 *
 * engine.redactLine('aws_key = "AKIAIOSFODNN7EXAMPLE"');
 * // { text: 'aws_key = "[REDACTED:AWS_ACCESS_KEY]"', matches: [...] }
 *
 * engine.redactLine('const uuid = "550e8400-e29b-41d4-a716-446655440000"');
 * // { text: 'const uuid = "550e8400-..."', matches: [] }  // UUID is safe-listed
 * ```
 */
export class RedactionEngine {
  /** Combined pattern library (high + medium + custom). */
  private patterns: CompiledPattern[];
  /** Whether Shannon entropy-based detection is enabled. */
  private entropyEnabled: boolean;
  /** Patterns that exempt strings from entropy detection (UUIDs, git SHAs, etc.). */
  private safePatterns: RegExp[];

  /**
   * Create a new RedactionEngine.
   *
   * @param options - Configuration options.
   * @param options.entropyDetection - Enable Shannon entropy-based detection for unknown secret formats.
   * @param options.customPatterns - Additional compiled patterns to include in the detection library.
   */
  constructor(options: {
    entropyDetection: boolean;
    customPatterns?: CompiledPattern[];
  }) {
    this.patterns = [
      ...HIGH_CONFIDENCE_PATTERNS,
      ...MEDIUM_CONFIDENCE_PATTERNS,
      ...(options.customPatterns ?? []),
    ];
    this.entropyEnabled = options.entropyDetection;
    this.safePatterns = [...SAFE_PATTERNS];
  }

  /**
   * Redact secrets from a single line of text.
   *
   * Applies all patterns sequentially, replacing matches with `[REDACTED:<name>]` markers.
   * If entropy detection is enabled, also scans for high-entropy quoted strings.
   *
   * @param line - The line of text to scan and redact.
   * @returns The redacted text and details of all matches found.
   */
  redactLine(line: string): RedactResult {
    const matches: RedactionMatch[] = [];
    let result = line;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(result)) !== null) {
        const replacement = `[REDACTED:${pattern.name}]`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: pattern.name,
          confidence: pattern.confidence,
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        regex.lastIndex = match.index + replacement.length;
      }
    }

    if (this.entropyEnabled) {
      result = this.redactHighEntropy(result, matches);
    }

    return { text: result, matches };
  }

  /**
   * Scan for high-entropy quoted strings that may be unknown secret formats.
   *
   * Targets quoted strings (`"..."` or `'...'`) of 20+ alphanumeric characters.
   * Strings matching safe patterns (UUIDs, git SHAs, SRI hashes) are exempted.
   * Remaining strings with Shannon entropy > 4.5 are redacted.
   *
   * @param line - The line to scan (after pattern-based redaction).
   * @param matches - Accumulator for match details (modified in place).
   * @returns The line with high-entropy strings redacted.
   * @internal
   */
  private redactHighEntropy(line: string, matches: RedactionMatch[]): string {
    const tokenRegex = /['"][A-Za-z0-9+/=_\-]{20,}['"]/g;
    let result = line;
    const regex = new RegExp(tokenRegex.source, tokenRegex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(result)) !== null) {
      const token = match[0].slice(1, -1);

      if (token.startsWith('[REDACTED:')) continue;
      if (this.isSafe(token, result)) continue;

      const entropy = this.shannonEntropy(token);
      if (entropy > 4.5) {
        const quoteChar = match[0][0];
        const replacement = `${quoteChar}[REDACTED:HIGH_ENTROPY]${quoteChar}`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: 'HIGH_ENTROPY',
          confidence: 'entropy',
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        regex.lastIndex = match.index + replacement.length;
      }
    }

    return result;
  }

  /**
   * Check whether a token matches any safe pattern (false positive prevention).
   *
   * @param token - The extracted token (without quotes).
   * @param line - The full line for context-aware matching.
   * @returns `true` if the token is safe and should not be redacted.
   * @internal
   */
  private isSafe(token: string, line: string): boolean {
    for (const safe of this.safePatterns) {
      const regex = new RegExp(safe.source, safe.flags);
      if (regex.test(token) || regex.test(line)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Calculate the Shannon entropy of a string.
   *
   * Higher entropy indicates more randomness, which is characteristic of
   * cryptographic keys, tokens, and other secrets. The threshold of 4.5 bits
   * was chosen to minimize false positives on natural text while catching
   * most secret formats.
   *
   * @param str - The string to analyze.
   * @returns Shannon entropy in bits (0 for empty string, max ~6.5 for random alphanumeric).
   */
  shannonEntropy(str: string): number {
    if (str.length === 0) return 0;
    const freq = new Map<string, number>();
    for (const char of str) {
      freq.set(char, (freq.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
