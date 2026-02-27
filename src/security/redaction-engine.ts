import { CompiledPattern, RedactionMatch } from '../types/patterns.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS, SAFE_PATTERNS } from './patterns.js';

/** Result of redacting a single line of text. */
export interface RedactResult {
  /** The line content with secrets replaced by `[REDACTED:CATEGORY]` */
  text: string;
  /** All redaction matches found in this line */
  matches: RedactionMatch[];
}

/**
 * Pattern-based and entropy-based secret detection engine.
 * Applies built-in and custom patterns to detect secrets in text content,
 * replacing matches with `[REDACTED:CATEGORY]` markers.
 *
 * When entropy detection is enabled (strict preset), quoted strings with
 * Shannon entropy > 4.5 and length >= 20 are also flagged as `[REDACTED:HIGH_ENTROPY]`,
 * unless they match known-safe patterns (UUIDs, git SHAs, SRI hashes).
 *
 * @example
 * ```typescript
 * const engine = new RedactionEngine({ entropyDetection: true });
 * const result = engine.redactLine('const key = "AKIAIOSFODNN7EXAMPLE";');
 * // result.text: 'const key = "[REDACTED:AWS_ACCESS_KEY]";'
 * // result.matches: [{ category: 'AWS_ACCESS_KEY', confidence: 'high', ... }]
 * ```
 */
export class RedactionEngine {
  private patterns: CompiledPattern[];
  private entropyEnabled: boolean;
  private safePatterns: RegExp[];

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
   * Redacts secrets from a single line of text.
   * Applies all compiled patterns (high, medium, and custom) followed by
   * entropy-based detection if enabled.
   *
   * @param line - The line of text to scan for secrets
   * @returns The redacted text and an array of all matches found
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
   * Detects high-entropy quoted strings that may be unknown secret formats.
   * Extracts tokens from quoted strings (20+ chars, alphanumeric + special),
   * checks them against safe patterns, and flags those with Shannon entropy > 4.5.
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
   * Checks whether a token matches any known-safe pattern (UUIDs, git SHAs, SRI hashes).
   * Safe tokens are exempt from entropy-based detection to reduce false positives.
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
   * Calculates the Shannon entropy of a string.
   * Higher entropy indicates more randomness, suggesting the string may be a secret.
   * Threshold for detection is > 4.5.
   *
   * @param str - The string to calculate entropy for
   * @returns Entropy value in bits (0 for empty string, up to log2(alphabet_size) for uniform distribution)
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
