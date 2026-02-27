/**
 * @module types/patterns
 * @description Type definitions for the secret detection pattern system.
 *
 * SecureIOMCP uses a compiled pattern library for real-time secret detection.
 * Patterns are applied line-by-line during file reads, search operations,
 * and write content scanning.
 */

/**
 * A compiled redaction pattern ready for runtime use.
 *
 * Unlike {@link RedactionPattern} (from `types/config`) which stores the pattern
 * as a string, `CompiledPattern` holds a pre-compiled `RegExp` instance for performance.
 * The built-in pattern library in `security/patterns.ts` exports pre-compiled patterns;
 * custom patterns from configuration are compiled during {@link SecurityMiddleware} construction.
 */
export interface CompiledPattern {
  /** Unique name used in `[REDACTED:<name>]` markers and audit logs. */
  name: string;
  /** Pre-compiled regular expression (must use the `g` flag for global matching). */
  regex: RegExp;
  /**
   * Confidence level of detections from this pattern.
   * - `'high'` — Distinct prefix or format, very low false-positive rate.
   * - `'medium'` — Requires context (variable name, protocol prefix) to reduce false positives.
   * - `'entropy'` — Shannon entropy-based detection (not pattern-based).
   */
  confidence: 'high' | 'medium' | 'entropy';
  /** Human-readable description of what this pattern detects. */
  description: string;
}

/**
 * A match found by the redaction engine within a single line.
 *
 * Records the exact position and classification of a detected secret.
 * Multiple matches can occur on a single line.
 */
export interface RedactionMatch {
  /** Start index (0-based) of the match within the line. */
  start: number;
  /** End index (exclusive, 0-based) of the match within the line. */
  end: number;
  /** Pattern name that matched (e.g., `'AWS_ACCESS_KEY'`, `'HIGH_ENTROPY'`). */
  category: string;
  /** Confidence level of this specific match. */
  confidence: 'high' | 'medium' | 'entropy';
}
