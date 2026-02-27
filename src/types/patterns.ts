/**
 * A compiled redaction pattern ready for use by the redaction engine.
 * Contains a pre-compiled RegExp for efficient matching against file content.
 */
export interface CompiledPattern {
  /** Unique identifier used in `[REDACTED:NAME]` replacements */
  name: string;
  /** Compiled regular expression (must include the `g` flag for global matching) */
  regex: RegExp;
  /** Detection confidence level */
  confidence: 'high' | 'medium' | 'entropy';
  /** Human-readable description of what this pattern detects */
  description: string;
}

/**
 * A single redaction match found within a line of text.
 * Used to report what was redacted and where, without exposing the secret value.
 */
export interface RedactionMatch {
  /** Start index within the original line */
  start: number;
  /** End index within the original line (exclusive) */
  end: number;
  /** Pattern category that matched (e.g., 'AWS_ACCESS_KEY', 'HIGH_ENTROPY') */
  category: string;
  /** Confidence level of this detection */
  confidence: 'high' | 'medium' | 'entropy';
}
