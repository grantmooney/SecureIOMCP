/**
 * @module types/errors
 * @description Error and audit log type definitions for SecureIOMCP.
 *
 * Error responses follow CWE-209 prevention guidelines — they never expose
 * resolved file paths, project root locations, or operating system details.
 * Error messages are designed to be safe for AI agents to receive and act upon.
 */

/**
 * Standardized error codes returned by SecureIOMCP tool handlers.
 *
 * These codes provide structured error classification without leaking
 * implementation details to the requesting agent.
 *
 * | Code | Description |
 * |------|-------------|
 * | `PATH_DENIED` | Path blocked by denylist, gitignore, or traversal detection |
 * | `SECRET_IN_WRITE` | Write content contains detected secrets |
 * | `INVALID_REGEX` | Search pattern is not a valid regular expression |
 * | `FILE_NOT_FOUND` | Requested file does not exist |
 * | `BINARY_FILE` | File detected as binary (null byte in first 512 bytes) |
 * | `ENCODING_UNSUPPORTED` | File encoding cannot be processed |
 * | `SIZE_EXCEEDED` | Content exceeds configured write size limit |
 * | `HASH_MISMATCH` | Optimistic lock failed — file modified since last read |
 * | `CONFIG_ERROR` | Invalid configuration detected |
 * | `INTERNAL_ERROR` | Unexpected internal error |
 */
export type ErrorCode =
  | 'PATH_DENIED'
  | 'SECRET_IN_WRITE'
  | 'INVALID_REGEX'
  | 'FILE_NOT_FOUND'
  | 'BINARY_FILE'
  | 'ENCODING_UNSUPPORTED'
  | 'SIZE_EXCEEDED'
  | 'HASH_MISMATCH'
  | 'CONFIG_ERROR'
  | 'INTERNAL_ERROR';

/**
 * Structured error response returned by tool handlers when an operation fails.
 *
 * Error messages are deliberately vague about internal paths and system details
 * to prevent information disclosure (CWE-209). The `suggestion` field provides
 * actionable guidance for the AI agent.
 *
 * @example
 * ```typescript
 * {
 *   code: 'PATH_DENIED',
 *   message: 'The requested path is not accessible',
 *   suggestion: 'Use secure_tree to discover available paths within the project.'
 * }
 * ```
 */
export interface SecureIOError {
  /** Machine-readable error classification code. */
  code: ErrorCode;
  /** Human-readable error description (safe for agent consumption — no sensitive details). */
  message: string;
  /** Optional actionable guidance for the agent to recover from the error. */
  suggestion?: string;
}

/**
 * Severity level for audit log entries.
 *
 * - `'normal'` — Standard successful operation.
 * - `'warning'` — Operation completed but with notable conditions (e.g., self-test failures).
 * - `'security'` — Access denied or secret detected in write content. Requires investigation.
 */
export type AuditSeverity = 'normal' | 'warning' | 'security';

/**
 * A single entry in the structured audit log.
 *
 * Every tool invocation produces an audit log entry, regardless of success or failure.
 * Write operation parameters have their `content` field replaced with a SHA-256 hash
 * to prevent audit logs from containing sensitive data.
 *
 * @example
 * ```json
 * {
 *   "timestamp": "2026-02-27T10:30:00.000Z",
 *   "tool": "secure_read",
 *   "params": { "path": "src/index.ts" },
 *   "redactions": [{ "line": 15, "category": "AWS_ACCESS_KEY", "confidence": "high" }],
 *   "access_denied": false,
 *   "severity": "normal",
 *   "duration_ms": 12
 * }
 * ```
 */
export interface AuditLogEntry {
  /** ISO 8601 timestamp of the operation. */
  timestamp: string;
  /** Name of the MCP tool that was invoked (e.g., `'secure_read'`, `'secure_write'`). */
  tool: string;
  /** Sanitized parameters (write content is replaced with `sha256:<hash>`). */
  params: Record<string, unknown>;
  /** List of redactions applied during this operation. */
  redactions: AuditRedaction[];
  /** Whether access was denied for this operation. */
  access_denied: boolean;
  /** Severity classification of this audit event. */
  severity: AuditSeverity;
  /** Wall-clock duration of the operation in milliseconds. */
  duration_ms: number;
  /** Error code if the operation failed. */
  error?: ErrorCode;
}

/**
 * Record of a single redaction applied during a tool operation.
 *
 * Included in audit log entries to provide a detailed trail of what
 * sensitive content was detected and where.
 */
export interface AuditRedaction {
  /** Line number (1-indexed) where the redaction occurred. */
  line: number;
  /** Name of the pattern that matched (e.g., `'AWS_ACCESS_KEY'`, `'HIGH_ENTROPY'`). */
  category: string;
  /** Confidence level of the detection. */
  confidence: 'high' | 'medium' | 'entropy';
}
