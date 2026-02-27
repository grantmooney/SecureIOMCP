/**
 * Error codes returned by SecureIOMCP tools.
 * Error responses never expose resolved paths, project root, or OS details (CWE-209 prevention).
 */
export type ErrorCode =
  /** Path is on the denylist, outside project root, or failed traversal checks */
  | 'PATH_DENIED'
  /** Write content contains a detected secret */
  | 'SECRET_IN_WRITE'
  /** Search pattern is not a valid regular expression */
  | 'INVALID_REGEX'
  /** Requested file does not exist */
  | 'FILE_NOT_FOUND'
  /** File is binary (contains null bytes in first 512 bytes) */
  | 'BINARY_FILE'
  /** File encoding is not supported */
  | 'ENCODING_UNSUPPORTED'
  /** Content exceeds maxWriteBytes limit */
  | 'SIZE_EXCEEDED'
  /** File was modified since last read (optimistic locking failure) */
  | 'HASH_MISMATCH'
  /** Malformed configuration file */
  | 'CONFIG_ERROR'
  /** Unexpected server-side error */
  | 'INTERNAL_ERROR';

/**
 * Structured error response returned to the agent.
 * Designed to be actionable without revealing sensitive system details.
 */
export interface SecureIOError {
  /** Machine-readable error code for programmatic handling */
  code: ErrorCode;
  /** Human-readable description safe to expose to agents (no internal paths or OS info) */
  message: string;
  /** Actionable suggestion for the agent to resolve the issue */
  suggestion?: string;
}

/**
 * Severity level for audit log entries.
 *
 * - `'normal'` -- Standard tool invocation
 * - `'warning'` -- Degraded behavior (e.g., self-test failures)
 * - `'security'` -- Access denials, secret-in-write rejections, path violations
 */
export type AuditSeverity = 'normal' | 'warning' | 'security';

/**
 * Structured audit log entry written as a single JSON line.
 * Write operation params are logged as content hashes, not plaintext.
 */
export interface AuditLogEntry {
  /** ISO 8601 UTC timestamp of the tool invocation */
  timestamp: string;
  /** Name of the MCP tool invoked (e.g., 'secure_read') */
  tool: string;
  /** Tool parameters (content fields are replaced with SHA-256 hash prefixes) */
  params: Record<string, unknown>;
  /** Secrets detected and redacted during this operation */
  redactions: AuditRedaction[];
  /** Whether the request was denied by access control */
  access_denied: boolean;
  /** Severity level for SIEM filtering */
  severity: AuditSeverity;
  /** Operation duration in milliseconds */
  duration_ms: number;
  /** Error code if the operation failed */
  error?: ErrorCode;
}

/** Record of a single secret redaction within an audit log entry. */
export interface AuditRedaction {
  /** Line number where the secret was detected (1-indexed) */
  line: number;
  /** Redaction pattern category (e.g., 'AWS_ACCESS_KEY', 'HIGH_ENTROPY') */
  category: string;
  /** Confidence level of the detection */
  confidence: 'high' | 'medium' | 'entropy';
}
