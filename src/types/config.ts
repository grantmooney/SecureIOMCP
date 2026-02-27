/**
 * Security preset level controlling the aggressiveness of secret detection and limits.
 *
 * - `'strict'` -- Entropy detection enabled, tighter response/write limits, audit required (default)
 * - `'standard'` -- Pattern matching only (no entropy), more generous limits, audit can be disabled
 */
export type Preset = 'standard' | 'strict';

/**
 * A user-defined or built-in pattern used by the redaction engine to detect secrets.
 *
 * @example
 * ```json
 * {
 *   "name": "AGENCY_TOKEN",
 *   "pattern": "AGCY-[A-Z0-9]{32}",
 *   "description": "Internal agency auth token",
 *   "confidence": "high"
 * }
 * ```
 */
export interface RedactionPattern {
  /** Unique identifier for this pattern, used in `[REDACTED:NAME]` replacements */
  name: string;
  /** Regular expression source string to match against file content */
  pattern: string;
  /** Human-readable description of what this pattern detects */
  description: string;
  /** Detection confidence level affecting how the pattern is applied */
  confidence: 'high' | 'medium' | 'entropy';
}

/**
 * Configuration for extending the immutable denylist with additional file patterns.
 * The built-in denylist entries (`.env`, `*.pem`, `.secureio/`, etc.) cannot be removed.
 */
export interface DenylistConfig {
  /** Glob patterns to add to the denylist (extend-only, cannot remove built-ins) */
  extend: string[];
}

/** Configuration for custom redaction patterns. */
export interface RedactionConfig {
  /** Additional patterns to run alongside the built-in pattern library */
  customPatterns: RedactionPattern[];
}

/** Audit logging configuration controlling where and how audit entries are recorded. */
export interface AuditConfig {
  /** Where audit log entries are written */
  output: 'file' | 'stderr' | 'none';
  /** File path for audit log output (relative to project root) */
  path: string;
  /** Whether audit logging is mandatory (set by system policy) */
  required?: boolean;
  /** Minimum output level enforced by system policy */
  minimumOutput?: 'file' | 'stderr';
}

/**
 * Response and operation size limits controlling token usage and resource consumption.
 * Limits have ceilings that cannot be exceeded: `maxResponseBytes` <= 512 KB, `maxWriteBytes` <= 1 MB.
 */
export interface LimitsConfig {
  /** Maximum number of results returned by search/glob tools */
  maxResultCount: number;
  /** Maximum characters per line before truncation with `[TRUNCATED]` suffix */
  maxLineLength: number;
  /** Hard cap on total response payload in bytes */
  maxResponseBytes: number;
  /** Maximum lines returned by `secure_read` */
  maxFileReadLines: number;
  /** Maximum content size in bytes for write operations */
  maxWriteBytes: number;
  /** Maximum directory traversal depth for `secure_tree` */
  maxTreeDepth: number;
  /** Audit log file size in MB before rotation triggers */
  maxAuditLogSizeMB: number;
}

/**
 * Project-level configuration loaded from `.secureiorc` in the project root.
 * All fields are optional when used as partial config; this interface represents the full shape.
 */
export interface ProjectConfig {
  /** Security preset to use */
  preset: Preset;
  /** Project root directory path */
  projectRoot: string;
  /** Additional denylist patterns */
  denylist: DenylistConfig;
  /** Custom redaction patterns */
  redaction: RedactionConfig;
  /** Audit logging settings */
  audit: AuditConfig;
  /** Response and operation limits */
  limits: LimitsConfig;
}

/**
 * Organization-level security policy loaded from `~/.secureio/policy.json`.
 * System policy overrides project config -- projects can only make settings stricter.
 */
export interface SystemPolicy {
  /** Minimum preset level allowed; projects cannot downgrade below this */
  minimumPreset: Preset;
  /** Additional denylist patterns enforced organization-wide */
  denylist: DenylistConfig;
  /** Additional redaction patterns enforced organization-wide */
  redaction: RedactionConfig;
  /** Audit requirements that cannot be weakened by project config */
  audit: {
    /** Whether audit logging is mandatory */
    required: boolean;
    /** Minimum output level (cannot be set to 'none' if required) */
    minimumOutput: 'file' | 'stderr';
  };
}

/**
 * Final resolved configuration after merging system policy, project config, CLI flags, and defaults.
 * This is the configuration object used at runtime by all security components.
 */
export interface ResolvedConfig {
  /** Active security preset */
  preset: Preset;
  /** Absolute path to the project root directory */
  projectRoot: string;
  /** Extended denylist patterns (in addition to immutable built-ins) */
  denylist: string[];
  /** Custom redaction patterns from system policy and project config */
  redactionPatterns: RedactionPattern[];
  /** Resolved audit configuration */
  audit: AuditConfig;
  /** Resolved size and count limits */
  limits: LimitsConfig;
  /** Whether Shannon entropy-based detection is active (true for strict preset) */
  entropyDetection: boolean;
}
