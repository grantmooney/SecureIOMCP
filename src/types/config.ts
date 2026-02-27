/**
 * @module types/config
 * @description Configuration type definitions for SecureIOMCP.
 *
 * SecureIOMCP uses a layered configuration system with four levels of precedence
 * (highest to lowest): CLI flags, system policy, project config, built-in defaults.
 *
 * Two security presets are available:
 * - `strict` — Enables entropy detection, lower limits, tighter controls (default)
 * - `standard` — Disables entropy detection, higher limits, more permissive
 *
 * @see {@link ResolvedConfig} for the final merged configuration used at runtime.
 */

/**
 * Security preset level.
 *
 * - `'strict'` — Default. Enables entropy-based secret detection, applies lower size/count limits.
 * - `'standard'` — Disables entropy detection, applies higher size/count limits.
 *   Can be blocked by system policy via {@link SystemPolicy.minimumPreset}.
 */
export type Preset = 'standard' | 'strict';

/**
 * A custom redaction pattern for detecting secrets in file content.
 *
 * Patterns are compiled to regular expressions and applied line-by-line during
 * read operations and write content scanning.
 *
 * @example
 * ```json
 * {
 *   "name": "INTERNAL_TOKEN",
 *   "pattern": "itk_[A-Za-z0-9]{32}",
 *   "description": "Internal service token",
 *   "confidence": "high"
 * }
 * ```
 */
export interface RedactionPattern {
  /** Unique name used in `[REDACTED:<name>]` replacement markers and audit logs. */
  name: string;
  /** Regular expression pattern string (compiled with the `g` flag at runtime). */
  pattern: string;
  /** Human-readable description of what this pattern detects. */
  description: string;
  /**
   * Confidence level of the detection.
   * - `'high'` — Distinct prefix/format, very low false-positive rate (e.g., `AKIA...` for AWS keys).
   * - `'medium'` — Context-anchored patterns requiring a variable name or prefix.
   * - `'entropy'` — Shannon entropy-based detection for unknown secret formats.
   */
  confidence: 'high' | 'medium' | 'entropy';
}

/**
 * Configuration for extending the built-in file denylist.
 *
 * The built-in denylist is **immutable** — it always blocks `.env`, `*.pem`, `*.key`,
 * `.secureio/`, etc. This configuration can only **add** additional patterns.
 */
export interface DenylistConfig {
  /** Additional gitignore-style patterns to deny. Merged with the immutable built-in list. */
  extend: string[];
}

/**
 * Configuration for custom secret redaction patterns.
 *
 * Custom patterns are applied in addition to the built-in high-confidence and
 * medium-confidence pattern libraries.
 */
export interface RedactionConfig {
  /** Additional redaction patterns to apply during read/write operations. */
  customPatterns: RedactionPattern[];
}

/**
 * Audit logging configuration.
 *
 * The audit log records every tool invocation with timestamps, parameters,
 * redaction counts, access decisions, and timing. The audit directory (`.secureio/`)
 * is on the immutable denylist — agents cannot read or tamper with their own audit trail.
 */
export interface AuditConfig {
  /**
   * Where to write audit log entries.
   * - `'file'` — Write to a JSON Lines file at {@link AuditConfig.path} (default).
   * - `'stderr'` — Write to stderr for container/sidecar log collection.
   * - `'none'` — Disable audit logging (can be blocked by system policy).
   */
  output: 'file' | 'stderr' | 'none';
  /** File path for audit log output, relative to project root. Default: `.secureio/audit.log`. */
  path: string;
  /** When `true` in system policy, prevents projects from setting output to `'none'`. */
  required?: boolean;
  /** Minimum output level enforced by system policy. */
  minimumOutput?: 'file' | 'stderr';
}

/**
 * Resource limits for controlling response sizes and preventing abuse.
 *
 * These limits are enforced by the {@link ResponseBuilder} and individual tool handlers.
 * Projects can only make limits **stricter** (lower values) than the preset defaults.
 * Hard ceilings prevent any configuration from exceeding safe maximums.
 */
export interface LimitsConfig {
  /** Maximum number of result items per response (strict: 50, standard: 100). */
  maxResultCount: number;
  /** Maximum characters per line before truncation (default: 2000). */
  maxLineLength: number;
  /** Maximum total response payload in bytes (strict: 50KB, standard: 100KB, ceiling: 512KB). */
  maxResponseBytes: number;
  /** Maximum lines returned by `secure_read` (strict: 500, standard: 1000). */
  maxFileReadLines: number;
  /** Maximum bytes for `secure_write`/`secure_patch` content (strict: 128KB, standard: 256KB, ceiling: 1MB). */
  maxWriteBytes: number;
  /** Maximum directory traversal depth for `secure_tree` (strict: 4, standard: 5). */
  maxTreeDepth: number;
  /** Maximum audit log file size in MB before rotation (default: 50). */
  maxAuditLogSizeMB: number;
}

/**
 * Project-level configuration, typically stored in `.secureiorc` at the project root.
 *
 * Projects can customize their security settings within the bounds allowed by
 * the system policy. Projects can only make settings **stricter** — they cannot
 * override system policy to relax security.
 *
 * @example
 * ```json
 * {
 *   "preset": "strict",
 *   "denylist": { "extend": ["internal/secrets/**"] },
 *   "redaction": { "customPatterns": [] },
 *   "audit": { "output": "file" },
 *   "limits": { "maxWriteBytes": 65536 }
 * }
 * ```
 */
export interface ProjectConfig {
  /** Security preset for this project. */
  preset: Preset;
  /** Absolute path to the project root directory. */
  projectRoot: string;
  /** Additional denylist patterns (extend-only). */
  denylist: DenylistConfig;
  /** Custom redaction patterns for project-specific secrets. */
  redaction: RedactionConfig;
  /** Audit logging preferences. */
  audit: AuditConfig;
  /** Resource limits (can only be made stricter than preset defaults). */
  limits: LimitsConfig;
}

/**
 * System-level security policy, stored at `~/.secureio/policy.json`.
 *
 * System policy is the highest-priority configuration layer (after CLI flags).
 * It enforces organizational security baselines that projects cannot override.
 * This is designed for GovTech environments where security teams need to enforce
 * minimum standards across all projects on a workstation.
 *
 * @example
 * ```json
 * {
 *   "minimumPreset": "strict",
 *   "denylist": { "extend": ["*.pfx", "*.jks"] },
 *   "redaction": { "customPatterns": [] },
 *   "audit": { "required": true, "minimumOutput": "file" }
 * }
 * ```
 */
export interface SystemPolicy {
  /** Minimum preset level. If set to `'strict'`, projects cannot use `'standard'`. */
  minimumPreset: Preset;
  /** Additional denylist patterns enforced at the system level. */
  denylist: DenylistConfig;
  /** Additional redaction patterns enforced at the system level. */
  redaction: RedactionConfig;
  /** Audit enforcement settings. */
  audit: {
    /** When `true`, audit logging cannot be disabled by projects or CLI flags. */
    required: boolean;
    /** Minimum output level. Prevents projects from using a less durable output mode. */
    minimumOutput: 'file' | 'stderr';
  };
}

/**
 * The fully resolved configuration used at runtime.
 *
 * This is the result of merging all configuration layers (defaults, system policy,
 * project config, CLI flags) with precedence rules applied. It is immutable after
 * construction and passed to all security and tool modules.
 */
export interface ResolvedConfig {
  /** Active security preset. */
  preset: Preset;
  /** Absolute path to the project root directory. */
  projectRoot: string;
  /** Merged denylist patterns (built-in + system policy + project config). */
  denylist: string[];
  /** Merged redaction patterns (built-in + system policy + project config). */
  redactionPatterns: RedactionPattern[];
  /** Resolved audit configuration. */
  audit: AuditConfig;
  /** Resolved resource limits with ceilings enforced. */
  limits: LimitsConfig;
  /** Whether Shannon entropy-based secret detection is enabled. `true` for strict preset. */
  entropyDetection: boolean;
}
