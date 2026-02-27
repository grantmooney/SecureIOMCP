/**
 * @module security/audit-logger
 * @description Structured audit logging for SecureIOMCP operations.
 *
 * The {@link AuditLogger} records every tool invocation as a structured JSON log entry.
 * It provides:
 * - **Immutability** — The audit directory (`.secureio/`) is on the immutable denylist,
 *   preventing agents from reading or tampering with their own audit trail.
 * - **Log rotation** — Automatically rotates log files when they exceed the configured
 *   maximum size (default: 50 MB).
 * - **Parameter sanitization** — Write operation `content` fields are replaced with
 *   SHA-256 hashes to prevent audit logs from containing sensitive data.
 * - **Multiple outputs** — Can write to a file, stderr, or be disabled.
 *
 * Log format: JSON Lines (one JSON object per line), compatible with standard
 * log analysis tools (jq, Datadog, Splunk, ELK).
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLogEntry, AuditRedaction, AuditSeverity, ErrorCode } from '../types/errors.js';

/**
 * Audit log output destination type.
 *
 * - `'file'` — Write to a JSON Lines file (default, recommended for production).
 * - `'stderr'` — Write to stderr for container/sidecar log collection.
 * - `'none'` — Disable audit logging (can be blocked by system policy).
 */
export type AuditOutput = 'file' | 'stderr' | 'none';

/**
 * Configuration options for the audit logger.
 */
export interface AuditLogOptions {
  /** Where to write audit log entries. */
  output: AuditOutput;
  /** Absolute file path for the audit log. */
  path: string;
  /** Maximum log file size in MB before rotation (default: 50). */
  maxSizeMB?: number;
}

/**
 * Input data for creating an audit log entry.
 *
 * Provided by tool handlers after each operation completes (or fails).
 */
export interface AuditLogInput {
  /** Name of the MCP tool that was invoked. */
  tool: string;
  /** Tool parameters (content fields will be hashed). */
  params: Record<string, unknown>;
  /** Redactions applied during this operation. */
  redactions: AuditRedaction[];
  /** Whether access was denied. */
  access_denied: boolean;
  /** Severity level of this event. */
  severity: AuditSeverity;
  /** Duration of the operation in milliseconds. */
  duration_ms: number;
  /** Error code if the operation failed. */
  error?: ErrorCode;
}

/**
 * Structured audit logger for SecureIOMCP operations.
 *
 * Records every tool invocation as a JSON Lines entry with timestamps,
 * sanitized parameters, redaction details, access decisions, and timing.
 *
 * @example
 * ```typescript
 * const logger = new AuditLogger({
 *   output: 'file',
 *   path: '/project/.secureio/audit.log',
 *   maxSizeMB: 50,
 * });
 *
 * await logger.log({
 *   tool: 'secure_read',
 *   params: { path: 'src/config.ts' },
 *   redactions: [],
 *   access_denied: false,
 *   severity: 'normal',
 *   duration_ms: 15,
 * });
 * ```
 */
export class AuditLogger {
  /** Resolved logger options. */
  private options: AuditLogOptions;

  /**
   * Create a new AuditLogger.
   *
   * @param options - Logger configuration.
   * @param options.output - Where to write log entries.
   * @param options.path - File path for file-based output.
   * @param options.maxSizeMB - Maximum file size before rotation (default: 50 MB).
   */
  constructor(options: { output: AuditOutput; path?: string; maxSizeMB?: number }) {
    this.options = {
      output: options.output,
      path: options.path ?? '.secureio/audit.log',
      maxSizeMB: options.maxSizeMB ?? 50,
    };
  }

  /**
   * Record an audit log entry.
   *
   * Creates a structured {@link AuditLogEntry} with an ISO 8601 timestamp,
   * sanitizes parameters (hashing content fields), and writes to the
   * configured output.
   *
   * @param input - The operation data to log.
   */
  async log(input: AuditLogInput): Promise<void> {
    const sanitizedParams = this.sanitizeParams(input.params);

    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      tool: input.tool,
      params: sanitizedParams,
      redactions: input.redactions,
      access_denied: input.access_denied,
      severity: input.severity,
      duration_ms: input.duration_ms,
      ...(input.error ? { error: input.error } : {}),
    };

    const line = JSON.stringify(entry) + '\n';

    if (this.options.output === 'file') {
      await this.writeToFile(line);
    } else if (this.options.output === 'stderr') {
      process.stderr.write(line);
    }
  }

  /**
   * Write a log line to the audit file, creating the directory if needed.
   *
   * @param line - The JSON-serialized log entry (with trailing newline).
   * @internal
   */
  private async writeToFile(line: string): Promise<void> {
    const logPath = this.options.path;
    const dir = path.dirname(logPath);

    await fs.mkdir(dir, { recursive: true });
    await this.rotateIfNeeded(logPath);
    await fs.appendFile(logPath, line, 'utf-8');
  }

  /**
   * Rotate the log file if it exceeds the maximum size.
   *
   * The rotated file is renamed with an ISO 8601 timestamp suffix
   * (e.g., `audit-2026-02-27T10-30-00-000Z.log`).
   *
   * @param logPath - Path to the current log file.
   * @internal
   */
  private async rotateIfNeeded(logPath: string): Promise<void> {
    try {
      const stat = await fs.stat(logPath);
      const maxBytes = (this.options.maxSizeMB ?? 50) * 1024 * 1024;
      if (stat.size >= maxBytes) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const rotatedPath = logPath.replace(/\.log$/, `-${timestamp}.log`);
        await fs.rename(logPath, rotatedPath);
      }
    } catch {
      // File doesn't exist yet
    }
  }

  /**
   * Sanitize tool parameters for safe audit logging.
   *
   * Replaces `content` string values with a truncated SHA-256 hash
   * (`sha256:<first 16 hex chars>`) to prevent audit logs from containing
   * potentially sensitive file content.
   *
   * @param params - Raw tool parameters.
   * @returns Sanitized parameters safe for logging.
   * @internal
   */
  private sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(params)) {
      if (key === 'content' && typeof value === 'string') {
        sanitized[key] = `sha256:${crypto.createHash('sha256').update(value).digest('hex').substring(0, 16)}`;
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
}
