import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLogEntry, AuditRedaction, AuditSeverity, ErrorCode } from '../types/errors.js';

/** Audit log output destination. */
export type AuditOutput = 'file' | 'stderr' | 'none';

/** Configuration options for the audit logger. */
export interface AuditLogOptions {
  /** Where to write audit entries */
  output: AuditOutput;
  /** File path for file-based output */
  path: string;
  /** Maximum log file size in MB before rotation (default: 50) */
  maxSizeMB?: number;
}

/** Input data for creating an audit log entry from a tool invocation. */
export interface AuditLogInput {
  /** Name of the MCP tool invoked */
  tool: string;
  /** Tool parameters (content fields will be hashed) */
  params: Record<string, unknown>;
  /** Secrets that were redacted during this operation */
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

/**
 * Structured JSON audit logger with tamper protection and automatic rotation.
 *
 * The `.secureio/` directory containing audit logs is on the immutable denylist,
 * preventing agents from reading, modifying, or deleting their own audit trail.
 *
 * Write operation parameters are sanitized: `content` fields are replaced with
 * SHA-256 hash prefixes to avoid storing sensitive data in logs.
 */
export class AuditLogger {
  private options: AuditLogOptions;

  constructor(options: { output: AuditOutput; path?: string; maxSizeMB?: number }) {
    this.options = {
      output: options.output,
      path: options.path ?? '.secureio/audit.log',
      maxSizeMB: options.maxSizeMB ?? 50,
    };
  }

  /**
   * Records an audit log entry for a tool invocation.
   * Sanitizes parameters (hashing content fields) and routes the entry
   * to the configured output (file, stderr, or none).
   *
   * @param input - Tool invocation data to log
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

  /** Appends an audit entry to the log file, creating directories as needed. */
  private async writeToFile(line: string): Promise<void> {
    const logPath = this.options.path;
    const dir = path.dirname(logPath);

    await fs.mkdir(dir, { recursive: true });
    await this.rotateIfNeeded(logPath);
    await fs.appendFile(logPath, line, 'utf-8');
  }

  /** Rotates the log file if it exceeds the configured maximum size. */
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
   * Sanitizes tool parameters for logging by replacing `content` fields
   * with a SHA-256 hash prefix to avoid storing sensitive data.
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
