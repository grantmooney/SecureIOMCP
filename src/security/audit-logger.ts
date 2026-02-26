import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLogEntry, AuditRedaction, AuditSeverity, ErrorCode } from '../types/errors.js';

export type AuditOutput = 'file' | 'stderr' | 'none';

export interface AuditLogOptions {
  output: AuditOutput;
  path: string;
  maxSizeMB?: number;
}

export interface AuditLogInput {
  tool: string;
  params: Record<string, unknown>;
  redactions: AuditRedaction[];
  access_denied: boolean;
  severity: AuditSeverity;
  duration_ms: number;
  error?: ErrorCode;
}

export class AuditLogger {
  private options: AuditLogOptions;

  constructor(options: { output: AuditOutput; path?: string; maxSizeMB?: number }) {
    this.options = {
      output: options.output,
      path: options.path ?? '.secureio/audit.log',
      maxSizeMB: options.maxSizeMB ?? 50,
    };
  }

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

  private async writeToFile(line: string): Promise<void> {
    const logPath = this.options.path;
    const dir = path.dirname(logPath);

    await fs.mkdir(dir, { recursive: true });
    await this.rotateIfNeeded(logPath);
    await fs.appendFile(logPath, line, 'utf-8');
  }

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
