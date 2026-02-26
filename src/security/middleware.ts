import { PathResolver, PathResult } from './path-resolver.js';
import { AccessControl } from './access-control.js';
import { RedactionEngine, RedactResult } from './redaction-engine.js';
import { AuditLogger, AuditLogInput } from './audit-logger.js';
import { transcodeToUtf8, detectEncoding, isBinary } from './encoding-detector.js';
import { ResolvedConfig } from '../types/config.js';
import { SecureIOError } from '../types/errors.js';
import { CompiledPattern } from '../types/patterns.js';
import fs from 'node:fs/promises';
import path from 'node:path';

export type SecurityCheckResult =
  | { ok: true; absolutePath: string }
  | { ok: false; error: SecureIOError };

export class SecurityMiddleware {
  readonly pathResolver: PathResolver;
  readonly accessControl: AccessControl;
  readonly redactionEngine: RedactionEngine;
  readonly auditLogger: AuditLogger;
  readonly config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this.config = config;
    this.pathResolver = new PathResolver(config.projectRoot);
    this.accessControl = new AccessControl(config.projectRoot, {
      extendDenylist: config.denylist,
    });
    this.redactionEngine = new RedactionEngine({
      entropyDetection: config.entropyDetection,
      customPatterns: config.redactionPatterns.map(p => ({
        name: p.name,
        regex: new RegExp(p.pattern, 'g'),
        confidence: p.confidence,
        description: p.description,
      })),
    });
    this.auditLogger = new AuditLogger({
      output: config.audit.output,
      path: path.resolve(config.projectRoot, config.audit.path),
      maxSizeMB: config.limits.maxAuditLogSizeMB,
    });
  }

  /** Validate a path for read access */
  async checkReadAccess(relativePath: string): Promise<SecurityCheckResult> {
    const resolved = this.pathResolver.resolve(relativePath);
    if (!resolved.ok) return resolved;

    const relToRoot = path.relative(this.config.projectRoot, resolved.path);
    if (!this.accessControl.isAllowed(relToRoot)) {
      return {
        ok: false,
        error: {
          code: 'PATH_DENIED',
          message: 'The requested path is not accessible',
          suggestion: 'Use secure_tree to discover available paths within the project.',
        },
      };
    }

    return { ok: true, absolutePath: resolved.path };
  }

  /** Validate a path for write access */
  async checkWriteAccess(relativePath: string): Promise<SecurityCheckResult> {
    const resolved = this.pathResolver.resolve(relativePath);
    if (!resolved.ok) return resolved;

    const relToRoot = path.relative(this.config.projectRoot, resolved.path);
    if (!this.accessControl.isAllowed(relToRoot)) {
      return {
        ok: false,
        error: {
          code: 'PATH_DENIED',
          message: 'The requested path is not accessible for writing',
          suggestion: 'This path is on the denylist and cannot be written to.',
        },
      };
    }

    return { ok: true, absolutePath: resolved.path };
  }

  /** Read a file with encoding detection and redaction */
  async readFileSecure(absolutePath: string): Promise<{ content: string; encoding: string; redactedLines: number[] }> {
    const rawBuffer = await fs.readFile(absolutePath);

    if (isBinary(rawBuffer)) {
      throw { code: 'BINARY_FILE' as const, message: 'File appears to be binary' };
    }

    const encoding = detectEncoding(rawBuffer);
    const text = transcodeToUtf8(rawBuffer);
    const lines = text.split('\n');
    const redactedLines: number[] = [];
    const processedLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const result = this.redactionEngine.redactLine(lines[i]);
      processedLines.push(result.text);
      if (result.matches.length > 0) {
        redactedLines.push(i + 1); // 1-indexed
      }
    }

    return {
      content: processedLines.join('\n'),
      encoding,
      redactedLines,
    };
  }

  /** Scan write content for secrets — returns error if secrets found */
  scanWriteContent(content: string): SecureIOError | null {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const result = this.redactionEngine.redactLine(lines[i]);
      if (result.matches.length > 0) {
        const firstMatch = result.matches[0];
        return {
          code: 'SECRET_IN_WRITE',
          message: `Content rejected: secret detected on line ${i + 1}, category: ${firstMatch.category}`,
          suggestion: 'Remove the secret from the content before writing.',
        };
      }
    }
    return null;
  }

  /** Redact a single line of text */
  redactLine(line: string): RedactResult {
    return this.redactionEngine.redactLine(line);
  }
}
