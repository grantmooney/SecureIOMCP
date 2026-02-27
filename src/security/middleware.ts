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

/**
 * Discriminated union result of a security access check.
 * On success, contains the validated absolute path. On failure, contains a safe error.
 */
export type SecurityCheckResult =
  | { ok: true; absolutePath: string }
  | { ok: false; error: SecureIOError };

/**
 * Central security middleware that wraps every MCP tool invocation.
 * The security layer is mandatory -- there is no way to bypass it.
 *
 * Orchestrates path resolution, access control, encoding detection,
 * secret redaction, and audit logging across all read and write operations.
 *
 * @example
 * ```typescript
 * const mw = new SecurityMiddleware(config);
 *
 * // Read flow: check access -> read with redaction
 * const access = await mw.checkReadAccess('src/config.ts');
 * if (access.ok) {
 *   const { content, redactedLines } = await mw.readFileSecure(access.absolutePath);
 * }
 *
 * // Write flow: check access -> scan for secrets
 * const writeAccess = await mw.checkWriteAccess('src/output.ts');
 * const secretError = mw.scanWriteContent(newContent);
 * ```
 */
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

  /**
   * Validates a relative path for read access through the full security pipeline.
   * Resolves the path against the project root, checks the denylist and gitignore rules.
   * Error responses never expose filesystem details (CWE-209 prevention).
   *
   * @param relativePath - Path relative to the project root
   * @returns Validated absolute path on success, or a safe error on denial
   */
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

  /**
   * Validates a relative path for write access through the full security pipeline.
   * Uses the same validation as read access but with a write-specific error message.
   *
   * @param relativePath - Path relative to the project root
   * @returns Validated absolute path on success, or a safe error on denial
   */
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

  /**
   * Reads a file with automatic encoding detection, transcoding, and secret redaction.
   * Pipeline: read raw bytes -> detect encoding -> transcode to UTF-8 -> redact each line.
   * All content passes through the redaction engine -- there is no code path that bypasses it.
   *
   * @param absolutePath - Validated absolute path to the file
   * @returns Redacted content, detected encoding, and line numbers where redaction occurred
   * @throws `{ code: 'BINARY_FILE' }` if the file appears to be binary
   */
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

  /**
   * Scans content intended for a write operation for secrets.
   * Returns `null` if the content is clean, or a `SecureIOError` identifying
   * the first detected secret (line number and category, never the value itself).
   *
   * @param content - The content to scan before writing
   * @returns `null` if clean, or an error with the detected secret's category and line
   */
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

  /**
   * Redacts secrets from a single line of text using the redaction engine.
   *
   * @param line - The line of text to redact
   * @returns The redacted text and any matches found
   */
  redactLine(line: string): RedactResult {
    return this.redactionEngine.redactLine(line);
  }
}
