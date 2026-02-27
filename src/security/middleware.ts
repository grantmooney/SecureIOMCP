/**
 * @module security/middleware
 * @description Central security middleware that orchestrates all security checks.
 *
 * The {@link SecurityMiddleware} is the single entry point for all security operations.
 * It composes the five security subsystems (path resolution, access control, redaction,
 * audit logging, encoding detection) into a unified API used by all tool handlers.
 *
 * This middleware is **mandatory** — there is no way to bypass it. Every tool handler
 * receives a `SecurityMiddleware` instance and must use it for all file operations.
 *
 * @example
 * ```typescript
 * const mw = new SecurityMiddleware(config);
 *
 * // Read path: resolve -> access check -> read -> detect encoding -> redact -> audit
 * const access = await mw.checkReadAccess('src/config.ts');
 * if (access.ok) {
 *   const file = await mw.readFileSecure(access.absolutePath);
 * }
 *
 * // Write path: resolve -> access check -> scan for secrets -> audit
 * const writeAccess = await mw.checkWriteAccess('src/output.ts');
 * const scanResult = mw.scanWriteContent(content);
 * ```
 */

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
 * Result of a security access check.
 *
 * - On success: `{ ok: true, absolutePath: string }` — the resolved absolute path is safe to use.
 * - On failure: `{ ok: false, error: SecureIOError }` — contains a safe error message for the agent.
 */
export type SecurityCheckResult =
  | { ok: true; absolutePath: string }
  | { ok: false; error: SecureIOError };

/**
 * Central security middleware that wraps every tool operation.
 *
 * Composes path resolution, access control, redaction, audit logging, and
 * encoding detection into a single orchestration layer. All tool handlers
 * receive an instance of this class and delegate security decisions to it.
 *
 * The middleware is constructed once during server initialization from the
 * fully resolved configuration and is immutable thereafter.
 *
 * @see {@link PathResolver} for path traversal prevention.
 * @see {@link AccessControl} for denylist and gitignore enforcement.
 * @see {@link RedactionEngine} for secret detection and masking.
 * @see {@link AuditLogger} for structured operation logging.
 */
export class SecurityMiddleware {
  /** Path resolver for traversal prevention and bounds checking. */
  readonly pathResolver: PathResolver;
  /** Access control for denylist and gitignore enforcement. */
  readonly accessControl: AccessControl;
  /** Redaction engine for secret detection and masking. */
  readonly redactionEngine: RedactionEngine;
  /** Audit logger for structured operation logging. */
  readonly auditLogger: AuditLogger;
  /** The fully resolved configuration driving all security decisions. */
  readonly config: ResolvedConfig;

  /**
   * Create a new SecurityMiddleware instance.
   *
   * Initializes all security subsystems from the resolved configuration:
   * - PathResolver with the project root as the containment boundary
   * - AccessControl with built-in + extended denylist and gitignore rules
   * - RedactionEngine with built-in + custom patterns and entropy settings
   * - AuditLogger with the configured output mode and rotation settings
   *
   * @param config - The fully resolved configuration from {@link loadConfig}.
   */
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
   * Validate a relative path for read access.
   *
   * Performs path resolution (traversal prevention, bounds checking) followed
   * by access control (denylist, gitignore). Returns the resolved absolute path
   * on success, or a safe error message on failure.
   *
   * @param relativePath - Path relative to the project root.
   * @returns Security check result with absolute path or error.
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
   * Validate a relative path for write access.
   *
   * Same security checks as {@link checkReadAccess} but with a write-specific
   * error message.
   *
   * @param relativePath - Path relative to the project root.
   * @returns Security check result with absolute path or error.
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
   * Read a file with encoding detection, binary rejection, and secret redaction.
   *
   * Pipeline: read raw bytes -> detect binary -> detect encoding -> transcode to UTF-8 -> redact secrets
   *
   * @param absolutePath - The absolute file path (must be pre-validated via {@link checkReadAccess}).
   * @returns Object containing the redacted content, detected encoding, and line numbers where redactions occurred.
   * @throws `{ code: 'BINARY_FILE' }` if the file appears to be binary.
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
   * Scan content intended for writing to detect embedded secrets.
   *
   * Used by `secure_write` and `secure_patch` to reject write operations
   * that would introduce secrets into the codebase.
   *
   * @param content - The content to scan.
   * @returns A {@link SecureIOError} if secrets are detected, or `null` if clean.
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
   * Redact a single line of text using the configured redaction engine.
   *
   * Convenience method used by tool handlers that process content line-by-line
   * (e.g., `secure_search` for context lines, `secure_diff` for diff hunks).
   *
   * @param line - The line of text to redact.
   * @returns The redaction result with masked text and match details.
   */
  redactLine(line: string): RedactResult {
    return this.redactionEngine.redactLine(line);
  }
}
