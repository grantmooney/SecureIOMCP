/**
 * @module secure-audit
 *
 * MCP tool handler for `secure_audit`. Performs a security scan of the
 * project tree (or a subdirectory) and produces a summary report of
 * blocked files and detected secrets.
 *
 * The scan walks the file system, checking each file against the
 * access-control denylist and running the redaction engine over readable
 * text files. Binary files are automatically skipped.
 *
 * When `verbose` mode is enabled, the response includes per-file detail
 * records listing the specific redaction locations and categories.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { AuditResult, AuditFileDetail, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { transcodeToUtf8, isBinary, detectEncoding } from '../../security/encoding-detector.js';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Parameters accepted by the `secure_audit` MCP tool.
 *
 * @property path    - Optional subdirectory to scope the audit to (relative to project root).
 * @property verbose - When `true`, include per-file details in the response
 *                     (blocked status, redaction line numbers and categories).
 */
export interface SecureAuditParams {
  path?: string;
  verbose?: boolean;
}

/**
 * Handle a `secure_audit` tool invocation.
 *
 * Recursively walks the project tree starting from the given (or default)
 * root, counts files blocked by the denylist, scans allowed text files for
 * secrets using the redaction engine, and assembles a summary report. In
 * verbose mode the report includes an array of per-file detail records.
 * The invocation is recorded in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters.
 * @returns A {@link SecureResponse} containing an {@link AuditResult},
 *          or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecureAudit(
  mw: SecurityMiddleware,
  params: SecureAuditParams,
): Promise<SecureResponse<AuditResult> | { error: SecureIOError }> {
  const startTime = Date.now();
  const auditPath = params.path ?? '.';
  const verbose = params.verbose ?? false;
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  let filesBlocked = 0;
  let secretsDetected = 0;
  let filesWithSecrets = 0;
  const details: AuditFileDetail[] = [];

  const absRoot = path.resolve(mw.config.projectRoot, auditPath);

  async function walk(dir: string): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(mw.config.projectRoot, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        // Check if blocked by denylist
        if (!mw.accessControl.isAllowed(relativePath)) {
          filesBlocked++;
          if (verbose) {
            details.push({ path: relativePath, blocked: true, redactions: [] });
          }
          continue;
        }

        // Scan file for secrets
        try {
          const buffer = await fsp.readFile(fullPath);
          if (isBinary(buffer)) continue;

          const text = transcodeToUtf8(buffer);
          const lines = text.split('\n');
          const fileRedactions: AuditFileDetail['redactions'] = [];

          for (let i = 0; i < lines.length; i++) {
            const result = mw.redactLine(lines[i]);
            for (const match of result.matches) {
              secretsDetected++;
              fileRedactions.push({
                line: i + 1,
                category: match.category,
                confidence: match.confidence,
              });
            }
          }

          if (fileRedactions.length > 0) {
            filesWithSecrets++;
            if (verbose) {
              details.push({ path: relativePath, blocked: false, redactions: fileRedactions });
            }
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  await walk(absRoot);

  const result: AuditResult = {
    preset: mw.config.preset,
    files_blocked: filesBlocked,
    secrets_detected: secretsDetected,
    files_with_secrets: filesWithSecrets,
    denylist_rules: 0, // Will count from access control
    custom_patterns: mw.config.redactionPatterns.length,
    ...(verbose ? { details } : {}),
  };

  await mw.auditLogger.log({
    tool: 'secure_audit',
    params: { path: auditPath, verbose },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return {
    results: result,
    meta: {
      total: 1,
      returned: 1,
      offset: 0,
      has_more: false,
      truncated_lines: 0,
      redactions: secretsDetected,
      bytes: Buffer.byteLength(JSON.stringify(result), 'utf-8'),
    },
  };
}
