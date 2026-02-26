import { SecurityMiddleware } from '../../security/middleware.js';
import { AuditResult, AuditFileDetail, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { transcodeToUtf8, isBinary, detectEncoding } from '../../security/encoding-detector.js';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';

export interface SecureAuditParams {
  path?: string;
  verbose?: boolean;
}

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
