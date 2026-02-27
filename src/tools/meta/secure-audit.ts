import { SecurityMiddleware } from '../../security/middleware.js';
import { AuditResult, AuditFileDetail, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { transcodeToUtf8, isBinary } from '../../security/encoding-detector.js';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';

/** Parameters for the `secure_audit` MCP tool. */
export interface SecureAuditParams {
  /** Scope audit to this subdirectory (default: project root) */
  path?: string;
  /** Include per-file details with line numbers and categories (default: false) */
  verbose?: boolean;
  /** Include blocked files in verbose details (default: false). Summary count always included. */
  show_blocked?: boolean;
  /** Compact output format (default: true). Set false for structured detail objects. */
  compact?: boolean;
  /** Number of detail entries to skip (for pagination, verbose mode only) */
  offset?: number;
  /** Maximum number of detail entries to return (for pagination, verbose mode only) */
  max_results?: number;
}

/**
 * Handles the `secure_audit` MCP tool: generates a security scan report.
 * Walks the project tree and reports files blocked by the denylist, total secrets
 * detected, and files with secrets. In verbose mode, includes per-file details
 * with redaction line numbers and categories (never the secret values).
 *
 * **Critical invariant:** Summary counts (`files_blocked`, `secrets_detected`,
 * `files_with_secrets`) always reflect the FULL scan. Only the `details` array
 * is paginated via `offset` and `max_results`.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters
 * @returns Audit summary with counts and optional per-file details, or a safe error response
 */
export async function handleSecureAudit(
  mw: SecurityMiddleware,
  params: SecureAuditParams,
): Promise<SecureResponse<AuditResult> | { error: SecureIOError }> {
  const startTime = Date.now();
  const auditPath = params.path ?? '.';
  const verbose = params.verbose ?? false;
  const showBlocked = params.show_blocked ?? false;
  const compact = params.compact ?? true;
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  // Pagination parameters (only apply to verbose details); clamp to sane values
  const offset = Math.max(0, params.offset ?? 0);
  const maxResults = Math.max(1, params.max_results ?? mw.config.limits.maxResultCount);
  const maxBytes = mw.config.limits.maxResponseBytes;

  // Summary counters — always reflect the FULL scan
  let filesBlocked = 0;
  let secretsDetected = 0;
  let filesWithSecrets = 0;

  // Detail tracking for verbose mode
  const details: AuditFileDetail[] = [];
  let totalDetails = 0;
  let detailsSkipped = 0;
  let detailBytes = 0;
  let constrainedBy: 'maxResultCount' | 'maxResponseBytes' | undefined;

  /**
   * Attempts to add a detail entry to the response, respecting offset, maxResults,
   * and maxResponseBytes constraints. Always increments totalDetails and rawDetailBytes.
   */
  function tryAddDetail(detail: AuditFileDetail): void {
    const entryBytes = Buffer.byteLength(JSON.stringify(detail), 'utf-8');
    totalDetails++;

    // Skip entries before offset
    if (detailsSkipped < offset) {
      detailsSkipped++;
      return;
    }

    // Already hit a constraint — don't add more
    if (constrainedBy) return;

    // Check result count limit
    if (details.length >= maxResults) {
      constrainedBy = 'maxResultCount';
      return;
    }

    // Check byte limit (tracks detail bytes only, consistent with ResponseBuilder;
    // envelope overhead is not counted against the limit)
    if (detailBytes + entryBytes > maxBytes) {
      constrainedBy = 'maxResponseBytes';
      return;
    }

    details.push(detail);
    detailBytes += entryBytes;
  }

  const absRoot = path.resolve(mw.config.projectRoot, auditPath);

  async function walk(dir: string): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    // Sort by byte-order for deterministic pagination across platforms/locales
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

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
          if (verbose && showBlocked) {
            tryAddDetail({ path: relativePath, blocked: true, redactions: [] });
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
              tryAddDetail({ path: relativePath, blocked: false, redactions: fileRedactions });
            }
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  await walk(absRoot);

  // Format details: compact mode converts AuditFileDetail[] to string[]
  let formattedDetails: AuditFileDetail[] | string[] | undefined;
  if (verbose) {
    if (compact) {
      formattedDetails = details.map(d => {
        if (d.blocked) return `${d.path}:blocked`;
        const findings = d.redactions
          .map(r => `${r.line}:${r.category}`)
          .join(',');
        return `${d.path}:${findings}`;
      });
    } else {
      formattedDetails = details;
    }
  }

  const result: AuditResult = {
    preset: mw.config.preset,
    files_blocked: filesBlocked,
    secrets_detected: secretsDetected,
    files_with_secrets: filesWithSecrets,
    denylist_rules: 0, // Will count from access control
    custom_patterns: mw.config.redactionPatterns.length,
    ...(formattedDetails ? { details: formattedDetails } : {}),
  };

  await mw.auditLogger.log({
    tool: 'secure_audit',
    params: { path: auditPath, verbose, offset, max_results: params.max_results },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  // In non-verbose mode, meta reflects the single audit result object (not details)
  const metaTotal = verbose ? totalDetails : 1;
  const metaReturned = verbose ? details.length : 1;
  const metaOffset = verbose ? offset : 0;
  const metaHasMore = verbose
    ? offset + details.length < totalDetails
    : false;

  return {
    results: result,
    meta: {
      total: metaTotal,
      returned: metaReturned,
      offset: metaOffset,
      has_more: metaHasMore,
      redactions: secretsDetected,
    },
  };
}
