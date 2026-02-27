/**
 * @module secure-read
 *
 * MCP tool handler for `secure_read`. Reads files from the project with
 * automatic secret redaction, encoding detection, and binary-file rejection.
 *
 * Security pipeline per request:
 * 1. Access-control check (denylist + bounds)
 * 2. Binary-file detection (rejected with a safe error)
 * 3. Encoding detection (UTF-8 / UTF-16 via BOM) with transcoding
 * 4. Secret redaction on every returned line
 * 5. Audit-log entry (including any redacted line numbers)
 *
 * Supports optional line-range parameters (`start_line`, `end_line`) for
 * token-efficient partial reads.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { ReadResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';

/**
 * Parameters accepted by the `secure_read` MCP tool.
 *
 * @property path       - File path relative to the project root.
 * @property start_line - Optional 1-indexed start line (defaults to 1).
 * @property end_line   - Optional 1-indexed end line (clamped to file length and max-read-lines limit).
 */
export interface SecureReadParams {
  path: string;
  start_line?: number;
  end_line?: number;
}

/**
 * Handle a `secure_read` tool invocation.
 *
 * Reads the target file through the security middleware, applies line-range
 * selection, redacts secrets, and returns the content together with pagination
 * metadata. All access — whether granted or denied — is recorded in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters (path, optional line range).
 * @returns A {@link SecureResponse} containing the file content and metadata,
 *          or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecureRead(
  mw: SecurityMiddleware,
  params: SecureReadParams,
): Promise<SecureResponse<ReadResult> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Check access
  const access = await mw.checkReadAccess(params.path);
  if (!access.ok) {
    await mw.auditLogger.log({
      tool: 'secure_read',
      params: { path: params.path },
      redactions: [],
      access_denied: true,
      severity: 'security',
      duration_ms: Date.now() - startTime,
    });
    return { error: access.error };
  }

  try {
    const { content, encoding, redactedLines } = await mw.readFileSecure(access.absolutePath);
    const allLines = content.split('\n');

    // Apply line range
    const start = Math.max(1, params.start_line ?? 1);
    const maxEnd = Math.min(allLines.length, start + mw.config.limits.maxFileReadLines - 1);
    const end = params.end_line ? Math.min(params.end_line, maxEnd) : maxEnd;

    const selectedLines = allLines.slice(start - 1, end);
    const selectedContent = selectedLines.join('\n');

    // Filter redacted lines to the selected range
    const rangeRedactedLines = redactedLines.filter(l => l >= start && l <= end);

    await mw.auditLogger.log({
      tool: 'secure_read',
      params: { path: params.path, start_line: start, end_line: end },
      redactions: rangeRedactedLines.map(l => ({
        line: l,
        category: 'REDACTED',
        confidence: 'high' as const,
      })),
      access_denied: false,
      severity: 'normal',
      duration_ms: Date.now() - startTime,
    });

    return {
      results: {
        path: params.path,
        content: selectedContent,
        start_line: start,
        end_line: end,
        total_lines: allLines.length,
        redacted_lines: rangeRedactedLines,
        encoding_detected: encoding,
      },
      meta: {
        total: allLines.length,
        returned: selectedLines.length,
        offset: start - 1,
        has_more: end < allLines.length,
        truncated_lines: 0,
        redactions: rangeRedactedLines.length,
        bytes: Buffer.byteLength(selectedContent, 'utf-8'),
      },
    };
  } catch (err: unknown) {
    const nodeErr = err as NodeJS.ErrnoException & { code?: string };
    if (nodeErr.code === 'ENOENT') {
      return {
        error: {
          code: 'FILE_NOT_FOUND',
          message: 'File not found',
          suggestion: 'Use secure_glob to find available files.',
        },
      };
    }
    if (nodeErr.code === 'BINARY_FILE') {
      return {
        error: {
          code: 'BINARY_FILE',
          message: 'File appears to be binary',
          suggestion: 'Use secure_glob to discover file types.',
        },
      };
    }
    throw err;
  }
}
