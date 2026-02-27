import { SecurityMiddleware } from '../../security/middleware.js';
import { ReadResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { estimateTokensSaved } from '../../response.js';

/** Parameters for the `secure_read` MCP tool. */
export interface SecureReadParams {
  /** File path relative to the project root */
  path: string;
  /** Starting line number (1-indexed, default: 1) */
  start_line?: number;
  /** Ending line number (capped by `maxFileReadLines`) */
  end_line?: number;
}

/**
 * Handles the `secure_read` MCP tool: reads a file with automatic secret redaction.
 * Pipeline: check access -> read with encoding detection -> redact -> apply line range.
 * Hard-capped at `maxFileReadLines` lines per request.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters
 * @returns Redacted file content with metadata, or a safe error response
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

    // Raw bytes: what `cat` would return (entire file)
    const rawBytes = Buffer.byteLength(content, 'utf-8');
    const efficientBytes = Buffer.byteLength(selectedContent, 'utf-8');
    const tokensSaved = estimateTokensSaved(rawBytes, efficientBytes);
    const sessionTokensSaved = mw.recordSavings(rawBytes, efficientBytes);

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
        bytes: efficientBytes,
        raw_bytes: rawBytes,
        tokens_saved: tokensSaved,
        session_tokens_saved: sessionTokensSaved,
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
