import { SecurityMiddleware } from '../../security/middleware.js';
import { WriteResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

/** Parameters for the `secure_write` MCP tool. */
export interface SecureWriteParams {
  /** File path relative to the project root */
  path: string;
  /** File content to write */
  content: string;
}

/**
 * Handles the `secure_write` MCP tool: writes a file with secret scanning.
 * Pipeline: check size limit -> check write access -> scan for secrets -> atomic write.
 * Rejects content containing detected secrets (returns category and line, not the value).
 * Uses atomic writes (temp file + rename) with retry for Windows file locking.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters including path and content
 * @returns Write result with SHA-256 hash on success, or a safe error response
 */
export async function handleSecureWrite(
  mw: SecurityMiddleware,
  params: SecureWriteParams,
): Promise<SecureResponse<WriteResult> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Check size limit
  const contentBytes = Buffer.byteLength(params.content, 'utf-8');
  if (contentBytes > mw.config.limits.maxWriteBytes) {
    return {
      error: {
        code: 'SIZE_EXCEEDED',
        message: `Content exceeds maximum write size of ${mw.config.limits.maxWriteBytes} bytes`,
        suggestion: 'Reduce the content size or use secure_patch for partial edits.',
      },
    };
  }

  // Check write access
  const access = await mw.checkWriteAccess(params.path);
  if (!access.ok) {
    await mw.auditLogger.log({
      tool: 'secure_write',
      params: { path: params.path },
      redactions: [],
      access_denied: true,
      severity: 'security',
      duration_ms: Date.now() - startTime,
    });
    return { error: access.error };
  }

  // Scan content for secrets
  const secretError = mw.scanWriteContent(params.content);
  if (secretError) {
    await mw.auditLogger.log({
      tool: 'secure_write',
      params: { path: params.path },
      redactions: [],
      access_denied: false,
      severity: 'security',
      duration_ms: Date.now() - startTime,
      error: 'SECRET_IN_WRITE',
    });
    return { error: secretError };
  }

  // Atomic write: temp file + rename
  const dir = path.dirname(access.absolutePath);
  const baseName = path.basename(access.absolutePath);
  const tmpPath = path.join(dir, `.${baseName}.secureio.tmp`);

  try {
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(tmpPath, params.content, 'utf-8');

    // Rename with retry for Windows
    await renameWithRetry(tmpPath, access.absolutePath);

    const hash = crypto.createHash('sha256').update(params.content).digest('hex');

    await mw.auditLogger.log({
      tool: 'secure_write',
      params: { path: params.path, content: params.content },
      redactions: [],
      access_denied: false,
      severity: 'normal',
      duration_ms: Date.now() - startTime,
    });

    return {
      results: {
        path: params.path,
        success: true,
        hash,
      },
      meta: {
        total: 1,
        returned: 1,
        offset: 0,
        has_more: false,
        truncated_lines: 0,
        redactions: 0,
        bytes: contentBytes,
        raw_bytes: contentBytes,
        tokens_saved: 0,
        session_tokens_saved: mw.sessionTokensSaved,
      },
    };
  } catch (err: unknown) {
    // Clean up temp file on failure
    try { await fsp.unlink(tmpPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Renames a file with retry logic for Windows EPERM errors.
 * On Windows, `rename` can fail with EPERM if the target file is locked by another process.
 * Retries up to 3 times with 100ms backoff between attempts.
 */
async function renameWithRetry(src: string, dest: string, retries = 3): Promise<void> {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      await fsp.rename(src, dest);
      return;
    } catch (err: unknown) {
      const nodeErr = err as NodeJS.ErrnoException;
      // EPERM on Windows when target is locked
      if (nodeErr.code === 'EPERM' && attempt < retries - 1) {
        await new Promise(r => setTimeout(r, 100 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}
