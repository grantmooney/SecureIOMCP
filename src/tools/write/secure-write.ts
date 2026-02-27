/**
 * @module secure-write
 *
 * MCP tool handler for `secure_write`. Writes a complete file to the project
 * with mandatory secret scanning and atomic write semantics.
 *
 * Security pipeline per request:
 * 1. Content size check against the configured `maxWriteBytes` limit
 * 2. Write-access check (denylist + bounds + read-only enforcement)
 * 3. Secret scanning of the entire content — write is rejected if secrets
 *    are detected (prevents agents from accidentally persisting credentials)
 * 4. Atomic write via temp file + rename (data is never partially written)
 * 5. SHA-256 hash of the written content returned for optimistic locking
 * 6. Audit-log entry for the operation
 *
 * On Windows, the rename step includes an automatic retry loop to handle
 * transient `EPERM` errors caused by file locking.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { WriteResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Parameters accepted by the `secure_write` MCP tool.
 *
 * @property path    - File path relative to the project root.
 * @property content - The full file content to write (UTF-8).
 */
export interface SecureWriteParams {
  path: string;
  content: string;
}

/**
 * Handle a `secure_write` tool invocation.
 *
 * Validates content size, checks write access through the security middleware,
 * scans the content for embedded secrets, then performs an atomic write
 * (temp file + rename). Returns the file path and a SHA-256 hash of the
 * written content for use with {@link handleSecurePatch}'s optimistic locking.
 * All access -- whether granted or denied -- is recorded in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters (path and content).
 * @returns A {@link SecureResponse} containing a {@link WriteResult},
 *          or an object with a {@link SecureIOError} on failure.
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
      },
    };
  } catch (err: unknown) {
    // Clean up temp file on failure
    try { await fsp.unlink(tmpPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Rename a file from `src` to `dest` with automatic retry on transient errors.
 *
 * On Windows, `fs.rename` can fail with `EPERM` when the target file is
 * momentarily locked by another process (e.g. antivirus scanner). This
 * helper retries up to `retries` times with an exponential back-off
 * (100ms, 200ms, 300ms, ...) before giving up.
 *
 * @param src     - Absolute path of the source (temp) file.
 * @param dest    - Absolute path of the destination file.
 * @param retries - Maximum number of attempts (default 3).
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
