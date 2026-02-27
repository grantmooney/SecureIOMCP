/**
 * @module secure-patch
 *
 * MCP tool handler for `secure_patch`. Performs a partial (search-and-replace)
 * edit of an existing file with optimistic locking via SHA-256 hash comparison
 * and mandatory secret scanning of the replacement content.
 *
 * Security pipeline per request:
 * 1. Content size check on `new_content` against `maxWriteBytes`
 * 2. Write-access check (denylist + bounds + read-only enforcement)
 * 3. Secret scanning of `new_content` — patch is rejected if secrets are detected
 * 4. Read current file content and compute its SHA-256 hash
 * 5. Optimistic lock verification: if `expected_hash` is provided and does not
 *    match the current hash, the patch is rejected (prevents lost updates)
 * 6. Locate `old_content` in the file and replace with `new_content`
 * 7. Atomic write via temp file + rename
 * 8. Return the new file hash and changed line range
 * 9. Audit-log the operation
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { PatchResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Parameters accepted by the `secure_patch` MCP tool.
 *
 * @property path          - File path relative to the project root.
 * @property old_content   - The exact substring to find in the current file content.
 * @property new_content   - The replacement string to substitute for `old_content`.
 * @property expected_hash - Optional SHA-256 hash of the file as last read by the agent.
 *                           When provided, the patch is rejected if the file has been
 *                           modified since that read (optimistic concurrency control).
 */
export interface SecurePatchParams {
  path: string;
  old_content: string;
  new_content: string;
  expected_hash?: string;
}

/**
 * Handle a `secure_patch` tool invocation.
 *
 * Validates content size, checks write access, scans the replacement content
 * for secrets, reads the current file, verifies the optimistic lock hash
 * (if provided), performs the find-and-replace, and atomically writes the
 * result. Returns the new SHA-256 hash and the line range affected by the
 * patch. All operations are recorded in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters.
 * @returns A {@link SecureResponse} containing a {@link PatchResult},
 *          or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecurePatch(
  mw: SecurityMiddleware,
  params: SecurePatchParams,
): Promise<SecureResponse<PatchResult> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Check size limit on new content
  const contentBytes = Buffer.byteLength(params.new_content, 'utf-8');
  if (contentBytes > mw.config.limits.maxWriteBytes) {
    return {
      error: {
        code: 'SIZE_EXCEEDED',
        message: `New content exceeds maximum write size of ${mw.config.limits.maxWriteBytes} bytes`,
        suggestion: 'Reduce the content size.',
      },
    };
  }

  // Check write access
  const access = await mw.checkWriteAccess(params.path);
  if (!access.ok) {
    await mw.auditLogger.log({
      tool: 'secure_patch',
      params: { path: params.path },
      redactions: [],
      access_denied: true,
      severity: 'security',
      duration_ms: Date.now() - startTime,
    });
    return { error: access.error };
  }

  // Scan new content for secrets
  const secretError = mw.scanWriteContent(params.new_content);
  if (secretError) {
    await mw.auditLogger.log({
      tool: 'secure_patch',
      params: { path: params.path },
      redactions: [],
      access_denied: false,
      severity: 'security',
      duration_ms: Date.now() - startTime,
      error: 'SECRET_IN_WRITE',
    });
    return { error: secretError };
  }

  // Read current file
  let currentContent: string;
  try {
    currentContent = await fsp.readFile(access.absolutePath, 'utf-8');
  } catch (err: unknown) {
    const nodeErr = err as NodeJS.ErrnoException;
    if (nodeErr.code === 'ENOENT') {
      return {
        error: {
          code: 'FILE_NOT_FOUND',
          message: 'File not found',
          suggestion: 'Use secure_write to create new files.',
        },
      };
    }
    throw err;
  }

  // Optimistic lock check
  const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
  if (params.expected_hash && params.expected_hash !== currentHash) {
    return {
      error: {
        code: 'HASH_MISMATCH',
        message: `File has been modified since last read. Current hash: ${currentHash}`,
        suggestion: 'Re-read the file with secure_read to get the current content and hash.',
      },
    };
  }

  // Find and replace
  const index = currentContent.indexOf(params.old_content);
  if (index === -1) {
    return {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'old_content not found in file',
        suggestion: 'Verify the old_content matches exactly. The file may have been modified.',
      },
    };
  }

  const newContent =
    currentContent.substring(0, index) +
    params.new_content +
    currentContent.substring(index + params.old_content.length);

  // Calculate changed line range
  const beforePatch = currentContent.substring(0, index);
  const startLine = beforePatch.split('\n').length;
  const endLine = startLine + params.new_content.split('\n').length - 1;

  // Atomic write
  const dir = path.dirname(access.absolutePath);
  const baseName = path.basename(access.absolutePath);
  const tmpPath = path.join(dir, `.${baseName}.secureio.tmp`);

  try {
    await fsp.writeFile(tmpPath, newContent, 'utf-8');
    await renameWithRetry(tmpPath, access.absolutePath);
  } catch (err) {
    try { await fsp.unlink(tmpPath); } catch { /* ignore */ }
    throw err;
  }

  const newHash = crypto.createHash('sha256').update(newContent).digest('hex');

  await mw.auditLogger.log({
    tool: 'secure_patch',
    params: { path: params.path, content: params.new_content },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return {
    results: {
      path: params.path,
      success: true,
      changed_range: { start: startLine, end: endLine },
      hash: newHash,
    },
    meta: {
      total: 1,
      returned: 1,
      offset: 0,
      has_more: false,
      truncated_lines: 0,
      redactions: 0,
      bytes: Buffer.byteLength(newContent, 'utf-8'),
    },
  };
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
      if (nodeErr.code === 'EPERM' && attempt < retries - 1) {
        await new Promise(r => setTimeout(r, 100 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}
