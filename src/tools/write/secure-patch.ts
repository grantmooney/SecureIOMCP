import { SecurityMiddleware } from '../../security/middleware.js';
import { PatchResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

/** Parameters for the `secure_patch` MCP tool. */
export interface SecurePatchParams {
  /** File path relative to the project root */
  path: string;
  /** Content to find and replace */
  old_content: string;
  /** Replacement content */
  new_content: string;
  /** SHA-256 hash for optimistic locking (rejects if file changed since last read) */
  expected_hash?: string;
}

/**
 * Handles the `secure_patch` MCP tool: partial file edit with optimistic locking.
 * Pipeline: check size limit -> check write access -> scan new content for secrets ->
 * read current file -> verify hash (if provided) -> find and replace -> atomic write.
 * Returns the changed line range and new file hash after a successful edit.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters including old and new content
 * @returns Patch result with changed range and new hash, or a safe error response
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
      redactions: 0,
    },
  };
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
      if (nodeErr.code === 'EPERM' && attempt < retries - 1) {
        await new Promise(r => setTimeout(r, 100 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}
