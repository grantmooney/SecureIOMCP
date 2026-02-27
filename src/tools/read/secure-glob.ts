/**
 * @module secure-glob
 *
 * MCP tool handler for `secure_glob`. Finds files matching a glob pattern
 * within the project, returning only the relative path and file size for
 * each match. All results are filtered through the security middleware's
 * access-control layer (denylist + bounds check).
 *
 * The glob matching is performed with a pure-JavaScript implementation
 * (no external binaries), supporting `*`, `**`, and `?` wildcards.
 * Pagination is available via `offset` and `max_results`.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { GlobResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { ResponseBuilder } from '../../response.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

/**
 * Parameters accepted by the `secure_glob` MCP tool.
 *
 * @property pattern     - Glob pattern to match files (supports `*`, `**`, `?`).
 * @property path        - Optional subdirectory to scope the search to (relative to project root).
 * @property max_results - Maximum number of results to return.
 * @property offset      - Number of matches to skip for pagination.
 */
export interface SecureGlobParams {
  pattern: string;
  path?: string;
  max_results?: number;
  offset?: number;
}

/**
 * Handle a `secure_glob` tool invocation.
 *
 * Converts the glob pattern to a regular expression via {@link globToRegex},
 * recursively walks the project tree, checks access control for each file,
 * and collects matching entries (path + size) into a paginated response.
 * The invocation is recorded in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters.
 * @returns A {@link SecureResponse} containing an array of {@link GlobResult}
 *          objects, or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecureGlob(
  mw: SecurityMiddleware,
  params: SecureGlobParams,
): Promise<SecureResponse<GlobResult[]> | { error: SecureIOError }> {
  const startTime = Date.now();
  const searchRoot = params.path ?? '.';
  const offset = params.offset ?? 0;
  const builder = new ResponseBuilder<GlobResult>(mw.config.limits, offset);
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  let totalMatches = 0;
  let skipped = 0;

  // Convert glob pattern to regex
  const globRegex = globToRegex(params.pattern);

  async function walk(dir: string): Promise<void> {
    let entries: import('node:fs').Dirent[];
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
        // Check access control
        if (!mw.accessControl.isAllowed(relativePath)) continue;

        // Check glob pattern
        if (!globRegex.test(relativePath) && !globRegex.test(entry.name)) continue;

        totalMatches++;

        if (skipped < offset) {
          skipped++;
          continue;
        }

        try {
          const stat = await fsp.stat(fullPath);
          const added = builder.add({
            path: relativePath,
            size: stat.size,
          });
          if (!added) return; // Stop walking if builder is full
        } catch {
          // Skip files we can't stat
          continue;
        }
      }
    }
  }

  const absSearchRoot = path.resolve(mw.config.projectRoot, searchRoot);
  await walk(absSearchRoot);

  builder.setTotal(totalMatches);

  await mw.auditLogger.log({
    tool: 'secure_glob',
    params: { pattern: params.pattern, path: searchRoot },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return builder.build();
}

/**
 * Convert a glob pattern string into an equivalent {@link RegExp}.
 *
 * Supports the following wildcards:
 * - `**` — matches any sequence of characters including path separators
 * - `*`  — matches any sequence of characters except `/`
 * - `?`  — matches a single character except `/`
 *
 * All other regex-special characters in the input are escaped.
 *
 * @param pattern - The glob pattern to convert.
 * @returns A compiled regular expression equivalent to the glob.
 */
function globToRegex(pattern: string): RegExp {
  let regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars (except * and ?)
    .replace(/\*\*/g, '{{GLOBSTAR}}')       // Temporarily replace **
    .replace(/\*/g, '[^/]*')                // * matches anything except /
    .replace(/\?/g, '[^/]')                 // ? matches single char except /
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');    // ** matches anything including /

  return new RegExp(regexStr);
}
