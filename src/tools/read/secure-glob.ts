import { SecurityMiddleware } from '../../security/middleware.js';
import { GlobResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { ResponseBuilder } from '../../response.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

/** Parameters for the `secure_glob` MCP tool. */
export interface SecureGlobParams {
  /** Glob pattern to match files (supports `*`, `**`, `?`) */
  pattern: string;
  /** Scope search to this subdirectory */
  path?: string;
  /** Maximum results to return */
  max_results?: number;
  /** Offset for pagination */
  offset?: number;
  /** Compact output format (default: true). Set false for structured objects with size. */
  compact?: boolean;
}

/**
 * Handles the `secure_glob` MCP tool: finds files by glob pattern.
 * Returns file paths (compact) or paths+sizes (structured). Respects access control
 * and never returns denylist files. Supports pagination.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters including the glob pattern
 * @returns Paginated list of matching files, or a safe error response
 */
export async function handleSecureGlob(
  mw: SecurityMiddleware,
  params: SecureGlobParams,
): Promise<SecureResponse<(GlobResult | string)[]> | { error: SecureIOError }> {
  const startTime = Date.now();
  const searchRoot = params.path ?? '.';
  const offset = params.offset ?? 0;
  const compact = params.compact ?? true;
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  // Collect all matching paths first
  const matchedPaths: string[] = [];
  const matchedFullPaths: string[] = [];
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
        if (!mw.accessControl.isAllowed(relativePath)) continue;
        if (!globRegex.test(relativePath) && !globRegex.test(entry.name)) continue;

        matchedPaths.push(relativePath);
        matchedFullPaths.push(fullPath);
      }
    }
  }

  const absSearchRoot = path.resolve(mw.config.projectRoot, searchRoot);
  await walk(absSearchRoot);

  const totalMatches = matchedPaths.length;

  let response: SecureResponse<(GlobResult | string)[]>;

  if (compact) {
    const builder = new ResponseBuilder<string>(mw.config.limits, offset);
    let skipped = 0;

    for (const relativePath of matchedPaths) {
      if (skipped < offset) { skipped++; continue; }
      if (!builder.add(relativePath)) break;
    }

    builder.setTotal(totalMatches);
    response = builder.build();
  } else {
    const builder = new ResponseBuilder<GlobResult>(mw.config.limits, offset);
    let skipped = 0;

    for (let idx = 0; idx < matchedPaths.length; idx++) {
      if (skipped < offset) { skipped++; continue; }

      try {
        const stat = await fsp.stat(matchedFullPaths[idx]);
        if (!builder.add({ path: matchedPaths[idx], size: stat.size })) break;
      } catch {
        continue;
      }
    }

    builder.setTotal(totalMatches);
    response = builder.build();
  }

  await mw.auditLogger.log({
    tool: 'secure_glob',
    params: { pattern: params.pattern, path: searchRoot },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return response;
}

/**
 * Converts a glob pattern to a regular expression.
 * Supports `**` (any path), `*` (any non-separator), and `?` (single non-separator char).
 *
 * @param pattern - Glob pattern to convert
 * @returns Compiled RegExp for matching against file paths
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
