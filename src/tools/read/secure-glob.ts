import { SecurityMiddleware } from '../../security/middleware.js';
import { GlobResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { ResponseBuilder } from '../../response.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

export interface SecureGlobParams {
  pattern: string;
  path?: string;
  max_results?: number;
  offset?: number;
}

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

function globToRegex(pattern: string): RegExp {
  let regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars (except * and ?)
    .replace(/\*\*/g, '{{GLOBSTAR}}')       // Temporarily replace **
    .replace(/\*/g, '[^/]*')                // * matches anything except /
    .replace(/\?/g, '[^/]')                 // ? matches single char except /
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');    // ** matches anything including /

  return new RegExp(regexStr);
}
