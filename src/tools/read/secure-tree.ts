import { SecurityMiddleware } from '../../security/middleware.js';
import { TreeEntry, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

/** Parameters for the `secure_tree` MCP tool. */
export interface SecureTreeParams {
  /** Root directory for the tree (default: project root) */
  path?: string;
  /** Maximum depth to traverse (default: `maxTreeDepth` from config) */
  max_depth?: number;
}

/**
 * Handles the `secure_tree` MCP tool: returns a directory structure with file counts.
 * Recursively traverses directories up to `max_depth`, skipping common non-essential
 * directories (node_modules, .git, dist, build, vendor). Respects access control.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters
 * @returns Directory tree structure with file counts, or a safe error response
 */
export async function handleSecureTree(
  mw: SecurityMiddleware,
  params: SecureTreeParams,
): Promise<SecureResponse<TreeEntry> | { error: SecureIOError }> {
  const startTime = Date.now();
  const treePath = params.path ?? '.';
  const maxDepth = params.max_depth ?? mw.config.limits.maxTreeDepth;
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  const absRoot = path.resolve(mw.config.projectRoot, treePath);

  async function buildTree(dir: string, depth: number): Promise<TreeEntry> {
    const name = path.basename(dir);
    const entry: TreeEntry = { name, type: 'directory', children: [], file_count: 0 };

    if (depth >= maxDepth) {
      // Count files without recursing deeper
      try {
        const items = await fsp.readdir(dir, { withFileTypes: true });
        entry.file_count = items.filter(i => i.isFile()).length;
      } catch {
        // Permission error
      }
      delete entry.children;
      return entry;
    }

    let items: import('node:fs').Dirent[];
    try {
      items = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return entry;
    }

    let fileCount = 0;

    for (const item of items.sort((a, b) => a.name.localeCompare(b.name))) {
      const fullPath = path.join(dir, item.name);
      const relativePath = path.relative(mw.config.projectRoot, fullPath).replace(/\\/g, '/');

      if (item.isDirectory()) {
        if (skipDirs.has(item.name)) continue;
        const childTree = await buildTree(fullPath, depth + 1);
        entry.children!.push(childTree);
      } else if (item.isFile()) {
        if (!mw.accessControl.isAllowed(relativePath)) continue;
        fileCount++;
        entry.children!.push({ name: item.name, type: 'file' });
      }
    }

    entry.file_count = fileCount;
    return entry;
  }

  const tree = await buildTree(absRoot, 0);

  await mw.auditLogger.log({
    tool: 'secure_tree',
    params: { path: treePath, max_depth: maxDepth },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return {
    results: tree,
    meta: {
      total: 1,
      returned: 1,
      offset: 0,
      has_more: false,
      redactions: 0,
    },
  };
}
