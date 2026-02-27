/**
 * @module secure-tree
 *
 * MCP tool handler for `secure_tree`. Produces a hierarchical directory-structure
 * overview of the project (or a subdirectory), suitable for giving AI agents a
 * quick sense of project layout without reading individual files.
 *
 * The tree is built recursively up to a configurable `max_depth`. At the depth
 * limit, directories are summarised by their file count rather than being fully
 * expanded. Well-known non-source directories (`node_modules`, `.git`, etc.)
 * are automatically skipped, and files on the denylist are excluded from the
 * output.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { TreeEntry, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

/**
 * Parameters accepted by the `secure_tree` MCP tool.
 *
 * @property path      - Optional subdirectory to root the tree at (relative to project root).
 * @property max_depth - Maximum recursion depth (defaults to the configured tree-depth limit).
 */
export interface SecureTreeParams {
  path?: string;
  max_depth?: number;
}

/**
 * Handle a `secure_tree` tool invocation.
 *
 * Recursively builds a {@link TreeEntry} hierarchy starting from the given
 * (or default) root path. Directories beyond `max_depth` are collapsed to
 * a file-count summary. The result is logged to the audit trail.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters.
 * @returns A {@link SecureResponse} containing the root {@link TreeEntry},
 *          or an object with a {@link SecureIOError} on failure.
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
      truncated_lines: 0,
      redactions: 0,
      bytes: Buffer.byteLength(JSON.stringify(tree), 'utf-8'),
    },
  };
}
