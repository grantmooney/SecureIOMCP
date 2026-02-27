/**
 * @module security/path-resolver
 * @description Path resolution and traversal prevention for SecureIOMCP.
 *
 * The {@link PathResolver} ensures that all file paths resolve within the project
 * root boundary. It defends against:
 * - Path traversal (`../`, `../../`)
 * - Absolute paths (`/etc/passwd`)
 * - UNC paths (`\\\\server\\share`)
 * - Windows drive letters (`C:\\...`)
 * - Windows reserved device names (CON, PRN, NUL, etc.)
 * - `.git` directory access
 * - Null byte injection
 * - Symlink escape (via async `resolveReal`)
 * - Circular symlinks (ELOOP)
 *
 * Error responses never expose the resolved path, project root, or OS details
 * (CWE-209 prevention).
 */

import path from 'node:path';
import { SecureIOError } from '../types/errors.js';

/**
 * Windows reserved device names that could cause unexpected behavior.
 * These names are rejected regardless of file extension (e.g., `CON.txt`).
 * @internal
 */
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

/**
 * Result of a path resolution attempt.
 *
 * - On success: `{ ok: true, path: string }` — the resolved absolute path within the project root.
 * - On failure: `{ ok: false, error: SecureIOError }` — a safe error message for the agent.
 */
export type PathResult =
  | { ok: true; path: string }
  | { ok: false; error: SecureIOError };

/**
 * Resolves and validates file paths to prevent directory traversal and escape.
 *
 * All paths are resolved relative to a fixed project root. The resolver ensures
 * that the final resolved path remains within the project root boundary using
 * case-insensitive comparison (for Windows compatibility).
 *
 * @example
 * ```typescript
 * const resolver = new PathResolver('/home/user/project');
 *
 * resolver.resolve('src/app.ts');       // { ok: true, path: '/home/user/project/src/app.ts' }
 * resolver.resolve('../etc/passwd');     // { ok: false, error: { code: 'PATH_DENIED', ... } }
 * resolver.resolve('/etc/passwd');       // { ok: false, error: { code: 'PATH_DENIED', ... } }
 * resolver.resolve('.git/config');       // { ok: false, error: { code: 'PATH_DENIED', ... } }
 * ```
 */
export class PathResolver {
  /** Absolute, normalized path to the project root. */
  private readonly root: string;

  /**
   * @param projectRoot - The project root directory path (will be resolved to absolute).
   */
  constructor(projectRoot: string) {
    this.root = path.resolve(projectRoot);
  }

  /**
   * Resolve a relative path to an absolute path within the project root.
   *
   * Performs synchronous validation only (no filesystem access). For operations
   * that need symlink resolution, use {@link resolveReal} instead.
   *
   * Rejects: null bytes, absolute paths, UNC paths, Windows drive letters,
   * Windows device names, `.git` directory access, and paths that resolve
   * outside the project root.
   *
   * @param inputPath - The path to resolve (relative to project root).
   * @returns A {@link PathResult} indicating success or denial.
   */
  resolve(inputPath: string): PathResult {
    // Reject null bytes
    if (inputPath.includes('\x00')) {
      return this.denied();
    }

    // Normalize backslashes
    const normalized = inputPath.replace(/\\/g, '/');

    // Reject absolute paths
    if (path.isAbsolute(normalized) || normalized.startsWith('//')) {
      return this.denied();
    }

    // Reject UNC paths (Windows)
    if (inputPath.startsWith('\\\\')) {
      return this.denied();
    }

    // Reject Windows drive letters
    if (/^[a-zA-Z]:/.test(inputPath)) {
      return this.denied();
    }

    // Reject Windows device names
    const baseName = path.basename(normalized).split('.')[0].toUpperCase();
    if (WINDOWS_DEVICE_NAMES.has(baseName)) {
      return this.denied();
    }

    // Reject .git internals
    const parts = normalized.split('/');
    if (parts.some(p => p === '.git')) {
      return this.denied();
    }

    // Resolve to absolute path
    const resolved = path.resolve(this.root, normalized);

    // Verify the resolved path is within the project root
    const normalizedResolved = resolved.toLowerCase();
    const normalizedRoot = this.root.toLowerCase();
    if (!normalizedResolved.startsWith(normalizedRoot + path.sep) &&
        normalizedResolved !== normalizedRoot) {
      return this.denied();
    }

    return { ok: true, path: resolved };
  }

  /**
   * Resolve a path with symlink/realpath verification (async).
   *
   * Performs the same checks as {@link resolve}, then additionally resolves
   * symlinks via `fs.realpath()` and verifies the real path is still within
   * the project root. This prevents symlink-based escape attacks.
   *
   * Handles:
   * - `ELOOP` (circular symlinks) — denied
   * - `ENOENT` (file doesn't exist yet) — returns the unresolved path (for new file creation)
   * - Other errors — denied
   *
   * @param inputPath - The path to resolve (relative to project root).
   * @returns A {@link PathResult} indicating success or denial.
   */
  async resolveReal(inputPath: string): Promise<PathResult> {
    const initial = this.resolve(inputPath);
    if (!initial.ok) return initial;

    try {
      const { realpath } = await import('node:fs/promises');
      const real = await realpath(initial.path);
      const normalizedReal = real.toLowerCase();
      const normalizedRoot = this.root.toLowerCase();

      if (!normalizedReal.startsWith(normalizedRoot + path.sep) &&
          normalizedReal !== normalizedRoot) {
        return this.denied();
      }

      return { ok: true, path: real };
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ELOOP') {
        return this.denied();
      }
      if (code === 'ENOENT') {
        return initial;
      }
      return this.denied();
    }
  }

  /**
   * Get the absolute project root path.
   *
   * @returns The resolved project root directory.
   */
  getRoot(): string {
    return this.root;
  }

  /**
   * Create a standard denial response.
   *
   * The error message is deliberately generic to prevent information disclosure
   * (CWE-209). It never reveals the resolved path, project root, or reason for denial.
   *
   * @returns A `PathResult` with a safe error response.
   * @internal
   */
  private denied(): PathResult {
    return {
      ok: false,
      error: {
        code: 'PATH_DENIED',
        message: 'The requested path is not accessible',
        suggestion: 'Use secure_tree to discover available paths within the project.',
      },
    };
  }
}
