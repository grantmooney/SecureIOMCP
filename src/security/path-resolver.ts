import path from 'node:path';
import { SecureIOError } from '../types/errors.js';

/** Reserved Windows device names that cannot be used as file names. */
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

/**
 * Discriminated union result of a path resolution attempt.
 * On success, contains the validated absolute path. On failure, contains a safe error
 * response that never exposes resolved paths or OS details.
 */
export type PathResult =
  | { ok: true; path: string }
  | { ok: false; error: SecureIOError };

/**
 * Path resolver that canonicalizes, validates, and jails all file paths to the project root.
 * This is the primary defense against CWE-22 (Path Traversal).
 *
 * Validation checks (in order):
 * 1. Null byte rejection
 * 2. Backslash normalization
 * 3. Absolute path rejection
 * 4. UNC path rejection (Windows)
 * 5. Drive letter rejection (Windows)
 * 6. Windows device name rejection (CON, PRN, NUL, etc.)
 * 7. `.git` directory rejection
 * 8. Bounds check (resolved path must be within project root)
 *
 * @example
 * ```typescript
 * const resolver = new PathResolver('/home/user/project');
 * const result = resolver.resolve('src/index.ts');
 * // { ok: true, path: '/home/user/project/src/index.ts' }
 *
 * const denied = resolver.resolve('../../etc/passwd');
 * // { ok: false, error: { code: 'PATH_DENIED', ... } }
 * ```
 */
export class PathResolver {
  private readonly root: string;

  constructor(projectRoot: string) {
    this.root = path.resolve(projectRoot);
  }

  /**
   * Synchronously resolves and validates a relative path against the project root.
   * Does not follow symlinks -- use {@link resolveReal} for symlink-safe resolution.
   *
   * @param inputPath - Path relative to the project root
   * @returns Validated absolute path on success, or a safe error on denial
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
   * Asynchronously resolves a path with symlink/realpath checking.
   * Resolves symlinks and junction points via `fs.realpath()` before performing
   * bounds checks, preventing symlink escape attacks. Handles ELOOP (circular symlinks)
   * gracefully as a path denial. Falls back to the initial resolution for ENOENT (new files).
   *
   * @param inputPath - Path relative to the project root
   * @returns Validated real absolute path on success, or a safe error on denial
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

  /** Returns the absolute path of the project root. */
  getRoot(): string {
    return this.root;
  }

  /** Returns a generic path denial error that never exposes filesystem details. */
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
