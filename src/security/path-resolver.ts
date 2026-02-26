import path from 'node:path';
import { SecureIOError } from '../types/errors.js';

const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

export type PathResult =
  | { ok: true; path: string }
  | { ok: false; error: SecureIOError };

export class PathResolver {
  private readonly root: string;

  constructor(projectRoot: string) {
    this.root = path.resolve(projectRoot);
  }

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

  /** Resolve with symlink/realpath check (async — for actual file access) */
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

  getRoot(): string {
    return this.root;
  }

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
