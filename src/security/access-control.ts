/**
 * @module security/access-control
 * @description File access control using denylist and gitignore rules.
 *
 * The {@link AccessControl} module enforces two layers of file-level access control:
 *
 * 1. **Immutable denylist** — Built-in patterns that always block sensitive files.
 *    Cannot be removed or overridden by any configuration layer. Can only be extended.
 *    Includes: `.env`, `*.pem`, `*.key`, `.aws/`, `.ssh/`, `.secureio/`, etc.
 *
 * 2. **Gitignore rules** — Patterns from `.gitignore` files are loaded recursively
 *    and applied as additional access restrictions. Files that git ignores are also
 *    blocked from agent access.
 *
 * Both layers use gitignore-style pattern syntax via the `ignore` library.
 */

import ignore, { Ignore } from 'ignore';
import fs from 'node:fs';
import path from 'node:path';

/**
 * The immutable built-in denylist.
 *
 * These patterns are **always** applied regardless of configuration.
 * They protect:
 * - Environment files (`.env`, `.env.*`)
 * - Cryptographic keys (`*.pem`, `*.key`, `*.p12`, `*.pfx`)
 * - Credential files (`credentials.json`, `secrets.yaml`)
 * - Cloud provider directories (`.aws/`, `.ssh/`, `.gnupg/`)
 * - SecureIOMCP's own files (`.secureio/`, `.secureiorc`)
 * - Files with "secret" in the name (`*secret*`)
 *
 * @internal
 */
const IMMUTABLE_DENYLIST = [
  '.env',
  '.env.*',
  '*.pem',
  '*.key',
  '*.p12',
  '*.pfx',
  'credentials.json',
  'secrets.yaml',
  '*secret*',
  '.aws/**',
  '.ssh/**',
  '.gnupg/**',
  '.secureio/**',
  '.secureiorc',
];

/**
 * Options for configuring access control.
 */
export interface AccessControlOptions {
  /** Additional gitignore-style patterns to add to the denylist. */
  extendDenylist: string[];
}

/**
 * File access control using immutable denylist and gitignore rules.
 *
 * Determines whether a given file path is accessible to AI agents.
 * A file is blocked if it matches either the denylist or any gitignore rule.
 *
 * The denylist is extend-only: the built-in patterns in {@link IMMUTABLE_DENYLIST}
 * are always present and cannot be removed. Additional patterns can be added
 * via system policy or project configuration.
 *
 * @example
 * ```typescript
 * const ac = new AccessControl('/path/to/project', {
 *   extendDenylist: ['internal/secrets/**'],
 * });
 *
 * ac.isAllowed('src/app.ts');      // true
 * ac.isAllowed('.env');             // false (immutable denylist)
 * ac.isAllowed('.env.local');       // false (immutable denylist)
 * ac.isAllowed('server.pem');       // false (immutable denylist)
 * ac.isAllowed('node_modules/x');   // false (gitignore)
 * ```
 */
export class AccessControl {
  /** Denylist matcher (immutable patterns + extensions). */
  private denylist: Ignore;
  /** Gitignore matcher (loaded recursively from `.gitignore` files). */
  private gitignore: Ignore;

  /**
   * Create a new AccessControl instance.
   *
   * Loads the immutable denylist, applies extensions, and recursively
   * loads all `.gitignore` files from the project directory tree.
   *
   * @param projectRoot - Absolute path to the project root.
   * @param options - Additional denylist patterns to apply.
   */
  constructor(projectRoot: string, options: AccessControlOptions) {
    this.denylist = ignore();
    this.denylist.add(IMMUTABLE_DENYLIST);
    if (options.extendDenylist.length > 0) {
      this.denylist.add(options.extendDenylist);
    }

    this.gitignore = ignore();
    this.loadGitignore(projectRoot, projectRoot);
  }

  /**
   * Check whether a file path is allowed (not blocked by denylist or gitignore).
   *
   * @param relativePath - Path relative to the project root (forward slashes).
   * @returns `true` if the file is accessible, `false` if blocked.
   */
  isAllowed(relativePath: string): boolean {
    const normalized = relativePath.replace(/\\/g, '/');

    if (this.denylist.ignores(normalized)) {
      return false;
    }

    if (this.gitignore.ignores(normalized)) {
      return false;
    }

    return true;
  }

  /**
   * Recursively load `.gitignore` files from the project tree.
   *
   * Patterns from subdirectory `.gitignore` files are prefixed with the
   * relative directory path so they match correctly from the project root.
   * Skips `node_modules` and `.git` directories.
   *
   * @param dir - Current directory being scanned.
   * @param projectRoot - The project root for relative path computation.
   * @internal
   */
  private loadGitignore(dir: string, projectRoot: string): void {
    const gitignorePath = path.join(dir, '.gitignore');
    try {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      const relativeTo = path.relative(projectRoot, dir);
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));

      if (relativeTo === '') {
        this.gitignore.add(lines);
      } else {
        this.gitignore.add(lines.map(l => `${relativeTo}/${l}`));
      }
    } catch {
      // No .gitignore in this directory
    }

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
          this.loadGitignore(path.join(dir, entry.name), projectRoot);
        }
      }
    } catch {
      // Permission error — skip
    }
  }
}
