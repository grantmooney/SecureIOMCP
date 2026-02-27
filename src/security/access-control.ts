import ignore, { Ignore } from 'ignore';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Immutable denylist of file patterns that are always blocked regardless of configuration.
 * These entries cannot be removed or overridden -- users can only extend the denylist.
 * Covers environment files, certificates, credential directories, and the audit trail.
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

/** Options for configuring the access control layer. */
export interface AccessControlOptions {
  /** Additional glob patterns to add to the denylist (supplements immutable built-ins) */
  extendDenylist: string[];
}

/**
 * Access control layer that combines an immutable denylist with `.gitignore` rules
 * to determine which files are accessible to agents.
 *
 * The denylist is extend-only: built-in protections (`.env`, `*.pem`, `.secureio/`, etc.)
 * are always enforced and cannot be removed via configuration.
 *
 * @example
 * ```typescript
 * const ac = new AccessControl('/project/root', { extendDenylist: ['*.tfvars'] });
 * ac.isAllowed('src/index.ts');    // true
 * ac.isAllowed('.env');             // false (immutable denylist)
 * ac.isAllowed('secrets.tfvars');   // false (extended denylist)
 * ```
 */
export class AccessControl {
  private denylist: Ignore;
  private gitignore: Ignore;

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
   * Checks whether a file path is accessible (not blocked by denylist or gitignore).
   *
   * @param relativePath - Path relative to the project root (forward slashes)
   * @returns `true` if the file is accessible, `false` if blocked
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
   * Recursively loads `.gitignore` files from the directory tree.
   * Skips `node_modules` and `.git` directories. Only uses project-scoped ignore rules
   * (not global gitignore or `.git/info/exclude`).
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
