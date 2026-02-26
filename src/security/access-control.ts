import ignore, { Ignore } from 'ignore';
import fs from 'node:fs';
import path from 'node:path';

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

export interface AccessControlOptions {
  extendDenylist: string[];
}

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
