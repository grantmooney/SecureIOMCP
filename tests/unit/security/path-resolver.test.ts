import { describe, it, expect, beforeEach } from 'vitest';
import { PathResolver } from '../../../src/security/path-resolver.js';
import path from 'node:path';
import os from 'node:os';

describe('PathResolver', () => {
  let resolver: PathResolver;
  const projectRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    resolver = new PathResolver(projectRoot);
  });

  describe('valid paths', () => {
    it('resolves relative paths within project root', () => {
      const result = resolver.resolve('src/index.ts');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.path).toBe(path.join(projectRoot, 'src', 'index.ts'));
      }
    });

    it('resolves nested paths', () => {
      const result = resolver.resolve('src/config.ts');
      expect(result.ok).toBe(true);
    });

    it('resolves paths with ./ prefix', () => {
      const result = resolver.resolve('./src/index.ts');
      expect(result.ok).toBe(true);
    });
  });

  describe('traversal attacks', () => {
    it('rejects basic ../ traversal', () => {
      const result = resolver.resolve('../etc/passwd');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('PATH_DENIED');
        expect(result.error.message).not.toContain(projectRoot);
        expect(result.error.message).not.toContain('/etc/passwd');
      }
    });

    it('rejects deeply nested traversal', () => {
      const result = resolver.resolve('../../../../../../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('rejects null bytes', () => {
      const result = resolver.resolve('safe.txt\x00../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('rejects absolute paths', () => {
      const result = resolver.resolve('/etc/passwd');
      expect(result.ok).toBe(false);
    });

    if (os.platform() === 'win32') {
      it('rejects Windows absolute paths', () => {
        const result = resolver.resolve('C:\\Windows\\System32\\config\\SAM');
        expect(result.ok).toBe(false);
      });

      it('rejects UNC paths', () => {
        const result = resolver.resolve('\\\\server\\share\\file');
        expect(result.ok).toBe(false);
      });

      it('rejects Windows device names', () => {
        for (const name of ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']) {
          const result = resolver.resolve(name);
          expect(result.ok).toBe(false);
        }
      });
    }
  });

  describe('.git internals', () => {
    it('rejects .git/config', () => {
      const result = resolver.resolve('.git/config');
      expect(result.ok).toBe(false);
    });

    it('rejects .git/objects', () => {
      const result = resolver.resolve('.git/objects/pack/something.pack');
      expect(result.ok).toBe(false);
    });

    it('rejects .git/HEAD', () => {
      const result = resolver.resolve('.git/HEAD');
      expect(result.ok).toBe(false);
    });
  });

  describe('backslash normalization', () => {
    it('normalizes backslashes to forward slashes', () => {
      const result = resolver.resolve('src\\index.ts');
      expect(result.ok).toBe(true);
    });
  });

  describe('error sanitization', () => {
    it('never leaks project root in error messages', () => {
      const result = resolver.resolve('../../secret');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).not.toContain(projectRoot);
        expect(JSON.stringify(result.error)).not.toContain(projectRoot);
      }
    });

    it('never leaks resolved path in error messages', () => {
      const result = resolver.resolve('../../../etc/passwd');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).not.toContain('etc/passwd');
      }
    });
  });
});
