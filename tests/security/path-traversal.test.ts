import { describe, it, expect } from 'vitest';
import { PathResolver } from '../../src/security/path-resolver.js';
import { TRAVERSAL_CORPUS, DENYLIST_CORPUS } from '../fixtures/traversal-corpus.js';
import { AccessControl } from '../../src/security/access-control.js';
import path from 'node:path';

describe('Path Traversal — Full Corpus', () => {
  const testRoot = path.resolve('tests/fixtures/test-repo');
  const resolver = new PathResolver(testRoot);

  describe('TRAVERSAL_CORPUS: every entry must be rejected', () => {
    for (const attack of TRAVERSAL_CORPUS) {
      it(`rejects: ${JSON.stringify(attack)}`, () => {
        const result = resolver.resolve(attack);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe('PATH_DENIED');
          // Error message must NOT contain the project root
          expect(result.error.message).not.toContain(testRoot);
          expect(result.error.message).not.toContain('test-repo');
        }
      });
    }
  });

  describe('DENYLIST_CORPUS: every entry must be denied by access control', () => {
    const ac = new AccessControl(testRoot, { extendDenylist: [] });

    for (const deniedPath of DENYLIST_CORPUS) {
      it(`denies: ${deniedPath}`, () => {
        expect(ac.isAllowed(deniedPath)).toBe(false);
      });
    }
  });

  describe('Windows-specific attacks', () => {
    it('rejects UNC paths', () => {
      expect(resolver.resolve('\\\\server\\share\\file').ok).toBe(false);
    });

    it('rejects drive letters', () => {
      expect(resolver.resolve('C:\\Windows\\System32').ok).toBe(false);
      expect(resolver.resolve('D:\\secrets.txt').ok).toBe(false);
    });

    it('rejects device names', () => {
      expect(resolver.resolve('CON').ok).toBe(false);
      expect(resolver.resolve('PRN.txt').ok).toBe(false);
      expect(resolver.resolve('NUL').ok).toBe(false);
      expect(resolver.resolve('COM1').ok).toBe(false);
      expect(resolver.resolve('LPT1').ok).toBe(false);
    });

    it('rejects null byte injection', () => {
      expect(resolver.resolve('safe.txt\x00../../etc/passwd').ok).toBe(false);
    });
  });

  describe('Safe paths are allowed', () => {
    it('allows simple relative paths', () => {
      expect(resolver.resolve('src/index.ts').ok).toBe(true);
    });

    it('allows nested paths', () => {
      expect(resolver.resolve('src/utils/helpers.ts').ok).toBe(true);
    });

    it('allows paths with dots in filenames', () => {
      expect(resolver.resolve('package.json').ok).toBe(true);
    });
  });
});
