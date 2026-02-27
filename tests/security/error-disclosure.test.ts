import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityMiddleware } from '../../src/security/middleware.js';
import { getDefaultConfig } from '../../src/config/defaults.js';
import { handleSecureRead } from '../../src/tools/read/secure-read.js';
import { handleSecureSearch } from '../../src/tools/read/secure-search.js';
import { handleSecureGlob } from '../../src/tools/read/secure-glob.js';
import { handleSecureWrite } from '../../src/tools/write/secure-write.js';
import { handleSecurePatch } from '../../src/tools/write/secure-patch.js';
import path from 'node:path';
import os from 'node:os';

describe('Error Disclosure Prevention (CWE-209)', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');
  const sensitiveStrings = [
    testRoot,
    path.resolve(testRoot),
    os.homedir(),
    os.hostname(),
    process.cwd(),
  ];

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  function assertNoDisclosure(errorObj: unknown): void {
    const json = JSON.stringify(errorObj);
    for (const sensitive of sensitiveStrings) {
      expect(json).not.toContain(sensitive);
    }
    // Should not contain Windows-style absolute paths
    expect(json).not.toMatch(/[A-Z]:\\/i);
    // Should not contain Unix-style absolute paths (but allow leading slash in suggestions)
    // Don't check for /etc or similar since error messages may contain safe references
  }

  describe('PATH_DENIED errors', () => {
    it('secure_read: denied path does not leak details', async () => {
      const result = await handleSecureRead(mw, { path: '../../../etc/passwd' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
        assertNoDisclosure(result.error);
      }
    });

    it('secure_read: denylist path does not leak details', async () => {
      const result = await handleSecureRead(mw, { path: '.env' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
        assertNoDisclosure(result.error);
      }
    });

    it('secure_write: denied path does not leak details', async () => {
      const result = await handleSecureWrite(mw, { path: '.env', content: 'test' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
        assertNoDisclosure(result.error);
      }
    });

    it('secure_patch: denied path does not leak details', async () => {
      const result = await handleSecurePatch(mw, {
        path: '.env',
        old_content: 'a',
        new_content: 'b',
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
        assertNoDisclosure(result.error);
      }
    });
  });

  describe('FILE_NOT_FOUND errors', () => {
    it('secure_read: missing file does not leak path', async () => {
      const result = await handleSecureRead(mw, { path: 'src/nonexistent-file.ts' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('FILE_NOT_FOUND');
        assertNoDisclosure(result.error);
      }
    });
  });

  describe('SECRET_IN_WRITE errors', () => {
    it('secure_write: secret detection error does not leak secret', async () => {
      const result = await handleSecureWrite(mw, {
        path: 'src/test-output.ts',
        content: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('SECRET_IN_WRITE');
        assertNoDisclosure(result.error);
        // Error should NOT contain the actual secret
        expect(result.error.message).not.toContain('AKIAIOSFODNN7EXAMPLE');
      }
    });
  });

  describe('SIZE_EXCEEDED errors', () => {
    it('secure_write: size error does not leak path', async () => {
      const bigContent = 'x'.repeat(200000);
      const result = await handleSecureWrite(mw, {
        path: 'src/big-file.ts',
        content: bigContent,
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('SIZE_EXCEEDED');
        assertNoDisclosure(result.error);
      }
    });
  });

  describe('INVALID_REGEX errors', () => {
    it('secure_search: invalid regex does not leak details', async () => {
      const result = await handleSecureSearch(mw, { pattern: '[invalid(' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('INVALID_REGEX');
        assertNoDisclosure(result.error);
      }
    });
  });

  describe('PathResolver error messages', () => {
    it('never contains the word "root"', () => {
      const resolver = mw.pathResolver;
      const result = resolver.resolve('../../../etc/passwd');
      if (!result.ok) {
        expect(result.error.message.toLowerCase()).not.toContain('root');
      }
    });

    it('provides a helpful suggestion', () => {
      const resolver = mw.pathResolver;
      const result = resolver.resolve('../../../etc/passwd');
      if (!result.ok) {
        expect(result.error.suggestion).toBeDefined();
        expect(result.error.suggestion!.length).toBeGreaterThan(0);
      }
    });
  });
});
