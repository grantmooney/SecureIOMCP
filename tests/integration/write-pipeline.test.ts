import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SecurityMiddleware } from '../../src/security/middleware.js';
import { getDefaultConfig } from '../../src/config/defaults.js';
import { handleSecureWrite } from '../../src/tools/write/secure-write.js';
import { handleSecurePatch } from '../../src/tools/write/secure-patch.js';
import { handleSecureRead } from '../../src/tools/read/secure-read.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

describe('Write Pipeline Integration', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');
  const testFile = 'src/write-test-output.ts';

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  afterEach(async () => {
    try {
      await fsp.unlink(path.join(testRoot, testFile));
    } catch { /* file may not exist */ }
  });

  describe('secure_write full pipeline', () => {
    it('writes clean content successfully', async () => {
      const content = 'export const greeting = "hello world";\n';
      const result = await handleSecureWrite(mw, { path: testFile, content });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results.success).toBe(true);
        expect(result.results.hash).toBeDefined();
        expect(result.results.hash.length).toBe(64);

        // Verify file was actually written
        const written = await fsp.readFile(path.join(testRoot, testFile), 'utf-8');
        expect(written).toBe(content);
      }
    });

    it('rejects write with secrets', async () => {
      const content = 'const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";\n';
      const result = await handleSecureWrite(mw, { path: testFile, content });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('SECRET_IN_WRITE');
      }

      // Verify file was NOT written
      await expect(fsp.access(path.join(testRoot, testFile))).rejects.toThrow();
    });

    it('blocks write to .env', async () => {
      const result = await handleSecureWrite(mw, { path: '.env', content: 'safe content' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
      }
    });

    it('blocks write to traversal path', async () => {
      const result = await handleSecureWrite(mw, { path: '../outside.txt', content: 'escape' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
      }
    });

    it('enforces size limit', async () => {
      const bigContent = 'x'.repeat(200000);
      const result = await handleSecureWrite(mw, { path: testFile, content: bigContent });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('SIZE_EXCEEDED');
      }
    });
  });

  describe('secure_patch full pipeline', () => {
    it('patches existing file content', async () => {
      const original = 'const x = 1;\nconst y = 2;\n';
      await fsp.writeFile(path.join(testRoot, testFile), original, 'utf-8');

      const result = await handleSecurePatch(mw, {
        path: testFile,
        old_content: 'const x = 1;',
        new_content: 'const x = 42;',
      });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results.success).toBe(true);
        const patched = await fsp.readFile(path.join(testRoot, testFile), 'utf-8');
        expect(patched).toContain('const x = 42;');
        expect(patched).toContain('const y = 2;');
      }
    });

    it('rejects patch with secrets in new_content', async () => {
      const original = 'const config = {};\n';
      await fsp.writeFile(path.join(testRoot, testFile), original, 'utf-8');

      const result = await handleSecurePatch(mw, {
        path: testFile,
        old_content: 'const config = {};',
        new_content: 'const config = { key: "AKIAIOSFODNN7EXAMPLE" };',
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('SECRET_IN_WRITE');
      }
    });

    it('blocks patch to denied path', async () => {
      const result = await handleSecurePatch(mw, {
        path: '.env',
        old_content: 'old',
        new_content: 'new',
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
      }
    });

    it('supports optimistic locking via expected_hash', async () => {
      const original = 'const version = 1;\n';
      await fsp.writeFile(path.join(testRoot, testFile), original, 'utf-8');

      // Patch with wrong hash
      const result = await handleSecurePatch(mw, {
        path: testFile,
        old_content: 'const version = 1;',
        new_content: 'const version = 2;',
        expected_hash: 'deadbeef'.repeat(8),
      });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('HASH_MISMATCH');
      }
    });
  });

  describe('write-then-read consistency', () => {
    it('writes clean content then reads it back with no redactions', async () => {
      const content = 'export function add(a: number, b: number) { return a + b; }\n';

      const writeResult = await handleSecureWrite(mw, { path: testFile, content });
      expect('results' in writeResult).toBe(true);

      const readResult = await handleSecureRead(mw, { path: testFile });
      expect('results' in readResult).toBe(true);
      if ('results' in readResult) {
        expect(readResult.results.content).toContain('export function add');
        expect(readResult.results.redacted_lines.length).toBe(0);
      }
    });
  });
});
