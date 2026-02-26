import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('SecurityMiddleware', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    const config = getDefaultConfig(testRoot);
    mw = new SecurityMiddleware(config);
  });

  describe('checkReadAccess', () => {
    it('allows access to normal source files', async () => {
      const result = await mw.checkReadAccess('src/index.ts');
      expect(result.ok).toBe(true);
    });

    it('denies access to .env', async () => {
      const result = await mw.checkReadAccess('.env');
      expect(result.ok).toBe(false);
    });

    it('denies path traversal', async () => {
      const result = await mw.checkReadAccess('../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('denies .secureiorc', async () => {
      const result = await mw.checkReadAccess('.secureiorc');
      expect(result.ok).toBe(false);
    });
  });

  describe('checkWriteAccess', () => {
    it('allows writing to normal source files', async () => {
      const result = await mw.checkWriteAccess('src/newfile.ts');
      expect(result.ok).toBe(true);
    });

    it('denies writing to .env', async () => {
      const result = await mw.checkWriteAccess('.env');
      expect(result.ok).toBe(false);
    });

    it('denies writing to audit log', async () => {
      const result = await mw.checkWriteAccess('.secureio/audit.log');
      expect(result.ok).toBe(false);
    });
  });

  describe('readFileSecure', () => {
    it('reads and redacts a file with secrets', async () => {
      const absPath = path.resolve(testRoot, 'src/config.ts');
      const result = await mw.readFileSecure(absPath);
      expect(result.content).toContain('[REDACTED:');
      expect(result.redactedLines.length).toBeGreaterThan(0);
    });

    it('reads a clean file without redaction', async () => {
      const absPath = path.resolve(testRoot, 'src/clean.ts');
      const result = await mw.readFileSecure(absPath);
      expect(result.content).toContain('function add');
      expect(result.redactedLines).toEqual([]);
    });
  });

  describe('scanWriteContent', () => {
    it('returns null for clean content', () => {
      const error = mw.scanWriteContent('const x = 42;\nconsole.log(x);');
      expect(error).toBeNull();
    });

    it('catches AWS keys in write content', () => {
      const error = mw.scanWriteContent('const key = "AKIAIOSFODNN7EXAMPLE";');
      expect(error).not.toBeNull();
      expect(error!.code).toBe('SECRET_IN_WRITE');
    });

    it('reports line number and category', () => {
      const error = mw.scanWriteContent('line 1\nconst key = "AKIAIOSFODNN7EXAMPLE";\nline 3');
      expect(error).not.toBeNull();
      expect(error!.message).toContain('line 2');
      expect(error!.message).toContain('AWS_ACCESS_KEY');
    });
  });
});
