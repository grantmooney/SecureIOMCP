import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureGlob } from '../../../src/tools/read/secure-glob.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_glob', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('finds TypeScript files', async () => {
    const result = await handleSecureGlob(mw, { pattern: '*.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBeGreaterThan(0);
      for (const r of result.results) {
        expect(r.path).toMatch(/\.ts$/);
      }
    }
  });

  it('returns path and size for each match', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**/*.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results) {
        expect(typeof r.path).toBe('string');
        expect(typeof r.size).toBe('number');
        expect(r.size).toBeGreaterThan(0);
      }
    }
  });

  it('never returns denylist files', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const paths = result.results.map(r => r.path);
      expect(paths).not.toContain('.env');
      for (const p of paths) {
        expect(p).not.toMatch(/\.pem$/);
        expect(p).not.toMatch(/\.key$/);
      }
    }
  });

  it('finds package.json', async () => {
    const result = await handleSecureGlob(mw, { pattern: 'package.json' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const paths = result.results.map(r => r.path);
      expect(paths).toContain('package.json');
    }
  });

  it('includes pagination metadata', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**' });
    expect('meta' in result).toBe(true);
    if ('meta' in result) {
      expect(typeof result.meta.total).toBe('number');
      expect(typeof result.meta.returned).toBe('number');
    }
  });

  it('scopes search to subdirectory', async () => {
    const result = await handleSecureGlob(mw, { pattern: '*.ts', path: 'src' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results) {
        expect(r.path).toMatch(/^src\//);
      }
    }
  });
});
