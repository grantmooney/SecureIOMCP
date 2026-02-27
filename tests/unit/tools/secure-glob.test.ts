import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureGlob } from '../../../src/tools/read/secure-glob.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import { GlobResult } from '../../../src/types/response.js';
import path from 'node:path';

describe('secure_glob', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('finds TypeScript files (compact)', async () => {
    const result = await handleSecureGlob(mw, { pattern: '*.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBeGreaterThan(0);
      for (const r of result.results) {
        expect(typeof r).toBe('string');
        expect(r as string).toMatch(/\.ts$/);
      }
    }
  });

  it('compact results are path strings', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**/*.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results) {
        expect(typeof r).toBe('string');
      }
    }
  });

  it('returns path and size for each match (structured)', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**/*.ts', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results as GlobResult[]) {
        expect(typeof r.path).toBe('string');
        expect(typeof r.size).toBe('number');
        expect(r.size).toBeGreaterThan(0);
      }
    }
  });

  it('never returns denylist files', async () => {
    const result = await handleSecureGlob(mw, { pattern: '**', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const paths = (result.results as GlobResult[]).map(r => r.path);
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
      expect(result.results).toContain('package.json');
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
        expect(r as string).toMatch(/^src\//);
      }
    }
  });

  it('compact mode respects offset for pagination', async () => {
    // Use maxResultCount=2 so offset behavior is verifiable regardless of file count
    const config = getDefaultConfig(testRoot);
    config.limits.maxResultCount = 2;
    const limitedMw = new SecurityMiddleware(config);

    // Page 0: first 2 results (test fixture has at least 3 .ts files in src/)
    const page0 = await handleSecureGlob(limitedMw, { pattern: '*.ts', path: 'src', offset: 0 });
    expect('results' in page0).toBe(true);
    if ('results' in page0) {
      expect(page0.meta.returned).toBe(2);
      expect(page0.meta.offset).toBe(0);
      expect(page0.meta.has_more).toBe(true);
      expect(page0.meta.total).toBeGreaterThan(2);
    }

    // Page 1: skip 2, get remaining (avoid cross-call total comparison since
    // parallel write tests may add files to the fixture between calls)
    const page1 = await handleSecureGlob(limitedMw, { pattern: '*.ts', path: 'src', offset: 2 });
    expect('results' in page1).toBe(true);
    if ('results' in page1) {
      expect(page1.meta.offset).toBe(2);
      expect(page1.meta.returned).toBeGreaterThan(0);
      expect(page1.meta.total).toBeGreaterThanOrEqual(page1.meta.returned + 2);
    }
  });

  it('compact mode has_more is set when results are limited', async () => {
    const config = getDefaultConfig(testRoot);
    config.limits.maxResultCount = 1;
    const tightMw = new SecurityMiddleware(config);

    const result = await handleSecureGlob(tightMw, { pattern: '**' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBe(1);
      expect(result.meta.has_more).toBe(true);
    }
  });
});
