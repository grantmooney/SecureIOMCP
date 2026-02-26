import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureSearch } from '../../../src/tools/read/secure-search.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_search', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('finds matches in source files', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBeGreaterThan(0);
      const files = result.results.map(r => r.file);
      expect(files).toContain('src/clean.ts');
    }
  });

  it('returns context lines around matches', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function add', context_lines: 1 });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const match = result.results.find(r => r.file === 'src/clean.ts');
      expect(match).toBeDefined();
      // context_after should have at least 1 line
      expect(match!.context_after.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('redacts secrets in search results', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'apiKey' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const configMatch = result.results.find(r => r.file === 'src/config.ts');
      expect(configMatch).toBeDefined();
      expect(configMatch!.content).toContain('[REDACTED:');
      expect(configMatch!.content).not.toContain('ghp_');
      expect(configMatch!.redacted).toBe(true);
    }
  });

  it('never returns denylist files in results', async () => {
    // .env contains "DB_HOST" and other content, but should never appear
    const result = await handleSecureSearch(mw, { pattern: '.*' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const files = result.results.map(r => r.file);
      expect(files).not.toContain('.env');
    }
  });

  it('returns error for invalid regex', async () => {
    const result = await handleSecureSearch(mw, { pattern: '(unclosed' });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('INVALID_REGEX');
    }
  });

  it('filters by file_pattern', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function', file_pattern: '*.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results) {
        expect(r.file).toMatch(/\.ts$/);
      }
    }
  });

  it('includes pagination metadata', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function' });
    expect('meta' in result).toBe(true);
    if ('meta' in result) {
      expect(typeof result.meta.total).toBe('number');
      expect(typeof result.meta.returned).toBe('number');
      expect(typeof result.meta.has_more).toBe('boolean');
    }
  });
});
