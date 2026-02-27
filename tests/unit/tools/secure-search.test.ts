import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureSearch } from '../../../src/tools/read/secure-search.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import { SearchResult } from '../../../src/types/response.js';
import path from 'node:path';

describe('secure_search', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('finds matches in source files (compact)', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBeGreaterThan(0);
      // Compact results are strings in file:line:content format
      const match = result.results.find(r => typeof r === 'string' && r.startsWith('src/clean.ts:'));
      expect(match).toBeDefined();
    }
  });

  it('compact results match file:line:content format', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function add' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results) {
        expect(typeof r).toBe('string');
        expect(r).toMatch(/^[^:]+:\d+:.+/);
      }
    }
  });

  it('finds matches in source files (structured)', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBeGreaterThan(0);
      const files = (result.results as SearchResult[]).map(r => r.file);
      expect(files).toContain('src/clean.ts');
    }
  });

  it('returns context lines around matches', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function add', context_lines: 1, compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const match = (result.results as SearchResult[]).find(r => r.file === 'src/clean.ts');
      expect(match).toBeDefined();
      // context_after should have at least 1 line
      expect(match!.context_after!.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('redacts secrets in search results', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'apiKey', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const configMatch = (result.results as SearchResult[]).find(r => r.file === 'src/config.ts');
      expect(configMatch).toBeDefined();
      expect(configMatch!.content).toContain('[REDACTED:');
      expect(configMatch!.content).not.toContain('ghp_');
      expect(configMatch!.redacted).toBe(true);
    }
  });

  it('never returns denylist files in results', async () => {
    // .env contains "DB_HOST" and other content, but should never appear
    const result = await handleSecureSearch(mw, { pattern: '.*', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const files = (result.results as SearchResult[]).map(r => r.file);
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
    const result = await handleSecureSearch(mw, { pattern: 'function', file_pattern: '*.ts', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const r of result.results as SearchResult[]) {
        expect(r.file).toMatch(/\.ts$/);
      }
    }
  });

  it('omits context keys when context_lines is 0 (default)', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'function add', compact: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const match = (result.results as SearchResult[]).find(r => r.file === 'src/clean.ts');
      expect(match).toBeDefined();
      expect(match!.context_before).toBeUndefined();
      expect(match!.context_after).toBeUndefined();
    }
  });

  it('redacts secrets in compact search results', async () => {
    const result = await handleSecureSearch(mw, { pattern: 'apiKey' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const configMatch = result.results.find(
        r => typeof r === 'string' && (r as string).startsWith('src/config.ts:'),
      );
      expect(configMatch).toBeDefined();
      expect(configMatch as string).toContain('[REDACTED:');
      expect(configMatch as string).not.toContain('ghp_');
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

  it('compact mode respects offset for pagination', async () => {
    const all = await handleSecureSearch(mw, { pattern: 'export' });
    const offset1 = await handleSecureSearch(mw, { pattern: 'export', offset: 1 });

    expect('results' in all).toBe(true);
    expect('results' in offset1).toBe(true);
    if ('results' in all && 'results' in offset1) {
      // Offset 1 should return one fewer result
      expect(offset1.meta.returned).toBe(all.meta.returned - 1);
      expect(offset1.meta.offset).toBe(1);
      expect(offset1.meta.total).toBe(all.meta.total);
    }
  });

  it('compact mode has_more is set when results are limited', async () => {
    const config = getDefaultConfig(testRoot);
    config.limits.maxResultCount = 1;
    const tightMw = new SecurityMiddleware(config);

    const result = await handleSecureSearch(tightMw, { pattern: 'export' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.length).toBe(1);
      expect(result.meta.has_more).toBe(true);
    }
  });
});
