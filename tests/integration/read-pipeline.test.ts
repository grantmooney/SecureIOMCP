import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityMiddleware } from '../../src/security/middleware.js';
import { getDefaultConfig } from '../../src/config/defaults.js';
import { handleSecureRead } from '../../src/tools/read/secure-read.js';
import { handleSecureSearch } from '../../src/tools/read/secure-search.js';
import { handleSecureGlob } from '../../src/tools/read/secure-glob.js';
import { SearchResult, GlobResult } from '../../src/types/response.js';
import path from 'node:path';

describe('Read Pipeline Integration', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  describe('secure_read full pipeline', () => {
    it('reads clean file without redactions', async () => {
      const result = await handleSecureRead(mw, { path: 'src/clean.ts' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results.content).not.toContain('[REDACTED:');
        expect(result.results.redacted_lines.length).toBe(0);
        expect(result.meta.redactions).toBe(0);
      }
    });

    it('reads file with secrets and redacts them', async () => {
      const result = await handleSecureRead(mw, { path: 'src/config.ts' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results.content).toContain('[REDACTED:');
        expect(result.results.content).not.toContain('sk_live_');
        expect(result.results.content).not.toContain('s3cretP@ss');
        expect(result.results.redacted_lines.length).toBeGreaterThan(0);
        expect(result.meta.redactions).toBeGreaterThan(0);
      }
    });

    it('blocks access to .env file', async () => {
      const result = await handleSecureRead(mw, { path: '.env' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
      }
    });

    it('blocks path traversal', async () => {
      const result = await handleSecureRead(mw, { path: '../../package.json' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('PATH_DENIED');
      }
    });

    it('returns correct response meta', async () => {
      const result = await handleSecureRead(mw, { path: 'src/clean.ts' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.meta.total).toBeGreaterThan(0);
        expect(result.meta.returned).toBeGreaterThan(0);
        expect(typeof result.meta.redactions).toBe('number');
      }
    });

    it('respects line range parameters', async () => {
      const result = await handleSecureRead(mw, { path: 'src/clean.ts', start_line: 1, end_line: 3 });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results.start_line).toBe(1);
        expect(result.results.end_line).toBeLessThanOrEqual(3);
      }
    });

    it('returns FILE_NOT_FOUND for missing files', async () => {
      const result = await handleSecureRead(mw, { path: 'src/does-not-exist.ts' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('FILE_NOT_FOUND');
      }
    });
  });

  describe('secure_search full pipeline', () => {
    it('finds matches and redacts secrets in results', async () => {
      const result = await handleSecureSearch(mw, { pattern: 'API_KEY', compact: false });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        const matches = result.results as SearchResult[];
        expect(Array.isArray(matches)).toBe(true);
        // Should find matches in config.ts but secret values should be redacted
        for (const match of matches) {
          expect(match.content).not.toContain('sk_live_');
        }
      }
    });

    it('does not return results from denied files', async () => {
      const result = await handleSecureSearch(mw, { pattern: 'DATABASE_URL', compact: false });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        for (const match of result.results as SearchResult[]) {
          expect(match.file).not.toBe('.env');
        }
      }
    });

    it('handles invalid regex gracefully', async () => {
      const result = await handleSecureSearch(mw, { pattern: '[invalid(' });
      expect('error' in result).toBe(true);
      if ('error' in result) {
        expect(result.error.code).toBe('INVALID_REGEX');
      }
    });

    it('supports file_pattern filtering', async () => {
      const result = await handleSecureSearch(mw, { pattern: 'export', file_pattern: '*.ts', compact: false });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        for (const match of result.results as SearchResult[]) {
          expect(match.file).toMatch(/\.ts$/);
        }
      }
    });
  });

  describe('secure_glob full pipeline', () => {
    it('finds TypeScript files respecting access control', async () => {
      const result = await handleSecureGlob(mw, { pattern: '*.ts' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        const files = result.results as string[];
        expect(files.length).toBeGreaterThan(0);
        for (const file of files) {
          expect(file).toMatch(/\.ts$/);
          expect(file).not.toContain('.env');
        }
      }
    });

    it('finds all files with wildcard', async () => {
      const result = await handleSecureGlob(mw, { pattern: '*' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results).toContain('package.json');
      }
    });

    it('excludes denied files from results', async () => {
      const result = await handleSecureGlob(mw, { pattern: '**/*' });
      expect('results' in result).toBe(true);
      if ('results' in result) {
        expect(result.results).not.toContain('.env');
      }
    });
  });
});
