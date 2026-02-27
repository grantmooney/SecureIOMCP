import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureRead } from '../../../src/tools/read/secure-read.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_read', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('reads a clean file without redaction', async () => {
    const result = await handleSecureRead(mw, { path: 'src/clean.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.content).toContain('function add');
      expect(result.results.redacted_lines).toEqual([]);
    }
  });

  it('redacts secrets in config file', async () => {
    const result = await handleSecureRead(mw, { path: 'src/config.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.content).toContain('[REDACTED:');
      expect(result.results.content).not.toContain('ghp_');
      expect(result.results.redacted_lines.length).toBeGreaterThan(0);
    }
  });

  it('rejects reading .env', async () => {
    const result = await handleSecureRead(mw, { path: '.env' });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('PATH_DENIED');
    }
  });

  it('supports line range reading', async () => {
    const result = await handleSecureRead(mw, { path: 'src/clean.ts', start_line: 2, end_line: 4 });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.start_line).toBe(2);
      expect(result.results.end_line).toBeLessThanOrEqual(4);
    }
  });

  it('returns file not found for missing files', async () => {
    const result = await handleSecureRead(mw, { path: 'nonexistent.ts' });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('FILE_NOT_FOUND');
    }
  });

  it('includes encoding detection', async () => {
    const result = await handleSecureRead(mw, { path: 'src/index.ts' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.encoding_detected).toBe('utf-8');
    }
  });

  it('includes metadata in response', async () => {
    const result = await handleSecureRead(mw, { path: 'src/clean.ts' });
    expect('meta' in result).toBe(true);
    if ('meta' in result) {
      expect(result.meta.total).toBeGreaterThan(0);
      expect(result.meta.returned).toBeGreaterThan(0);
      expect(typeof result.meta.redactions).toBe('number');
    }
  });
});
