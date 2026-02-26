import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureAudit } from '../../../src/tools/meta/secure-audit.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_audit', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('reports blocked files count', async () => {
    const result = await handleSecureAudit(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      // .env is blocked
      expect(result.results.files_blocked).toBeGreaterThan(0);
    }
  });

  it('reports detected secrets count', async () => {
    const result = await handleSecureAudit(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      // config.ts has secrets
      expect(result.results.secrets_detected).toBeGreaterThan(0);
      expect(result.results.files_with_secrets).toBeGreaterThan(0);
    }
  });

  it('reports preset in use', async () => {
    const result = await handleSecureAudit(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.preset).toBe('strict');
    }
  });

  it('does not include details in summary mode', async () => {
    const result = await handleSecureAudit(mw, { verbose: false });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.details).toBeUndefined();
    }
  });

  it('includes file details in verbose mode', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.details).toBeDefined();
      expect(result.results.details!.length).toBeGreaterThan(0);

      // Should have at least one blocked file
      const blocked = result.results.details!.filter(d => d.blocked);
      expect(blocked.length).toBeGreaterThan(0);

      // Should have config.ts with redactions
      const configFile = result.results.details!.find(d => d.path === 'src/config.ts');
      expect(configFile).toBeDefined();
      expect(configFile!.redactions.length).toBeGreaterThan(0);
    }
  });

  it('verbose details include line numbers and categories', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const configFile = result.results.details!.find(d => d.path === 'src/config.ts');
      expect(configFile).toBeDefined();
      for (const redaction of configFile!.redactions) {
        expect(typeof redaction.line).toBe('number');
        expect(typeof redaction.category).toBe('string');
        expect(typeof redaction.confidence).toBe('string');
      }
    }
  });
});
