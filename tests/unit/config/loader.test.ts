import { describe, it, expect } from 'vitest';
import { loadConfig } from '../../../src/config/loader.js';
import path from 'node:path';

describe('Config Loader', () => {
  const testRoot = path.resolve('tests/fixtures/test-repo');

  describe('defaults', () => {
    it('uses strict preset by default', () => {
      const config = loadConfig(testRoot);
      expect(config.preset).toBe('strict');
      expect(config.entropyDetection).toBe(true);
    });

    it('sets file audit output by default', () => {
      const config = loadConfig(testRoot);
      expect(config.audit.output).toBe('file');
    });

    it('has correct strict limits', () => {
      const config = loadConfig(testRoot);
      expect(config.limits.maxResultCount).toBe(50);
      expect(config.limits.maxWriteBytes).toBe(131072);
    });
  });

  describe('CLI flags', () => {
    it('overrides preset via CLI flag', () => {
      const config = loadConfig(testRoot, { preset: 'standard' });
      expect(config.preset).toBe('standard');
      expect(config.entropyDetection).toBe(false);
    });

    it('overrides audit output via CLI flag', () => {
      const config = loadConfig(testRoot, { auditOutput: 'stdout' });
      expect(config.audit.output).toBe('stdout');
    });
  });

  describe('ceilings', () => {
    it('maxResponseBytes cannot exceed 512KB', () => {
      const config = loadConfig(testRoot);
      expect(config.limits.maxResponseBytes).toBeLessThanOrEqual(524288);
    });

    it('maxWriteBytes cannot exceed 1MB', () => {
      const config = loadConfig(testRoot);
      expect(config.limits.maxWriteBytes).toBeLessThanOrEqual(1048576);
    });
  });

  describe('project root', () => {
    it('stores the project root in config', () => {
      const config = loadConfig(testRoot);
      expect(config.projectRoot).toBe(testRoot);
    });
  });
});
