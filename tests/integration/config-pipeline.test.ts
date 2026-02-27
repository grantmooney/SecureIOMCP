import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../../src/config/loader.js';
import { STRICT_LIMITS, STANDARD_LIMITS } from '../../src/config/defaults.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Config Pipeline Integration', () => {
  const testRoot = path.resolve('tests/fixtures/test-repo');
  const policyPath = path.join(os.homedir(), '.secureio', 'policy.json');
  const configPath = path.join(testRoot, '.secureiorc');
  let policyExisted: boolean;
  let configExisted: boolean;
  let policyBackup: string | null;
  let configBackup: string | null;

  beforeEach(() => {
    policyExisted = fs.existsSync(policyPath);
    configExisted = fs.existsSync(configPath);
    policyBackup = policyExisted ? fs.readFileSync(policyPath, 'utf-8') : null;
    configBackup = configExisted ? fs.readFileSync(configPath, 'utf-8') : null;
  });

  afterEach(() => {
    // Restore or remove test files
    if (policyExisted && policyBackup) {
      fs.writeFileSync(policyPath, policyBackup, 'utf-8');
    } else {
      try { fs.unlinkSync(policyPath); } catch { /* didn't exist */ }
    }
    if (configExisted && configBackup) {
      fs.writeFileSync(configPath, configBackup, 'utf-8');
    } else {
      try { fs.unlinkSync(configPath); } catch { /* didn't exist */ }
    }
  });

  it('loads default strict config with no overrides', () => {
    const config = loadConfig(testRoot);
    expect(config.preset).toBe('strict');
    expect(config.entropyDetection).toBe(true);
    expect(config.limits.maxResultCount).toBe(STRICT_LIMITS.maxResultCount);
    expect(config.limits.maxFileReadLines).toBe(STRICT_LIMITS.maxFileReadLines);
  });

  it('CLI --preset standard changes limits', () => {
    const config = loadConfig(testRoot, { preset: 'standard' });
    expect(config.preset).toBe('standard');
    expect(config.entropyDetection).toBe(false);
    expect(config.limits.maxResultCount).toBe(STANDARD_LIMITS.maxResultCount);
    expect(config.limits.maxFileReadLines).toBe(STANDARD_LIMITS.maxFileReadLines);
  });

  it('CLI --audit-output changes audit setting', () => {
    const config = loadConfig(testRoot, { auditOutput: 'stderr' });
    expect(config.audit.output).toBe('stderr');
  });

  it('project .secureiorc extends denylist', () => {
    fs.writeFileSync(configPath, JSON.stringify({
      denylist: { extend: ['*.log', 'temp/**'] },
    }), 'utf-8');

    const config = loadConfig(testRoot);
    expect(config.denylist).toContain('*.log');
    expect(config.denylist).toContain('temp/**');
  });

  it('project config cannot reduce preset below system policy minimum', () => {
    // Set system policy requiring strict
    const policyDir = path.dirname(policyPath);
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(policyPath, JSON.stringify({
      minimumPreset: 'strict',
    }), 'utf-8');

    // Project config tries to use standard
    fs.writeFileSync(configPath, JSON.stringify({
      preset: 'standard',
    }), 'utf-8');

    const config = loadConfig(testRoot);
    expect(config.preset).toBe('strict');
    expect(config.entropyDetection).toBe(true);
  });

  it('system policy enforces required audit', () => {
    const policyDir = path.dirname(policyPath);
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(policyPath, JSON.stringify({
      audit: { required: true, minimumOutput: 'file' },
    }), 'utf-8');

    // CLI trying to disable audit should be blocked
    const config = loadConfig(testRoot, { auditOutput: 'none' });
    expect(config.audit.output).not.toBe('none');
  });

  it('CLI preset flag is blocked by system policy minimum', () => {
    const policyDir = path.dirname(policyPath);
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(policyPath, JSON.stringify({
      minimumPreset: 'strict',
    }), 'utf-8');

    const config = loadConfig(testRoot, { preset: 'standard' });
    expect(config.preset).toBe('strict');
  });

  it('project config can tighten limits but not loosen them', () => {
    fs.writeFileSync(configPath, JSON.stringify({
      limits: {
        maxResultCount: 10, // tighter than strict's 50
      },
    }), 'utf-8');

    const config = loadConfig(testRoot);
    expect(config.limits.maxResultCount).toBe(10);
  });

  it('project config cannot raise limits above preset', () => {
    fs.writeFileSync(configPath, JSON.stringify({
      limits: {
        maxResultCount: 999, // higher than strict's 50
      },
    }), 'utf-8');

    const config = loadConfig(testRoot);
    // Should stay at strict default since 999 > 50
    expect(config.limits.maxResultCount).toBe(STRICT_LIMITS.maxResultCount);
  });
});
