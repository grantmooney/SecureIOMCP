import { LimitsConfig, ResolvedConfig } from '../types/config.js';

export const STRICT_LIMITS: LimitsConfig = {
  maxResultCount: 50,
  maxLineLength: 2000,
  maxResponseBytes: 51200,
  maxFileReadLines: 500,
  maxWriteBytes: 131072,
  maxTreeDepth: 4,
  maxAuditLogSizeMB: 50,
};

export const STANDARD_LIMITS: LimitsConfig = {
  maxResultCount: 100,
  maxLineLength: 2000,
  maxResponseBytes: 102400,
  maxFileReadLines: 1000,
  maxWriteBytes: 262144,
  maxTreeDepth: 5,
  maxAuditLogSizeMB: 50,
};

export const LIMITS_CEILINGS: Partial<LimitsConfig> = {
  maxResponseBytes: 524288,
  maxWriteBytes: 1048576,
};

export function getDefaultConfig(projectRoot: string): ResolvedConfig {
  return {
    preset: 'strict',
    projectRoot,
    denylist: [],
    redactionPatterns: [],
    audit: {
      output: 'file',
      path: '.secureio/audit.log',
    },
    limits: { ...STRICT_LIMITS },
    entropyDetection: true,
  };
}
