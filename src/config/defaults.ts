import { LimitsConfig, ResolvedConfig } from '../types/config.js';

/**
 * Default limits for the `strict` preset.
 * Tighter constraints prioritize security over convenience.
 */
export const STRICT_LIMITS: LimitsConfig = {
  maxResultCount: 50,
  maxLineLength: 2000,
  maxResponseBytes: 51200,
  maxFileReadLines: 500,
  maxWriteBytes: 131072,
  maxTreeDepth: 4,
  maxAuditLogSizeMB: 50,
};

/**
 * Default limits for the `standard` preset.
 * More permissive constraints for lower-security contexts.
 */
export const STANDARD_LIMITS: LimitsConfig = {
  maxResultCount: 100,
  maxLineLength: 2000,
  maxResponseBytes: 102400,
  maxFileReadLines: 1000,
  maxWriteBytes: 262144,
  maxTreeDepth: 5,
  maxAuditLogSizeMB: 50,
};

/**
 * Hard ceilings that cannot be exceeded regardless of configuration.
 * `maxResponseBytes` <= 512 KB, `maxWriteBytes` <= 1 MB.
 */
export const LIMITS_CEILINGS: Partial<LimitsConfig> = {
  maxResponseBytes: 524288,
  maxWriteBytes: 1048576,
};

/**
 * Creates the default resolved configuration with strict preset.
 * Used as the starting point before applying system policy, project config, and CLI flags.
 *
 * @param projectRoot - Absolute path to the project root directory
 * @returns Default configuration with strict preset and entropy detection enabled
 */
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
