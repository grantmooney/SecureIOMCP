/**
 * @module config/defaults
 * @description Default configuration values and preset limit definitions for SecureIOMCP.
 *
 * This module defines the baseline limits for each security preset and the
 * hard ceilings that no configuration can exceed.
 */

import { LimitsConfig, ResolvedConfig } from '../types/config.js';

/**
 * Resource limits for the `strict` security preset (default).
 *
 * These limits prioritize security and token efficiency over convenience:
 * - Lower result counts and response sizes reduce data exposure
 * - Fewer read lines encourage targeted file access
 * - Smaller write limits prevent bulk data injection
 *
 * | Limit | Value |
 * |-------|-------|
 * | maxResultCount | 50 |
 * | maxLineLength | 2,000 chars |
 * | maxResponseBytes | 50 KB |
 * | maxFileReadLines | 500 |
 * | maxWriteBytes | 128 KB |
 * | maxTreeDepth | 4 |
 * | maxAuditLogSizeMB | 50 MB |
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
 * Resource limits for the `standard` security preset.
 *
 * More permissive limits for development environments where
 * convenience is prioritized alongside security.
 *
 * | Limit | Value |
 * |-------|-------|
 * | maxResultCount | 100 |
 * | maxLineLength | 2,000 chars |
 * | maxResponseBytes | 100 KB |
 * | maxFileReadLines | 1,000 |
 * | maxWriteBytes | 256 KB |
 * | maxTreeDepth | 5 |
 * | maxAuditLogSizeMB | 50 MB |
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
 * Hard upper bounds that no configuration layer can exceed.
 *
 * These ceilings are enforced after all configuration merging is complete.
 * Even system policy cannot set limits above these values.
 *
 * | Limit | Ceiling |
 * |-------|---------|
 * | maxResponseBytes | 512 KB |
 * | maxWriteBytes | 1 MB |
 */
export const LIMITS_CEILINGS: Partial<LimitsConfig> = {
  maxResponseBytes: 524288,
  maxWriteBytes: 1048576,
};

/**
 * Creates the default resolved configuration for a given project root.
 *
 * Returns a strict-preset configuration with entropy detection enabled,
 * file-based audit logging, and no custom patterns or denylist extensions.
 * This serves as the baseline that system policy and project config build upon.
 *
 * @param projectRoot - Absolute path to the project root directory.
 * @returns A fresh {@link ResolvedConfig} with strict defaults.
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
