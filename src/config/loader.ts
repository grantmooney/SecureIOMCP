/**
 * @module config/loader
 * @description Configuration loading and merging system for SecureIOMCP.
 *
 * Implements the four-layer configuration precedence model:
 * 1. **CLI flags** (highest priority)
 * 2. **System policy** (`~/.secureio/policy.json`) — organizational enforcement
 * 3. **Project config** (`.secureiorc`) — project-specific settings
 * 4. **Built-in defaults** (strict preset)
 *
 * Key merging rules:
 * - Denylist is extend-only — layers can only add patterns, never remove built-in ones
 * - Presets can only be made stricter (`standard` -> `strict`), never relaxed
 * - Resource limits can only be made stricter (lower values), never relaxed
 * - System policy `audit.required` prevents disabling audit logging
 * - Hard ceilings are enforced as a final step after all merging
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ProjectConfig, SystemPolicy, ResolvedConfig, Preset } from '../types/config.js';
import { getDefaultConfig, STRICT_LIMITS, STANDARD_LIMITS, LIMITS_CEILINGS } from './defaults.js';

/**
 * CLI flag overrides passed from the command-line argument parser.
 */
export interface CLIFlags {
  /** Override the security preset. */
  preset?: Preset;
  /** Override the project root directory. */
  root?: string;
  /** Override the audit log output mode. */
  auditOutput?: 'file' | 'stderr' | 'none';
}

/**
 * Load and merge all configuration layers into a single resolved config.
 *
 * Configuration sources are loaded in order and merged with precedence rules:
 * 1. Start with built-in defaults (strict preset)
 * 2. Apply system policy from `~/.secureio/policy.json` (if present)
 * 3. Apply project config from `.secureiorc` (if present, bounded by system policy)
 * 4. Apply CLI flags (bounded by system policy)
 * 5. Enforce hard ceilings
 *
 * @param projectRoot - Absolute path to the project root directory.
 * @param cliFlags - Optional CLI flag overrides.
 * @returns The fully resolved configuration ready for use by {@link SecurityMiddleware}.
 *
 * @example
 * ```typescript
 * const config = loadConfig('/path/to/project', {
 *   preset: 'strict',
 *   auditOutput: 'file',
 * });
 * const mw = new SecurityMiddleware(config);
 * ```
 */
export function loadConfig(projectRoot: string, cliFlags: CLIFlags = {}): ResolvedConfig {
  const config = getDefaultConfig(projectRoot);

  const systemPolicy = loadSystemPolicy();
  const projectConfig = loadProjectConfig(projectRoot);

  if (systemPolicy) {
    applySystemPolicy(config, systemPolicy);
  }

  if (projectConfig) {
    applyProjectConfig(config, projectConfig, systemPolicy);
  }

  applyCLIFlags(config, cliFlags, systemPolicy);
  enforceCeilings(config);

  return config;
}

/**
 * Load system-level security policy from `~/.secureio/policy.json`.
 *
 * @returns The parsed system policy, or `null` if the file doesn't exist or can't be parsed.
 */
function loadSystemPolicy(): SystemPolicy | null {
  const policyPath = path.join(os.homedir(), '.secureio', 'policy.json');
  try {
    const content = fs.readFileSync(policyPath, 'utf-8');
    return JSON.parse(content) as SystemPolicy;
  } catch {
    return null;
  }
}

/**
 * Load project-level configuration from `.secureiorc` in the project root.
 *
 * @param projectRoot - Absolute path to the project root directory.
 * @returns The parsed project config, or `null` if the file doesn't exist or can't be parsed.
 */
function loadProjectConfig(projectRoot: string): Partial<ProjectConfig> | null {
  const configPath = path.join(projectRoot, '.secureiorc');
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(content) as Partial<ProjectConfig>;
  } catch {
    return null;
  }
}

/**
 * Apply system policy overrides to the configuration.
 *
 * System policy can:
 * - Force the strict preset
 * - Extend the denylist
 * - Add custom redaction patterns (assigned high confidence)
 * - Require audit logging
 *
 * @param config - The configuration to modify in place.
 * @param policy - The system policy to apply.
 */
function applySystemPolicy(config: ResolvedConfig, policy: SystemPolicy): void {
  if (policy.minimumPreset === 'strict') {
    config.preset = 'strict';
    config.entropyDetection = true;
    config.limits = { ...STRICT_LIMITS };
  }

  if (policy.denylist?.extend) {
    config.denylist.push(...policy.denylist.extend);
  }

  if (policy.redaction?.customPatterns) {
    config.redactionPatterns.push(
      ...policy.redaction.customPatterns.map(p => ({
        ...p,
        confidence: 'high' as const,
      }))
    );
  }

  if (policy.audit?.required) {
    config.audit.output = policy.audit.minimumOutput ?? 'file';
  }
}

/**
 * Apply project configuration, bounded by system policy constraints.
 *
 * Projects can:
 * - Set a preset (if at or above system policy minimum)
 * - Extend the denylist
 * - Add custom redaction patterns (assigned medium confidence)
 * - Configure audit output (unless system policy requires it)
 * - Lower resource limits (cannot raise them above preset defaults)
 *
 * @param config - The configuration to modify in place.
 * @param project - The project configuration to apply.
 * @param policy - The active system policy (for bounds checking), or `null`.
 */
function applyProjectConfig(
  config: ResolvedConfig,
  project: Partial<ProjectConfig>,
  policy: SystemPolicy | null,
): void {
  if (project.preset) {
    const minimumPreset = policy?.minimumPreset ?? 'standard';
    if (canApplyPreset(project.preset, minimumPreset)) {
      config.preset = project.preset;
      config.entropyDetection = project.preset === 'strict';
      config.limits = project.preset === 'strict'
        ? { ...STRICT_LIMITS }
        : { ...STANDARD_LIMITS };
    }
  }

  if (project.denylist?.extend) {
    config.denylist.push(...project.denylist.extend);
  }

  if (project.redaction?.customPatterns) {
    config.redactionPatterns.push(
      ...project.redaction.customPatterns.map(p => ({
        ...p,
        confidence: 'medium' as const,
      }))
    );
  }

  if (project.audit) {
    if (policy?.audit?.required && project.audit.output === 'none') {
      // Cannot disable audit when policy requires it
    } else {
      if (project.audit.output) config.audit.output = project.audit.output;
      if (project.audit.path) config.audit.path = project.audit.path;
    }
  }

  if (project.limits) {
    for (const [key, value] of Object.entries(project.limits)) {
      const k = key as keyof typeof config.limits;
      if (typeof value === 'number' && value < config.limits[k]) {
        config.limits[k] = value;
      }
    }
  }
}

/**
 * Apply CLI flag overrides, bounded by system policy constraints.
 *
 * @param config - The configuration to modify in place.
 * @param flags - CLI flags to apply.
 * @param policy - The active system policy (for bounds checking), or `null`.
 */
function applyCLIFlags(
  config: ResolvedConfig,
  flags: CLIFlags,
  policy: SystemPolicy | null,
): void {
  if (flags.preset) {
    const minimumPreset = policy?.minimumPreset ?? 'standard';
    if (canApplyPreset(flags.preset, minimumPreset)) {
      config.preset = flags.preset;
      config.entropyDetection = flags.preset === 'strict';
      config.limits = flags.preset === 'strict'
        ? { ...STRICT_LIMITS }
        : { ...STANDARD_LIMITS };
    }
  }

  if (flags.auditOutput) {
    if (policy?.audit?.required && flags.auditOutput === 'none') {
      // Cannot disable audit when policy requires it
    } else {
      config.audit.output = flags.auditOutput;
    }
  }
}

/**
 * Check whether a requested preset meets the minimum requirement.
 *
 * @param requested - The preset being requested.
 * @param minimum - The minimum allowed preset.
 * @returns `true` if the requested preset is at or above the minimum level.
 */
function canApplyPreset(requested: Preset, minimum: Preset): boolean {
  const levels: Record<Preset, number> = { standard: 0, strict: 1 };
  return levels[requested] >= levels[minimum];
}

/**
 * Enforce hard ceilings on resource limits.
 *
 * This is the final step in configuration resolution. It ensures that
 * no configuration layer (including system policy) can set limits above
 * the absolute maximums defined in {@link LIMITS_CEILINGS}.
 *
 * @param config - The configuration to cap in place.
 */
function enforceCeilings(config: ResolvedConfig): void {
  for (const [key, ceiling] of Object.entries(LIMITS_CEILINGS)) {
    const k = key as keyof typeof config.limits;
    if (ceiling !== undefined && config.limits[k] > ceiling) {
      config.limits[k] = ceiling;
    }
  }
}
