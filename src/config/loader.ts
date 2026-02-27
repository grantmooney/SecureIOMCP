import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ProjectConfig, SystemPolicy, ResolvedConfig, Preset } from '../types/config.js';
import { getDefaultConfig, STRICT_LIMITS, STANDARD_LIMITS, LIMITS_CEILINGS } from './defaults.js';

/** CLI flags parsed from command-line arguments. */
export interface CLIFlags {
  /** Security preset override */
  preset?: Preset;
  /** Project root directory override */
  root?: string;
  /** Audit log output destination override */
  auditOutput?: 'file' | 'stderr' | 'none';
}

/**
 * Loads and merges configuration from all sources in priority order:
 * defaults -> system policy -> project config -> CLI flags.
 *
 * System policy (`~/.secureio/policy.json`) can enforce minimum preset levels
 * and mandatory audit logging that project config and CLI flags cannot weaken.
 * Projects can only make settings stricter than the system policy.
 * Hard ceilings on limits are enforced at the end.
 *
 * @param projectRoot - Absolute path to the project root directory
 * @param cliFlags - CLI flag overrides
 * @returns Fully resolved configuration ready for use
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

/** Loads organization-level system policy from `~/.secureio/policy.json`. */
function loadSystemPolicy(): SystemPolicy | null {
  const policyPath = path.join(os.homedir(), '.secureio', 'policy.json');
  try {
    const content = fs.readFileSync(policyPath, 'utf-8');
    return JSON.parse(content) as SystemPolicy;
  } catch {
    return null;
  }
}

/** Loads project-level configuration from `.secureiorc` in the project root. */
function loadProjectConfig(projectRoot: string): Partial<ProjectConfig> | null {
  const configPath = path.join(projectRoot, '.secureiorc');
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(content) as Partial<ProjectConfig>;
  } catch {
    return null;
  }
}

/** Applies system policy overrides. These take highest priority and cannot be weakened. */
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

/** Applies project config overrides. Cannot weaken system policy settings. */
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

/** Applies CLI flag overrides. Cannot violate system policy. */
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

/** Checks whether a requested preset meets the minimum level required by system policy. */
function canApplyPreset(requested: Preset, minimum: Preset): boolean {
  const levels: Record<Preset, number> = { standard: 0, strict: 1 };
  return levels[requested] >= levels[minimum];
}

/** Enforces hard ceilings on limits that cannot be exceeded regardless of configuration. */
function enforceCeilings(config: ResolvedConfig): void {
  for (const [key, ceiling] of Object.entries(LIMITS_CEILINGS)) {
    const k = key as keyof typeof config.limits;
    if (ceiling !== undefined && config.limits[k] > ceiling) {
      config.limits[k] = ceiling;
    }
  }
}
