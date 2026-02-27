import { SecurityMiddleware } from '../../security/middleware.js';
import { OverviewResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fsp from 'node:fs/promises';
import path from 'node:path';

/** Parameters for the `secure_overview` MCP tool. */
export interface SecureOverviewParams {
  /** Project root to analyze (default: configured project root) */
  path?: string;
  /** Include full dependency names and versions (default: false) */
  verbose?: boolean;
}

/**
 * Handles the `secure_overview` MCP tool: returns a single-call project summary.
 * Detects framework, language, package manager, entry points, scripts, dependency counts,
 * directory structure, and configuration files. Replaces multiple glob/read calls with
 * one token-efficient response.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters
 * @returns Project overview with detected metadata, or a safe error response
 */
export async function handleSecureOverview(
  mw: SecurityMiddleware,
  params: SecureOverviewParams,
): Promise<SecureResponse<OverviewResult> | { error: SecureIOError }> {
  const startTime = Date.now();
  const overviewRoot = path.resolve(mw.config.projectRoot, params.path ?? '.');

  // Try to read package.json
  let pkg: Record<string, unknown> | null = null;
  try {
    const content = await fsp.readFile(path.join(overviewRoot, 'package.json'), 'utf-8');
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    // No package.json
  }

  // Detect language
  let language: string | null = null;
  const configFiles: string[] = [];

  for (const [file, lang] of [
    ['tsconfig.json', 'typescript'],
    ['jsconfig.json', 'javascript'],
    ['pyproject.toml', 'python'],
    ['Cargo.toml', 'rust'],
    ['go.mod', 'go'],
  ] as const) {
    try {
      await fsp.access(path.join(overviewRoot, file));
      if (!language) language = lang;
      configFiles.push(file);
    } catch {
      // Not present
    }
  }

  // Check for other config files
  for (const file of ['.eslintrc.json', '.prettierrc', 'vitest.config.ts', 'jest.config.ts', 'webpack.config.js', '.gitignore', 'Dockerfile', 'docker-compose.yml']) {
    try {
      await fsp.access(path.join(overviewRoot, file));
      configFiles.push(file);
    } catch {
      // Not present
    }
  }

  if (pkg) {
    configFiles.unshift('package.json');
  }

  // Detect framework
  let framework: string | null = null;
  if (pkg) {
    const allDeps = {
      ...(pkg.dependencies as Record<string, string> | undefined ?? {}),
      ...(pkg.devDependencies as Record<string, string> | undefined ?? {}),
    };

    if ('next' in allDeps) framework = 'next';
    else if ('nuxt' in allDeps) framework = 'nuxt';
    else if ('react' in allDeps) framework = 'react';
    else if ('vue' in allDeps) framework = 'vue';
    else if ('angular' in allDeps || '@angular/core' in allDeps) framework = 'angular';
    else if ('express' in allDeps) framework = 'express';
    else if ('fastify' in allDeps) framework = 'fastify';
    else if ('koa' in allDeps) framework = 'koa';
    else if ('hono' in allDeps) framework = 'hono';
  }

  if (!language && pkg) {
    const allDeps = {
      ...(pkg.dependencies as Record<string, string> | undefined ?? {}),
      ...(pkg.devDependencies as Record<string, string> | undefined ?? {}),
    };
    language = 'typescript' in allDeps ? 'typescript' : 'javascript';
  }

  // Detect package manager
  let packageManager: string | null = null;
  for (const [lockfile, pm] of [
    ['bun.lockb', 'bun'],
    ['pnpm-lock.yaml', 'pnpm'],
    ['yarn.lock', 'yarn'],
    ['package-lock.json', 'npm'],
  ] as const) {
    try {
      await fsp.access(path.join(overviewRoot, lockfile));
      packageManager = pm;
      break;
    } catch {
      // Not present
    }
  }
  if (!packageManager && pkg) packageManager = 'npm';

  // Entry points
  const entryPoints: string[] = [];
  if (pkg?.main) entryPoints.push(pkg.main as string);
  if (pkg?.module) entryPoints.push(pkg.module as string);
  if (pkg?.bin) {
    if (typeof pkg.bin === 'string') entryPoints.push(pkg.bin);
    else if (typeof pkg.bin === 'object') entryPoints.push(...Object.values(pkg.bin as Record<string, string>));
  }

  // Scripts
  const scripts = (pkg?.scripts as Record<string, string>) ?? {};

  // Dependency counts
  const deps = pkg?.dependencies as Record<string, string> | undefined;
  const devDeps = pkg?.devDependencies as Record<string, string> | undefined;
  const dependencyCount = deps ? Object.keys(deps).length : 0;
  const devDependencyCount = devDeps ? Object.keys(devDeps).length : 0;

  // Simple directory structure summary
  const structure = await buildStructureSummary(overviewRoot, mw);

  const result: OverviewResult = {
    name: (pkg?.name as string) ?? path.basename(overviewRoot),
    framework,
    language,
    packageManager,
    entryPoints,
    scripts,
    dependencyCount,
    devDependencyCount,
    structure,
    configFiles,
  };

  await mw.auditLogger.log({
    tool: 'secure_overview',
    params: { path: params.path },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  const overviewBytes = Buffer.byteLength(JSON.stringify(result), 'utf-8');

  return {
    results: result,
    meta: {
      total: 1,
      returned: 1,
      offset: 0,
      has_more: false,
      truncated_lines: 0,
      redactions: 0,
      bytes: overviewBytes,
      raw_bytes: overviewBytes,
      tokens_saved: 0,
      session_tokens_saved: mw.sessionTokensSaved,
    },
  };
}

/**
 * Builds a compact directory structure summary, listing directories and file counts
 * up to 3 levels deep. Skips node_modules, .git, dist, build, and vendor.
 */
async function buildStructureSummary(root: string, mw: SecurityMiddleware): Promise<string> {
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);
  const lines: string[] = [];

  async function walk(dir: string, prefix: string, depth: number): Promise<void> {
    if (depth > 2) return;

    let entries: import('node:fs').Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    const dirs = entries.filter(e => e.isDirectory() && !skipDirs.has(e.name)).sort((a, b) => a.name.localeCompare(b.name));
    const files = entries.filter(e => e.isFile()).sort((a, b) => a.name.localeCompare(b.name));

    for (const d of dirs) {
      lines.push(`${prefix}${d.name}/`);
      await walk(path.join(dir, d.name), prefix + '  ', depth + 1);
    }

    const fileCount = files.length;
    if (fileCount > 0 && depth <= 2) {
      lines.push(`${prefix}(${fileCount} files)`);
    }
  }

  await walk(root, '', 0);
  return lines.join('\n');
}
