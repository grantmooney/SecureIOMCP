#!/usr/bin/env node
/**
 * @module index
 *
 * CLI entry point for the SecureIOMCP server. Parses command-line arguments,
 * loads the merged configuration (system policy + project config + CLI flags),
 * initialises the security middleware, and either runs the self-test suite
 * or starts the MCP server on stdio transport.
 *
 * Usage:
 * ```
 * secureio-mcp [--preset strict|standard] [--root <path>]
 *              [--audit-output file|stderr|none] [--self-test] [-h|--help]
 * ```
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config/loader.js';
import { SecurityMiddleware } from './security/index.js';
import { createServer } from './server.js';
import { handleSecureSelfTest } from './tools/meta/secure-self-test.js';
import type { Preset } from './types/config.js';

/**
 * Structured representation of parsed CLI arguments.
 *
 * @property preset      - Security preset override (`strict` or `standard`).
 * @property root        - Project root directory override.
 * @property auditOutput - Audit log destination override.
 * @property selfTest    - Whether to run the self-test suite and exit.
 * @property help        - Whether to print usage information and exit.
 */
interface ParsedArgs {
  preset?: Preset;
  root?: string;
  auditOutput?: 'file' | 'stderr' | 'none';
  selfTest: boolean;
  help: boolean;
}

/**
 * Parse raw CLI argument strings into a structured {@link ParsedArgs} object.
 *
 * Supports the following flags:
 * - `--help` / `-h` -- print usage and exit
 * - `--self-test` -- run security validation suite and exit
 * - `--preset <strict|standard>` -- override the security preset
 * - `--root <path>` -- override the project root directory
 * - `--audit-output <file|stderr|none>` -- override the audit log destination
 *
 * @param argv - The argument array (typically `process.argv.slice(2)`).
 * @returns A populated {@link ParsedArgs} object.
 */
function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = { selfTest: false, help: false };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--self-test') {
      args.selfTest = true;
    } else if (arg === '--preset' && i + 1 < argv.length) {
      const val = argv[++i];
      if (val === 'strict' || val === 'standard') {
        args.preset = val;
      }
    } else if (arg === '--root' && i + 1 < argv.length) {
      args.root = argv[++i];
    } else if (arg === '--audit-output' && i + 1 < argv.length) {
      const val = argv[++i];
      if (val === 'file' || val === 'stderr' || val === 'none') {
        args.auditOutput = val;
      }
    }
  }

  return args;
}

/**
 * Print the CLI usage/help text to stderr.
 *
 * Outputs a summary of all supported command-line flags and their defaults.
 */
function printUsage(): void {
  const usage = `SecureIOMCP — Secure, token-efficient MCP server for AI agents

Usage: secureio-mcp [options]

Options:
  --preset <strict|standard>    Security preset (default: strict)
  --root <path>                 Project root directory (default: cwd)
  --audit-output <file|stderr|none>  Audit log output (default: file)
  --self-test                   Run security validation and exit
  -h, --help                    Show this help message
`;
  process.stderr.write(usage);
}

/**
 * Main application entry point.
 *
 * Parses CLI arguments, loads configuration, and either:
 * - prints usage (if `--help`),
 * - runs the self-test suite and exits with code 1 on failure (if `--self-test`), or
 * - starts the MCP server on stdio transport for normal operation.
 *
 * @param argv - Optional argument array; defaults to `process.argv.slice(2)`.
 */
export async function main(argv: string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);

  if (args.help) {
    printUsage();
    return;
  }

  const projectRoot = args.root ?? process.cwd();
  const config = loadConfig(projectRoot, {
    preset: args.preset,
    auditOutput: args.auditOutput,
  });
  const mw = new SecurityMiddleware(config);

  if (args.selfTest) {
    const result = await handleSecureSelfTest(mw, {});
    if ('results' in result) {
      process.stderr.write(JSON.stringify(result.results, null, 2) + '\n');
      if (!result.results.passed) {
        process.exitCode = 1;
      }
    }
    return;
  }

  const server = createServer(mw);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Run if this is the entry point
const isMainModule = process.argv[1] && (
  process.argv[1].endsWith('/index.js') ||
  process.argv[1].endsWith('\\index.js') ||
  process.argv[1].endsWith('/index.ts') ||
  process.argv[1].endsWith('\\index.ts')
);

if (isMainModule) {
  main().catch((err) => {
    process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
