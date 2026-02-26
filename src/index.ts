#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config/loader.js';
import { SecurityMiddleware } from './security/index.js';
import { createServer } from './server.js';
import { handleSecureSelfTest } from './tools/meta/secure-self-test.js';
import type { Preset } from './types/config.js';

interface ParsedArgs {
  preset?: Preset;
  root?: string;
  auditOutput?: 'file' | 'stderr' | 'none';
  selfTest: boolean;
  help: boolean;
}

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
