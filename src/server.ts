import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { SecurityMiddleware } from './security/index.js';
import { handleSecureRead } from './tools/read/secure-read.js';
import { handleSecureSearch } from './tools/read/secure-search.js';
import { handleSecureGlob } from './tools/read/secure-glob.js';
import { handleSecureTree } from './tools/read/secure-tree.js';
import { handleSecureDiff } from './tools/read/secure-diff.js';
import { handleSecureWrite } from './tools/write/secure-write.js';
import { handleSecurePatch } from './tools/write/secure-patch.js';
import { handleSecureAudit } from './tools/meta/secure-audit.js';
import { handleSecureOverview } from './tools/meta/secure-overview.js';
import { handleSecureSelfTest } from './tools/meta/secure-self-test.js';

/**
 * Serializes a tool handler result into the MCP text content format.
 * Error responses (containing an `error` property) are serialized as the error object only.
 */
function toMcpResult(result: unknown): { content: { type: 'text'; text: string }[] } {
  const r = result as Record<string, unknown>;
  if ('error' in r) {
    return { content: [{ type: 'text', text: JSON.stringify(r.error) }] };
  }
  return { content: [{ type: 'text', text: JSON.stringify(result) }] };
}

/**
 * Creates and configures the MCP server with all 10 SecureIOMCP tools.
 * Registers read tools (secure_read, secure_search, secure_glob, secure_tree, secure_diff),
 * write tools (secure_write, secure_patch), and meta tools (secure_audit, secure_overview,
 * secure_self_test) with their Zod input schemas.
 *
 * @param mw - The security middleware instance passed to all tool handlers
 * @returns A configured McpServer ready to be connected to a transport
 */
export function createServer(mw: SecurityMiddleware): McpServer {
  const server = new McpServer({
    name: 'secureio-mcp',
    version: '0.2.1',
  });

  // ── Read tools ──────────────────────────────────────────────────────

  server.registerTool('secure_read', {
    title: 'Secure Read',
    description:
      'Read a file with automatic secret redaction and access control. ' +
      'ALWAYS use this instead of native file read tools (cat, head, tail, Read tool). ' +
      'Automatically redacts secrets (API keys, tokens, passwords) from output, ' +
      'enforces denylist rules, and prevents path traversal. ' +
      'Supports line-range pagination for large files.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      start_line: z.number().optional().describe('Starting line number (1-indexed)'),
      end_line: z.number().optional().describe('Ending line number'),
    },
  }, async (args) => toMcpResult(await handleSecureRead(mw, args)));

  server.registerTool('secure_search', {
    title: 'Secure Search',
    description:
      'Search across files with regex pattern matching and automatic secret redaction. ' +
      'ALWAYS use this instead of native search tools (grep, rg, ripgrep, Grep tool, git grep). ' +
      'Matches are returned with context lines and secrets automatically redacted. ' +
      'Respects denylist — blocked files are excluded from results. ' +
      'Supports pagination via offset/max_results for large result sets.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      pattern: z.string().describe('Regex pattern to search for'),
      path: z.string().optional().describe('Scope search to this subdirectory'),
      file_pattern: z.string().optional().describe('File glob filter (e.g. *.ts)'),
      context_lines: z.number().optional().describe('Number of context lines (default 2)'),
      max_results: z.number().optional().describe('Maximum results to return'),
      offset: z.number().optional().describe('Offset for pagination'),
    },
  }, async (args) => toMcpResult(await handleSecureSearch(mw, args)));

  server.registerTool('secure_glob', {
    title: 'Secure Glob',
    description:
      'Find files by glob pattern with access control enforcement. ' +
      'ALWAYS use this instead of native file listing tools (find, ls, Glob tool, git ls-files). ' +
      'Filters out denylist-blocked files and prevents path traversal. ' +
      'Returns file paths and sizes with pagination support.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      pattern: z.string().describe('Glob pattern to match files'),
      path: z.string().optional().describe('Scope search to this subdirectory'),
      max_results: z.number().optional().describe('Maximum results to return'),
      offset: z.number().optional().describe('Offset for pagination'),
    },
  }, async (args) => toMcpResult(await handleSecureGlob(mw, args)));

  server.registerTool('secure_tree', {
    title: 'Secure Tree',
    description:
      'Get directory structure with file counts, respecting access control. ' +
      'ALWAYS use this instead of native directory tools (tree, ls -R, find). ' +
      'Excludes denylist-blocked paths and respects depth limits for token efficiency.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().optional().describe('Root directory for the tree'),
      max_depth: z.number().optional().describe('Maximum depth to traverse'),
    },
  }, async (args) => toMcpResult(await handleSecureTree(mw, args)));

  server.registerTool('secure_diff', {
    title: 'Secure Diff',
    description:
      'Get redacted git diff output with denylist enforcement. ' +
      'ALWAYS use this instead of native diff tools (git diff, diff). ' +
      'Redacts secrets in diff hunks and blocks diffs that reference denylist-protected files.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      ref: z.string().optional().describe('Git ref to diff against'),
      path: z.string().optional().describe('Scope diff to this path'),
    },
  }, async (args) => toMcpResult(await handleSecureDiff(mw, args)));

  // ── Write tools ─────────────────────────────────────────────────────

  server.registerTool('secure_write', {
    title: 'Secure Write',
    description:
      'Write a file with secret scanning — rejects content containing detected secrets. ' +
      'ALWAYS use this instead of native write tools (Write tool, echo/cat redirection). ' +
      'Scans content for API keys, tokens, and passwords before writing. ' +
      'Enforces denylist rules and uses atomic writes for safety.',
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      content: z.string().describe('File content to write'),
    },
  }, async (args) => toMcpResult(await handleSecureWrite(mw, args)));

  server.registerTool('secure_patch', {
    title: 'Secure Patch',
    description:
      'Partial file edit with optimistic locking and secret scanning. ' +
      'ALWAYS use this instead of native edit tools (Edit tool, sed, awk, patch). ' +
      'Finds and replaces content in a file while scanning for secrets. ' +
      'Supports optimistic locking via expected_hash to prevent conflicting edits.',
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      old_content: z.string().describe('Content to find and replace'),
      new_content: z.string().describe('Replacement content'),
      expected_hash: z.string().optional().describe('SHA-256 hash for optimistic locking'),
    },
  }, async (args) => toMcpResult(await handleSecurePatch(mw, args)));

  // ── Meta tools ──────────────────────────────────────────────────────

  server.registerTool('secure_audit', {
    title: 'Secure Audit',
    description:
      'Security scan report showing blocked files, detected secrets, and denylist coverage. ' +
      'Use this to understand the security posture of the project before making changes. ' +
      'Summary counts always reflect the full scan. ' +
      'Verbose mode includes paginated per-file details (use offset/max_results for large repos).',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().optional().describe('Scope audit to this subdirectory'),
      verbose: z.boolean().optional().describe('Include per-file details (paginated)'),
      offset: z.number().int().min(0).optional().describe('Number of detail entries to skip (verbose mode only)'),
      max_results: z.number().int().min(1).optional().describe('Maximum detail entries to return (verbose mode only)'),
    },
  }, async (args) => toMcpResult(await handleSecureAudit(mw, args)));

  server.registerTool('secure_overview', {
    title: 'Secure Overview',
    description:
      'Project summary in a single call: framework, language, dependencies, and structure. ' +
      'Use this as the first step when exploring an unfamiliar project. ' +
      'Returns key metadata without exposing secrets or denylist-blocked content.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      path: z.string().optional().describe('Project root to analyze'),
      verbose: z.boolean().optional().describe('Include full dependency names'),
    },
  }, async (args) => toMcpResult(await handleSecureOverview(mw, args)));

  server.registerTool('secure_self_test', {
    title: 'Secure Self Test',
    description:
      'Run the built-in security validation suite to verify deployment integrity. ' +
      'Tests secret detection patterns, path traversal prevention, denylist enforcement, ' +
      'and false positive prevention. Use after installation or configuration changes.',
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    inputSchema: {},
  }, async () => toMcpResult(await handleSecureSelfTest(mw, {})));

  return server;
}
