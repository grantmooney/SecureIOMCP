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
    version: '0.1.0',
  });

  // Read tools
  server.registerTool('secure_read', {
    description: 'Read a file with automatic secret redaction',
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      start_line: z.number().optional().describe('Starting line number (1-indexed)'),
      end_line: z.number().optional().describe('Ending line number'),
    },
  }, async (args) => toMcpResult(await handleSecureRead(mw, args)));

  server.registerTool('secure_search', {
    description: 'Search across files with regex pattern matching and redaction',
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
    description: 'Find files by glob pattern, respecting access control',
    inputSchema: {
      pattern: z.string().describe('Glob pattern to match files'),
      path: z.string().optional().describe('Scope search to this subdirectory'),
      max_results: z.number().optional().describe('Maximum results to return'),
      offset: z.number().optional().describe('Offset for pagination'),
    },
  }, async (args) => toMcpResult(await handleSecureGlob(mw, args)));

  server.registerTool('secure_tree', {
    description: 'Get directory structure with file counts',
    inputSchema: {
      path: z.string().optional().describe('Root directory for the tree'),
      max_depth: z.number().optional().describe('Maximum depth to traverse'),
    },
  }, async (args) => toMcpResult(await handleSecureTree(mw, args)));

  server.registerTool('secure_diff', {
    description: 'Get redacted git diff output',
    inputSchema: {
      ref: z.string().optional().describe('Git ref to diff against'),
      path: z.string().optional().describe('Scope diff to this path'),
    },
  }, async (args) => toMcpResult(await handleSecureDiff(mw, args)));

  // Write tools
  server.registerTool('secure_write', {
    description: 'Write a file with secret scanning (rejects if secrets detected)',
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      content: z.string().describe('File content to write'),
    },
  }, async (args) => toMcpResult(await handleSecureWrite(mw, args)));

  server.registerTool('secure_patch', {
    description: 'Partial file edit with optimistic locking and secret scanning',
    inputSchema: {
      path: z.string().describe('File path relative to project root'),
      old_content: z.string().describe('Content to find and replace'),
      new_content: z.string().describe('Replacement content'),
      expected_hash: z.string().optional().describe('SHA-256 hash for optimistic locking'),
    },
  }, async (args) => toMcpResult(await handleSecurePatch(mw, args)));

  // Meta tools
  server.registerTool('secure_audit', {
    description: 'Security scan report showing blocked files and detected secrets',
    inputSchema: {
      path: z.string().optional().describe('Scope audit to this subdirectory'),
      verbose: z.boolean().optional().describe('Include per-file details'),
    },
  }, async (args) => toMcpResult(await handleSecureAudit(mw, args)));

  server.registerTool('secure_overview', {
    description: 'Project summary: framework, language, dependencies, structure',
    inputSchema: {
      path: z.string().optional().describe('Project root to analyze'),
      verbose: z.boolean().optional().describe('Include full dependency names'),
    },
  }, async (args) => toMcpResult(await handleSecureOverview(mw, args)));

  server.registerTool('secure_self_test', {
    description: 'Run security validation suite to verify deployment',
    inputSchema: {},
  }, async () => toMcpResult(await handleSecureSelfTest(mw, {})));

  return server;
}
