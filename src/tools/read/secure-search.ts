import { SecurityMiddleware } from '../../security/middleware.js';
import { SearchResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { ResponseBuilder } from '../../response.js';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';

/** Parameters for the `secure_search` MCP tool. */
export interface SecureSearchParams {
  /** Regex pattern to search for */
  pattern: string;
  /** Scope search to this subdirectory */
  path?: string;
  /** File glob filter (e.g., `*.ts`) */
  file_pattern?: string;
  /** Number of context lines before and after each match (default: 0) */
  context_lines?: number;
  /** Maximum results to return */
  max_results?: number;
  /** Offset for pagination */
  offset?: number;
  /** Compact output format (default: true). Set false for structured objects. */
  compact?: boolean;
}

/** A raw match yielded by the file-walking helper. */
interface RawMatch {
  file: string;
  lineNum: number;
  redactedText: string;
  redacted: boolean;
  redactionCount: number;
  contextBefore?: string[];
  contextAfter?: string[];
}

/**
 * Handles the `secure_search` MCP tool: searches across files with regex pattern matching.
 * Collects files (skipping node_modules, .git, etc.), matches regex against each line,
 * and returns redacted results with surrounding context. Supports pagination via offset.
 *
 * @param mw - Security middleware instance
 * @param params - Tool parameters including the regex pattern
 * @returns Paginated search results with redacted content, or a safe error response
 */
export async function handleSecureSearch(
  mw: SecurityMiddleware,
  params: SecureSearchParams,
): Promise<SecureResponse<(SearchResult | string)[]> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Validate regex
  let regex: RegExp;
  try {
    regex = new RegExp(params.pattern, 'gi');
  } catch {
    return {
      error: {
        code: 'INVALID_REGEX',
        message: 'Invalid search pattern',
        suggestion: 'Ensure the pattern is a valid regular expression.',
      },
    };
  }

  const searchRoot = params.path ?? '.';
  const contextLines = params.context_lines ?? 0;
  const offset = params.offset ?? 0;
  const compact = params.compact ?? true;

  // Collect files to search
  const files = await collectFiles(
    path.resolve(mw.config.projectRoot, searchRoot),
    mw.config.projectRoot,
    mw,
    params.file_pattern,
  );

  // Collect all raw matches
  const rawMatches: RawMatch[] = [];
  for (const filePath of files) {
    const absolutePath = path.resolve(mw.config.projectRoot, filePath);

    try {
      const stat = await fsp.stat(absolutePath);
      if (!stat.isFile()) continue;

      // Skip binary files
      const headBuf = Buffer.alloc(512);
      const fd = await fsp.open(absolutePath, 'r');
      let bytesRead = 0;
      try {
        const readResult = await fd.read(headBuf, 0, 512, 0);
        bytesRead = readResult.bytesRead;
      } finally {
        await fd.close();
      }

      const { isBinary } = await import('../../security/encoding-detector.js');
      if (isBinary(headBuf.subarray(0, bytesRead))) continue;

      const fileLines: string[] = [];
      const rl = readline.createInterface({
        input: fs.createReadStream(absolutePath, { encoding: 'utf-8' }),
        crlfDelay: Infinity,
      });

      for await (const line of rl) {
        fileLines.push(line);
      }

      for (let i = 0; i < fileLines.length; i++) {
        const line = fileLines[i];
        regex.lastIndex = 0;
        if (!regex.test(line)) continue;

        const redacted = mw.redactLine(line);
        const match: RawMatch = {
          file: filePath,
          lineNum: i + 1,
          redactedText: redacted.text,
          redacted: redacted.matches.length > 0,
          redactionCount: redacted.matches.length,
        };

        // Eagerly resolve context so fileLines can be GC'd after this file
        if (contextLines > 0) {
          const contextBefore: string[] = [];
          const contextAfter: string[] = [];
          for (let j = Math.max(0, i - contextLines); j < i; j++) {
            contextBefore.push(mw.redactLine(fileLines[j]).text);
          }
          for (let j = i + 1; j <= Math.min(fileLines.length - 1, i + contextLines); j++) {
            contextAfter.push(mw.redactLine(fileLines[j]).text);
          }
          match.contextBefore = contextBefore;
          match.contextAfter = contextAfter;
        }

        rawMatches.push(match);
      }
    } catch {
      continue;
    }
  }

  const totalMatches = rawMatches.length;

  let response: SecureResponse<(SearchResult | string)[]>;

  if (compact) {
    const builder = new ResponseBuilder<string>(mw.config.limits, offset);
    let skipped = 0;

    for (const match of rawMatches) {
      if (skipped < offset) { skipped++; continue; }
      if (match.redactionCount > 0) builder.addRedactions(match.redactionCount);
      if (!builder.add(`${match.file}:${match.lineNum}:${match.redactedText}`)) break;
    }

    builder.setTotal(totalMatches);
    response = builder.build();
  } else {
    const builder = new ResponseBuilder<SearchResult>(mw.config.limits, offset);
    let skipped = 0;

    for (const match of rawMatches) {
      if (skipped < offset) { skipped++; continue; }
      if (match.redactionCount > 0) builder.addRedactions(match.redactionCount);

      const result: SearchResult = {
        file: match.file,
        line: match.lineNum,
        content: match.redactedText,
        redacted: match.redacted,
      };

      if (contextLines > 0 && match.contextBefore && match.contextAfter) {
        result.context_before = match.contextBefore;
        result.context_after = match.contextAfter;
      }

      if (!builder.add(result)) break;
    }

    builder.setTotal(totalMatches);
    response = builder.build();
  }

  await mw.auditLogger.log({
    tool: 'secure_search',
    params: { pattern: params.pattern, path: searchRoot },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return response;
}

/**
 * Recursively collects file paths from a directory tree, respecting access control
 * and optional file pattern filtering. Skips node_modules, .git, dist, build, and vendor.
 */
async function collectFiles(
  dir: string,
  projectRoot: string,
  mw: SecurityMiddleware,
  filePattern?: string,
): Promise<string[]> {
  const files: string[] = [];
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'vendor']);

  async function walk(currentDir: string): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(projectRoot, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (!mw.accessControl.isAllowed(relativePath)) continue;

        if (filePattern) {
          // Simple glob matching: *.ts, *.js etc.
          const ext = path.extname(entry.name);
          const patternExt = filePattern.startsWith('*') ? filePattern.slice(1) : filePattern;
          if (ext !== patternExt) continue;
        }

        files.push(relativePath);
      }
    }
  }

  await walk(dir);
  return files.sort();
}
