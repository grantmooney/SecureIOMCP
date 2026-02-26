import { SecurityMiddleware } from '../../security/middleware.js';
import { SearchResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { ResponseBuilder } from '../../response.js';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';

export interface SecureSearchParams {
  pattern: string;
  path?: string;
  file_pattern?: string;
  context_lines?: number;
  max_results?: number;
  offset?: number;
}

export async function handleSecureSearch(
  mw: SecurityMiddleware,
  params: SecureSearchParams,
): Promise<SecureResponse<SearchResult[]> | { error: SecureIOError }> {
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
  const contextLines = params.context_lines ?? 2;
  const maxResults = params.max_results ?? mw.config.limits.maxResultCount;
  const offset = params.offset ?? 0;

  const builder = new ResponseBuilder<SearchResult>(mw.config.limits, offset);
  let totalMatches = 0;
  let skipped = 0;

  // Collect files to search
  const files = await collectFiles(
    path.resolve(mw.config.projectRoot, searchRoot),
    mw.config.projectRoot,
    mw,
    params.file_pattern,
  );

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
        // Reset regex for each line
        regex.lastIndex = 0;
        if (!regex.test(line)) continue;

        totalMatches++;

        if (skipped < offset) {
          skipped++;
          continue;
        }

        // Redact the matching line
        const redacted = mw.redactLine(line);
        const isRedacted = redacted.matches.length > 0;

        // Build context
        const contextBefore: string[] = [];
        const contextAfter: string[] = [];

        for (let j = Math.max(0, i - contextLines); j < i; j++) {
          const ctxRedacted = mw.redactLine(fileLines[j]);
          contextBefore.push(ctxRedacted.text);
        }

        for (let j = i + 1; j <= Math.min(fileLines.length - 1, i + contextLines); j++) {
          const ctxRedacted = mw.redactLine(fileLines[j]);
          contextAfter.push(ctxRedacted.text);
        }

        if (redacted.matches.length > 0) {
          builder.addRedactions(redacted.matches.length);
        }

        const added = builder.add({
          file: filePath,
          line: i + 1,
          content: redacted.text,
          context_before: contextBefore,
          context_after: contextAfter,
          redacted: isRedacted,
        });

        if (!added) break;
      }
    } catch {
      // Skip files we can't read
      continue;
    }
  }

  builder.setTotal(totalMatches);

  await mw.auditLogger.log({
    tool: 'secure_search',
    params: { pattern: params.pattern, path: searchRoot },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return builder.build();
}

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
