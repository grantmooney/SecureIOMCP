/**
 * @module secure-diff
 *
 * MCP tool handler for `secure_diff`. Executes `git diff` against the
 * project repository and returns the output with automatic secret redaction
 * and denylist enforcement.
 *
 * Security pipeline per request:
 * 1. Run `git diff` with optional ref and path scoping
 * 2. Parse the raw diff output, identifying per-file hunks
 * 3. Block diffs for files on the denylist (replaced with `[REDACTED PATH]`)
 * 4. Redact secrets in added (`+`) and removed (`-`) lines
 * 5. Audit-log the invocation
 *
 * Requires `git` to be available on the system `PATH`.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Parameters accepted by the `secure_diff` MCP tool.
 *
 * @property ref  - Optional git ref (commit, branch, tag) to diff against.
 *                  When omitted, diffs the working tree against the index.
 * @property path - Optional path to scope the diff to a specific file or directory.
 */
export interface SecureDiffParams {
  ref?: string;
  path?: string;
}

/**
 * Result returned by the `secure_diff` tool after redaction.
 *
 * @property diff           - The redacted diff text.
 * @property files_changed  - Number of files included in the diff.
 * @property redacted_hunks - Number of file diffs that were fully blocked
 *                            because the file is on the denylist.
 */
export interface DiffResult {
  diff: string;
  files_changed: number;
  redacted_hunks: number;
}

/**
 * Handle a `secure_diff` tool invocation.
 *
 * Spawns `git diff` in the project root, parses the output through
 * {@link redactDiff} to block denylist files and redact secrets, then
 * returns the sanitised diff with metadata. The invocation is recorded
 * in the audit log.
 *
 * @param mw     - The initialised {@link SecurityMiddleware} instance.
 * @param params - Validated tool parameters (optional ref and path).
 * @returns A {@link SecureResponse} containing a {@link DiffResult},
 *          or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecureDiff(
  mw: SecurityMiddleware,
  params: SecureDiffParams,
): Promise<SecureResponse<DiffResult> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Build git diff command
  const args = ['diff'];
  if (params.ref) args.push(params.ref);
  if (params.path) args.push('--', params.path);

  let rawDiff: string;
  try {
    const result = await execFileAsync('git', args, {
      cwd: mw.config.projectRoot,
      maxBuffer: 1024 * 1024,
    });
    rawDiff = result.stdout;
  } catch (err: unknown) {
    const execErr = err as { stderr?: string; code?: number };
    if (execErr.stderr?.includes('not a git repository')) {
      return {
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Not a git repository',
          suggestion: 'This tool requires a git repository.',
        },
      };
    }
    return {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to run git diff',
        suggestion: 'Ensure git is installed and the project is a git repository.',
      },
    };
  }

  // Parse and redact the diff
  const { redactedDiff, filesChanged, redactedHunks } = redactDiff(rawDiff, mw);

  await mw.auditLogger.log({
    tool: 'secure_diff',
    params: { ref: params.ref, path: params.path },
    redactions: [],
    access_denied: false,
    severity: 'normal',
    duration_ms: Date.now() - startTime,
  });

  return {
    results: {
      diff: redactedDiff,
      files_changed: filesChanged,
      redacted_hunks: redactedHunks,
    },
    meta: {
      total: filesChanged,
      returned: filesChanged,
      offset: 0,
      has_more: false,
      truncated_lines: 0,
      redactions: redactedHunks,
      bytes: Buffer.byteLength(redactedDiff, 'utf-8'),
    },
  };
}

/**
 * Redact a raw git diff string by blocking denylist files and redacting
 * secrets in changed lines.
 *
 * For each file header (`diff --git a/... b/...`), the file path is
 * checked against the access-control denylist. If the file is blocked,
 * the entire hunk is replaced with a redaction notice. For allowed files,
 * added and removed lines are individually passed through the security
 * middleware's secret redactor.
 *
 * @param rawDiff - The raw `git diff` output string.
 * @param mw      - The security middleware providing access-control and redaction.
 * @returns An object containing the redacted diff text, the total number
 *          of files changed, and the count of fully redacted hunks.
 */
function redactDiff(
  rawDiff: string,
  mw: SecurityMiddleware,
): { redactedDiff: string; filesChanged: number; redactedHunks: number } {
  if (!rawDiff.trim()) {
    return { redactedDiff: '', filesChanged: 0, redactedHunks: 0 };
  }

  const lines = rawDiff.split('\n');
  const outputLines: string[] = [];
  let filesChanged = 0;
  let redactedHunks = 0;
  let currentFileBlocked = false;

  for (const line of lines) {
    // Detect file header: diff --git a/path b/path
    if (line.startsWith('diff --git ')) {
      filesChanged++;
      const filePath = extractFilePath(line);
      const relPath = filePath.replace(/\\/g, '/');

      if (filePath && !mw.accessControl.isAllowed(relPath)) {
        currentFileBlocked = true;
        redactedHunks++;
        outputLines.push('diff --git [REDACTED PATH] [REDACTED PATH]');
        outputLines.push('[DIFF BLOCKED: protected file]');
        continue;
      }

      currentFileBlocked = false;
      outputLines.push(line);
      continue;
    }

    // Skip lines in blocked files
    if (currentFileBlocked) continue;

    // Redact + and - lines
    if (line.startsWith('+') && !line.startsWith('+++')) {
      const redacted = mw.redactLine(line.substring(1));
      outputLines.push('+' + redacted.text);
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      const redacted = mw.redactLine(line.substring(1));
      outputLines.push('-' + redacted.text);
    } else {
      outputLines.push(line);
    }
  }

  return {
    redactedDiff: outputLines.join('\n'),
    filesChanged,
    redactedHunks,
  };
}

/**
 * Extract the file path from a `diff --git` header line.
 *
 * Parses lines of the form `diff --git a/path/to/file b/path/to/file`
 * and returns the path portion after `a/`.
 *
 * @param diffHeader - A single diff header line starting with `diff --git`.
 * @returns The extracted file path, or an empty string if parsing fails.
 */
function extractFilePath(diffHeader: string): string {
  // diff --git a/path/to/file b/path/to/file
  const match = diffHeader.match(/diff --git a\/(.+?) b\//);
  return match ? match[1] : '';
}
