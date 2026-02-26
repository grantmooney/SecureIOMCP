import { SecurityMiddleware } from '../../security/middleware.js';
import { SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface SecureDiffParams {
  ref?: string;
  path?: string;
}

export interface DiffResult {
  diff: string;
  files_changed: number;
  redacted_hunks: number;
}

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

function extractFilePath(diffHeader: string): string {
  // diff --git a/path/to/file b/path/to/file
  const match = diffHeader.match(/diff --git a\/(.+?) b\//);
  return match ? match[1] : '';
}
