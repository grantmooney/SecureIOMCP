/**
 * @module types/response
 * @description Response type definitions for all SecureIOMCP tool handlers.
 *
 * Every tool response is wrapped in a {@link SecureResponse} envelope that includes
 * both the result data and a {@link ResponseMeta} object with pagination, truncation,
 * and redaction metadata. This design enables token-efficient communication with
 * AI agents by providing enough context for the agent to decide whether to paginate
 * or refine its request.
 */

/**
 * Metadata envelope included with every tool response.
 *
 * Provides pagination state, truncation indicators, and redaction counts
 * so that AI agents can make informed decisions about follow-up requests.
 *
 * @example
 * ```json
 * {
 *   "total": 150,
 *   "returned": 50,
 *   "offset": 0,
 *   "has_more": true,
 *   "truncated_lines": 3,
 *   "redactions": 2,
 *   "bytes": 48200,
 *   "constrained_by": "maxResultCount"
 * }
 * ```
 */
export interface ResponseMeta {
  /** Total number of matching items available (before pagination). */
  total: number;
  /** Number of items actually returned in this response. */
  returned: number;
  /** Zero-based offset into the full result set. */
  offset: number;
  /** Whether additional results are available via pagination. */
  has_more: boolean;
  /** Number of lines that were truncated due to `maxLineLength`. */
  truncated_lines: number;
  /** Total number of secret redactions applied in this response. */
  redactions: number;
  /** Total size of the response payload in bytes. */
  bytes: number;
  /** Which limit caused the response to be constrained, if any. */
  constrained_by?: 'maxResultCount' | 'maxResponseBytes' | 'maxLineLength';
}

/**
 * Standard response envelope wrapping tool results with metadata.
 *
 * All successful tool responses use this structure. Error responses
 * use `{ error: SecureIOError }` instead.
 *
 * @typeParam T - The type of the `results` payload, specific to each tool.
 */
export interface SecureResponse<T> {
  /** Tool-specific result data. */
  results: T;
  /** Pagination, truncation, and redaction metadata. */
  meta: ResponseMeta;
}

/**
 * A single search match returned by `secure_search`.
 *
 * Includes the matching line with surrounding context lines,
 * and indicates whether the content was redacted.
 */
export interface SearchResult {
  /** File path relative to project root. */
  file: string;
  /** Line number of the match (1-indexed). */
  line: number;
  /** Content of the matching line (after redaction if applicable). */
  content: string;
  /** Lines before the match for context (redacted if applicable). */
  context_before: string[];
  /** Lines after the match for context (redacted if applicable). */
  context_after: string[];
  /** Whether any part of the matching line was redacted. */
  redacted: boolean;
}

/**
 * A file entry returned by `secure_glob`.
 *
 * Contains path and size metadata only — no file content is exposed.
 */
export interface GlobResult {
  /** File path relative to project root. */
  path: string;
  /** File size in bytes. */
  size: number;
}

/**
 * A node in the directory tree returned by `secure_tree`.
 *
 * Represents either a file or a directory. Directories may contain
 * children (up to the configured max depth) and a file count.
 */
export interface TreeEntry {
  /** Name of the file or directory. */
  name: string;
  /** Whether this entry is a `'file'` or `'directory'`. */
  type: 'file' | 'directory';
  /** Child entries (only present for directories within the depth limit). */
  children?: TreeEntry[];
  /** Number of direct child files in this directory. */
  file_count?: number;
}

/**
 * Result of reading a file via `secure_read`.
 *
 * Content is returned with automatic secret redaction applied.
 * Line numbers are 1-indexed and can be used for pagination.
 */
export interface ReadResult {
  /** File path relative to project root (as requested). */
  path: string;
  /** File content with secrets redacted (line range may be a subset). */
  content: string;
  /** Starting line number of the returned content (1-indexed). */
  start_line: number;
  /** Ending line number of the returned content. */
  end_line: number;
  /** Total number of lines in the file. */
  total_lines: number;
  /** Line numbers (1-indexed) where redactions were applied within the returned range. */
  redacted_lines: number[];
  /** Detected file encoding (e.g., `'utf-8'`, `'utf-8-bom'`, `'utf-16le'`, `'utf-16be'`). */
  encoding_detected: string;
}

/**
 * Result of writing a file via `secure_write`.
 */
export interface WriteResult {
  /** File path relative to project root (as requested). */
  path: string;
  /** Whether the write operation succeeded. */
  success: boolean;
  /** SHA-256 hash of the written content (for use with optimistic locking in `secure_patch`). */
  hash: string;
}

/**
 * Result of patching a file via `secure_patch`.
 */
export interface PatchResult {
  /** File path relative to project root (as requested). */
  path: string;
  /** Whether the patch operation succeeded. */
  success: boolean;
  /** Line range affected by the patch (1-indexed). */
  changed_range: { start: number; end: number };
  /** SHA-256 hash of the file content after patching (for subsequent optimistic locking). */
  hash: string;
}

/**
 * Project overview information returned by `secure_overview`.
 *
 * Provides a high-level summary of the project's technology stack,
 * dependencies, and structure for AI agent orientation.
 */
export interface OverviewResult {
  /** Project name from `package.json` or directory name. */
  name: string;
  /** Detected framework (e.g., `'next'`, `'react'`, `'express'`), or `null`. */
  framework: string | null;
  /** Detected primary language (e.g., `'typescript'`, `'python'`), or `null`. */
  language: string | null;
  /** Detected package manager (e.g., `'npm'`, `'pnpm'`, `'yarn'`, `'bun'`), or `null`. */
  packageManager: string | null;
  /** Application entry points from `package.json` (main, module, bin). */
  entryPoints: string[];
  /** NPM scripts from `package.json`. */
  scripts: Record<string, string>;
  /** Number of production dependencies. */
  dependencyCount: number;
  /** Number of development dependencies. */
  devDependencyCount: number;
  /** Text summary of the top-level directory structure. */
  structure: string;
  /** Configuration files found in the project root. */
  configFiles: string[];
}

/**
 * Security audit scan results returned by `secure_audit`.
 *
 * Summarizes the security posture of the project including blocked files,
 * detected secrets, and active protection rules.
 */
export interface AuditResult {
  /** Active security preset (`'strict'` or `'standard'`). */
  preset: string;
  /** Number of files blocked by the denylist. */
  files_blocked: number;
  /** Total number of secret instances detected across all files. */
  secrets_detected: number;
  /** Number of files containing at least one detected secret. */
  files_with_secrets: number;
  /** Number of denylist rules in effect. */
  denylist_rules: number;
  /** Number of custom redaction patterns configured. */
  custom_patterns: number;
  /** Per-file details (only included when `verbose: true`). */
  details?: AuditFileDetail[];
}

/**
 * Per-file detail in a verbose audit report.
 */
export interface AuditFileDetail {
  /** File path relative to project root. */
  path: string;
  /** Whether the file is blocked by the denylist. */
  blocked: boolean;
  /** Redactions found in this file (empty if blocked). */
  redactions: { line: number; category: string; confidence: string }[];
}

/**
 * Results of the `secure_self_test` validation suite.
 *
 * Used to verify that the security layer is functioning correctly
 * after deployment. Can be triggered via `--self-test` CLI flag.
 */
export interface SelfTestResult {
  /** Whether all test categories passed. */
  passed: boolean;
  /** Individual test category results. */
  categories: SelfTestCategory[];
}

/**
 * A single test category within the self-test results.
 */
export interface SelfTestCategory {
  /** Category name (e.g., `'pattern_detection'`, `'traversal_prevention'`). */
  name: string;
  /** Whether all tests in this category passed. */
  passed: boolean;
  /** Total number of test cases in this category. */
  total: number;
  /** Descriptions of any failed test cases. */
  failures: string[];
}
