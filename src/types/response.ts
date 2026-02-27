/**
 * Pagination and constraint metadata included in every tool response.
 * Enables agents to make strategic decisions about pagination without wasting tokens.
 */
export interface ResponseMeta {
  /** Total number of matching items available (before pagination) */
  total: number;
  /** Number of items included in this response */
  returned: number;
  /** Number of items skipped from the beginning */
  offset: number;
  /** Whether more results are available beyond this response */
  has_more: boolean;
  /** Number of lines truncated due to `maxLineLength` */
  truncated_lines: number;
  /** Total number of secrets redacted in this response */
  redactions: number;
  /** Total response payload size in bytes */
  bytes: number;
  /** Which limit caused the response to stop, if any */
  constrained_by?: 'maxResultCount' | 'maxResponseBytes' | 'maxLineLength';
}

/**
 * Standard response envelope wrapping tool results with pagination metadata.
 *
 * @typeParam T - The result type specific to each tool
 */
export interface SecureResponse<T> {
  /** Tool-specific result data */
  results: T;
  /** Pagination and constraint metadata */
  meta: ResponseMeta;
}

/** A single search match returned by `secure_search`. */
export interface SearchResult {
  /** File path relative to project root */
  file: string;
  /** Line number of the match (1-indexed) */
  line: number;
  /** Matching line content (with secrets redacted) */
  content: string;
  /** Lines before the match (with secrets redacted) */
  context_before: string[];
  /** Lines after the match (with secrets redacted) */
  context_after: string[];
  /** Whether any secrets were redacted in this result */
  redacted: boolean;
}

/** A file match returned by `secure_glob`. */
export interface GlobResult {
  /** File path relative to project root */
  path: string;
  /** File size in bytes */
  size: number;
}

/** A node in the directory tree returned by `secure_tree`. */
export interface TreeEntry {
  /** File or directory name */
  name: string;
  /** Whether this entry is a file or directory */
  type: 'file' | 'directory';
  /** Child entries (only present for directories within max_depth) */
  children?: TreeEntry[];
  /** Number of files directly in this directory */
  file_count?: number;
}

/** File content returned by `secure_read`. */
export interface ReadResult {
  /** File path relative to project root */
  path: string;
  /** File content with secrets replaced by `[REDACTED:CATEGORY]` */
  content: string;
  /** First line number in the returned range (1-indexed) */
  start_line: number;
  /** Last line number in the returned range */
  end_line: number;
  /** Total number of lines in the file */
  total_lines: number;
  /** Line numbers where secrets were redacted */
  redacted_lines: number[];
  /** Detected file encoding (e.g., 'utf-8', 'utf-16le') */
  encoding_detected: string;
}

/** Result of a successful `secure_write` operation. */
export interface WriteResult {
  /** File path relative to project root */
  path: string;
  /** Whether the write succeeded */
  success: boolean;
  /** SHA-256 hash of the written content */
  hash: string;
}

/** Result of a successful `secure_patch` operation. */
export interface PatchResult {
  /** File path relative to project root */
  path: string;
  /** Whether the patch succeeded */
  success: boolean;
  /** Line range affected by the patch */
  changed_range: { start: number; end: number };
  /** SHA-256 hash of the file after patching */
  hash: string;
}

/** Project summary returned by `secure_overview`. */
export interface OverviewResult {
  /** Project name from package.json or directory name */
  name: string;
  /** Detected framework (e.g., 'next', 'express', 'react') or null */
  framework: string | null;
  /** Detected primary language (e.g., 'typescript', 'python') or null */
  language: string | null;
  /** Detected package manager (e.g., 'npm', 'pnpm', 'yarn', 'bun') or null */
  packageManager: string | null;
  /** Entry point files from package.json (main, module, bin) */
  entryPoints: string[];
  /** Scripts defined in package.json */
  scripts: Record<string, string>;
  /** Number of production dependencies */
  dependencyCount: number;
  /** Number of development dependencies */
  devDependencyCount: number;
  /** Compact directory structure summary */
  structure: string;
  /** Configuration files detected in the project */
  configFiles: string[];
}

/** Security audit summary returned by `secure_audit`. */
export interface AuditResult {
  /** Active security preset */
  preset: string;
  /** Number of files blocked by the denylist */
  files_blocked: number;
  /** Total number of secrets detected across all files */
  secrets_detected: number;
  /** Number of unique files containing at least one secret */
  files_with_secrets: number;
  /** Number of active denylist rules */
  denylist_rules: number;
  /** Number of custom redaction patterns loaded */
  custom_patterns: number;
  /** Per-file details (only present when `verbose: true`) */
  details?: AuditFileDetail[];
}

/** Per-file detail in a verbose audit report. */
export interface AuditFileDetail {
  /** File path relative to project root */
  path: string;
  /** Whether this file is blocked by the denylist */
  blocked: boolean;
  /** Secrets detected in this file (line numbers, categories, confidence) */
  redactions: { line: number; category: string; confidence: string }[];
}

/** Overall result of the `secure_self_test` validation suite. */
export interface SelfTestResult {
  /** Whether all test categories passed */
  passed: boolean;
  /** Results for each test category */
  categories: SelfTestCategory[];
}

/** Result of a single test category within `secure_self_test`. */
export interface SelfTestCategory {
  /** Category name (e.g., 'pattern_detection', 'traversal_prevention') */
  name: string;
  /** Whether all tests in this category passed */
  passed: boolean;
  /** Total number of tests in this category */
  total: number;
  /** Descriptions of failed tests (empty if all passed) */
  failures: string[];
}
