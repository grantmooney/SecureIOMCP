export interface ResponseMeta {
  total: number;
  returned: number;
  offset: number;
  has_more: boolean;
  truncated_lines: number;
  redactions: number;
  bytes: number;
  constrained_by?: 'maxResultCount' | 'maxResponseBytes' | 'maxLineLength';
}

export interface SecureResponse<T> {
  results: T;
  meta: ResponseMeta;
}

export interface SearchResult {
  file: string;
  line: number;
  content: string;
  context_before: string[];
  context_after: string[];
  redacted: boolean;
}

export interface GlobResult {
  path: string;
  size: number;
}

export interface TreeEntry {
  name: string;
  type: 'file' | 'directory';
  children?: TreeEntry[];
  file_count?: number;
}

export interface ReadResult {
  path: string;
  content: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  redacted_lines: number[];
  encoding_detected: string;
}

export interface WriteResult {
  path: string;
  success: boolean;
  hash: string;
}

export interface PatchResult {
  path: string;
  success: boolean;
  changed_range: { start: number; end: number };
  hash: string;
}

export interface OverviewResult {
  name: string;
  framework: string | null;
  language: string | null;
  packageManager: string | null;
  entryPoints: string[];
  scripts: Record<string, string>;
  dependencyCount: number;
  devDependencyCount: number;
  structure: string;
  configFiles: string[];
}

export interface AuditResult {
  preset: string;
  files_blocked: number;
  secrets_detected: number;
  files_with_secrets: number;
  denylist_rules: number;
  custom_patterns: number;
  details?: AuditFileDetail[];
}

export interface AuditFileDetail {
  path: string;
  blocked: boolean;
  redactions: { line: number; category: string; confidence: string }[];
}

export interface SelfTestResult {
  passed: boolean;
  categories: SelfTestCategory[];
}

export interface SelfTestCategory {
  name: string;
  passed: boolean;
  total: number;
  failures: string[];
}
