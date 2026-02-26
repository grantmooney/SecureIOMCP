export type ErrorCode =
  | 'PATH_DENIED'
  | 'SECRET_IN_WRITE'
  | 'INVALID_REGEX'
  | 'FILE_NOT_FOUND'
  | 'BINARY_FILE'
  | 'ENCODING_UNSUPPORTED'
  | 'SIZE_EXCEEDED'
  | 'HASH_MISMATCH'
  | 'CONFIG_ERROR'
  | 'INTERNAL_ERROR';

export interface SecureIOError {
  code: ErrorCode;
  message: string;
  suggestion?: string;
}

export type AuditSeverity = 'normal' | 'warning' | 'security';

export interface AuditLogEntry {
  timestamp: string;
  tool: string;
  params: Record<string, unknown>;
  redactions: AuditRedaction[];
  access_denied: boolean;
  severity: AuditSeverity;
  duration_ms: number;
  error?: ErrorCode;
}

export interface AuditRedaction {
  line: number;
  category: string;
  confidence: 'high' | 'medium' | 'entropy';
}
