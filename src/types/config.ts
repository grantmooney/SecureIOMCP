export type Preset = 'standard' | 'strict';

export interface RedactionPattern {
  name: string;
  pattern: string;
  description: string;
  confidence: 'high' | 'medium' | 'entropy';
}

export interface DenylistConfig {
  extend: string[];
}

export interface RedactionConfig {
  customPatterns: RedactionPattern[];
}

export interface AuditConfig {
  output: 'file' | 'stdout' | 'none';
  path: string;
  required?: boolean;
  minimumOutput?: 'file' | 'stdout';
}

export interface LimitsConfig {
  maxResultCount: number;
  maxLineLength: number;
  maxResponseBytes: number;
  maxFileReadLines: number;
  maxWriteBytes: number;
  maxTreeDepth: number;
  maxAuditLogSizeMB: number;
}

export interface ProjectConfig {
  preset: Preset;
  projectRoot: string;
  denylist: DenylistConfig;
  redaction: RedactionConfig;
  audit: AuditConfig;
  limits: LimitsConfig;
}

export interface SystemPolicy {
  minimumPreset: Preset;
  denylist: DenylistConfig;
  redaction: RedactionConfig;
  audit: {
    required: boolean;
    minimumOutput: 'file' | 'stdout';
  };
}

export interface ResolvedConfig {
  preset: Preset;
  projectRoot: string;
  denylist: string[];
  redactionPatterns: RedactionPattern[];
  audit: AuditConfig;
  limits: LimitsConfig;
  entropyDetection: boolean;
}
