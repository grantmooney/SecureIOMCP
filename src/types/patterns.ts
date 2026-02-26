export interface CompiledPattern {
  name: string;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'entropy';
  description: string;
}

export interface RedactionMatch {
  start: number;
  end: number;
  category: string;
  confidence: 'high' | 'medium' | 'entropy';
}
