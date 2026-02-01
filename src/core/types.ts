/**
 * Trust levels for memory sources
 */
export enum TrustLevel {
  /** Direct user input - highest trust */
  USER = 'user',
  /** Verified/allowlisted tools */
  TOOL_VERIFIED = 'tool_verified',
  /** Unverified external tools */
  TOOL_UNVERIFIED = 'tool_unverified',
  /** Agent-generated content */
  AGENT = 'agent',
  /** External/web content - lowest trust */
  EXTERNAL = 'external',
}

/**
 * Provenance metadata attached to each memory entry
 */
export interface MemoryProvenance {
  /** Unique identifier for this provenance record */
  id: string;
  /** Source of the memory (e.g., 'user', 'web_scrape', 'tool:github') */
  source: string;
  /** Trust level based on source classification */
  trustLevel: TrustLevel;
  /** Timestamp when memory was ingested */
  timestamp: Date;
  /** Session ID for grouping related memories */
  sessionId?: string;
  /** Context that triggered this memory creation */
  triggerContext?: string;
  /** Detection score from analysis (0-1, higher = more suspicious) */
  detectionScore?: number;
  /** Flags raised during detection */
  flags?: string[];
}

/**
 * Result from the detection pipeline
 */
export interface DetectionResult {
  /** Whether the content passed detection (false = flagged) */
  passed: boolean;
  /** Overall risk score (0-1, higher = more suspicious) */
  score: number;
  /** Layer 1 pattern matches */
  layer1: {
    triggered: boolean;
    patterns: string[];
  };
  /** Layer 2 semantic similarity results */
  layer2: {
    triggered: boolean;
    similarity: number;
    matchedExemplar?: string;
  };
  /** Layer 3 LLM judge results (only for borderline cases) */
  layer3?: {
    evaluated: boolean;
    verdict?: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
    confidence?: number;
    reasoning?: string;
  };
  /** Anomaly detection results (behavioral baseline) */
  anomaly?: {
    score: number;
    signals: Array<{
      type: string;
      description: string;
      severity: number;
    }>;
    inLearningPeriod: boolean;
  };
  /** Human-readable explanation */
  reason: string;
}

/**
 * Status of a quarantined memory
 */
export type QuarantineStatus = 'pending' | 'approved' | 'rejected';

/**
 * A memory that has been quarantined for review
 */
export interface QuarantinedMemory {
  /** Unique identifier */
  id: string;
  /** Original memory text */
  text: string;
  /** Source of the memory */
  source: string;
  /** Trust level of the source */
  trustLevel: TrustLevel;
  /** Layer 1 pattern flags */
  layer1Flags: string[];
  /** Layer 2 similarity score */
  layer2Similarity: number;
  /** The exemplar that matched (if any) */
  layer2Exemplar?: string;
  /** Layer 3 LLM verdict (if evaluated) */
  layer3Verdict?: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  /** Layer 3 reasoning */
  layer3Reasoning?: string;
  /** When the memory was quarantined */
  quarantinedAt: Date;
  /** Current status */
  status: QuarantineStatus;
  /** When the memory was reviewed */
  reviewedAt?: Date;
  /** Who reviewed the memory */
  reviewedBy?: string;
}

/**
 * A stored memory entry with provenance
 */
export interface Memory {
  /** Unique identifier */
  id: string;
  /** Memory content */
  text: string;
  /** Provenance metadata */
  provenance: MemoryProvenance;
  /** When the memory was stored */
  createdAt: Date;
  /** When the memory was last accessed */
  lastAccessedAt?: Date;
}

/**
 * Configuration for memfw
 */
export interface MemfwConfig {
  /** OpenAI API key for embeddings and LLM judge */
  openaiApiKey: string;
  /** Path to SQLite database */
  dbPath?: string;
  /** Layer 2 similarity threshold (default: 0.82) */
  similarityThreshold?: number;
  /** Trust-adjusted threshold modifiers */
  trustThresholds?: Partial<Record<TrustLevel, number>>;
  /** Whether to enable Layer 2 semantic analysis */
  enableLayer2?: boolean;
  /** Whether to enable Layer 3 LLM judge for borderline cases */
  enableLayer3?: boolean;
  /** Model to use for Layer 3 LLM judge (default: gpt-4o-mini) */
  layer3Model?: string;
}

/**
 * Default trust-adjusted thresholds
 * Lower values = stricter (more likely to flag)
 */
export const DEFAULT_TRUST_THRESHOLDS: Record<TrustLevel, number> = {
  [TrustLevel.USER]: 0.90,
  [TrustLevel.TOOL_VERIFIED]: 0.85,
  [TrustLevel.TOOL_UNVERIFIED]: 0.80,
  [TrustLevel.AGENT]: 0.78,
  [TrustLevel.EXTERNAL]: 0.75,
};

/**
 * Default similarity threshold for Layer 2
 */
export const DEFAULT_SIMILARITY_THRESHOLD = 0.82;
