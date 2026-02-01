/**
 * memfw - Memory Firewall
 *
 * A security layer for AI agents with persistent memory.
 * Protects against memory poisoning attacks through provenance
 * tracking, pattern detection, and semantic analysis.
 */

// Core types and configuration
export { TrustLevel, DEFAULT_TRUST_THRESHOLDS, DEFAULT_SIMILARITY_THRESHOLD } from './core/types.js';
export type {
  MemoryProvenance,
  DetectionResult,
  QuarantineStatus,
  QuarantinedMemory,
  Memory,
  MemfwConfig,
} from './core/types.js';

// Detection pipeline
export { Detector, createDetector } from './core/detector.js';
export { LLMJudge, createJudge } from './core/judge.js';
export type { JudgeResult, JudgeVerdict, JudgeContext } from './core/judge.js';
export { Notifier, createNotifier } from './core/notifications.js';
export type {
  NotifierConfig,
  NotificationChannel,
  NotificationHandler,
  QuarantineNotification,
  WebhookConfig,
} from './core/notifications.js';
export { BaselineTracker, containsInstruction, createBaselineTracker } from './core/baseline.js';
export type { BaselineConfig, BaselineStats, AnomalyResult, AnomalySignal } from './core/baseline.js';
export { INSPECTION_TRIGGERS, ALL_PATTERNS, layer1Triage, hasLayer1Match } from './core/patterns.js';
export type { PatternMatch } from './core/patterns.js';
export { EmbeddingClient } from './core/embeddings.js';
export { ATTACK_EXEMPLARS } from './core/exemplars.js';

// Storage
export { ProvenanceStore } from './storage/provenance.js';
export { QuarantineStore } from './storage/quarantine.js';
export { MemoryStore } from './storage/memory.js';

// Ingress tagging
export { IngressTagger } from './tagger/index.js';
export type { TagResult, TagOptions } from './tagger/index.js';
