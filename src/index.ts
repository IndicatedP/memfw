/**
 * memfw - Memory Firewall
 *
 * A security layer for AI agents with persistent memory.
 * Protects against memory poisoning attacks through provenance
 * tracking, pattern detection, and semantic analysis.
 */

// Core types and configuration
export {
  TrustLevel,
  MemoryProvenance,
  DetectionResult,
  QuarantineStatus,
  QuarantinedMemory,
  Memory,
  MemfwConfig,
  DEFAULT_TRUST_THRESHOLDS,
  DEFAULT_SIMILARITY_THRESHOLD,
} from './core/types.js';

// Detection pipeline
export { Detector, createDetector } from './core/detector.js';
export { LLMJudge, JudgeResult, JudgeVerdict, JudgeContext, createJudge } from './core/judge.js';
export {
  Notifier,
  NotifierConfig,
  NotificationChannel,
  NotificationHandler,
  QuarantineNotification,
  WebhookConfig,
  createNotifier,
} from './core/notifications.js';
export {
  PatternMatch,
  INSPECTION_TRIGGERS,
  ALL_PATTERNS,
  layer1Triage,
  hasLayer1Match,
} from './core/patterns.js';
export { EmbeddingClient } from './core/embeddings.js';
export { ATTACK_EXEMPLARS } from './core/exemplars.js';

// Storage
export { ProvenanceStore } from './storage/provenance.js';
export { QuarantineStore } from './storage/quarantine.js';
export { MemoryStore } from './storage/memory.js';

// Ingress tagging
export { IngressTagger, TagResult, TagOptions } from './tagger/index.js';
