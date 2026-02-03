import { v4 as uuidv4 } from 'uuid';
import { TrustLevel, MemoryProvenance, DetectionResult } from '../core/types.js';
import { Detector } from '../core/detector.js';
import { Notifier } from '../core/notifications.js';
import { BaselineTracker, containsInstruction } from '../core/baseline.js';
import { ProvenanceStore } from '../storage/provenance.js';
import { QuarantineStore } from '../storage/quarantine.js';

/**
 * Result of tagging a memory
 */
export interface TagResult {
  /** Whether the content was allowed (not quarantined) */
  allowed: boolean;
  /** Provenance metadata */
  provenance: MemoryProvenance;
  /** Detection result from analysis */
  detection: DetectionResult;
  /** Quarantine ID if content was quarantined */
  quarantineId?: string;
  /** Whether agent self-evaluation is needed (borderline case) */
  needsAgentEvaluation?: boolean;
}

/**
 * Options for tagging content
 */
export interface TagOptions {
  /** The text content to tag */
  text: string;
  /** Source identifier (e.g., 'user', 'web_scrape', 'tool:github') */
  source: string;
  /** Trust level for the source */
  trustLevel: TrustLevel;
  /** Session ID for grouping related memories */
  sessionId?: string;
  /** Context that triggered this memory creation */
  triggerContext?: string;
}

/**
 * Ingress tagger that analyzes and tags incoming content
 * with provenance metadata and detection results
 */
export class IngressTagger {
  private detector: Detector;
  private provenanceStore: ProvenanceStore;
  private quarantineStore: QuarantineStore;
  private notifier: Notifier | null;
  private baselineTracker: BaselineTracker | null;
  private currentSessionId: string;

  constructor(options: {
    detector: Detector;
    provenanceStore: ProvenanceStore;
    quarantineStore: QuarantineStore;
    notifier?: Notifier;
    baselineTracker?: BaselineTracker;
    sessionId?: string;
  }) {
    this.detector = options.detector;
    this.provenanceStore = options.provenanceStore;
    this.quarantineStore = options.quarantineStore;
    this.notifier = options.notifier ?? null;
    this.baselineTracker = options.baselineTracker ?? null;
    this.currentSessionId = options.sessionId ?? uuidv4();
  }

  /**
   * Tag incoming content with provenance and run detection
   */
  async tag(options: TagOptions): Promise<TagResult> {
    const sessionId = options.sessionId ?? this.currentSessionId;
    const hasInstruction = containsInstruction(options.text);

    // Run detection pipeline (pass source for Layer 3 context)
    let detection = await this.detector.detect(options.text, options.trustLevel, options.source);

    // Run anomaly detection if baseline tracker is available
    if (this.baselineTracker) {
      const anomalyResult = await this.baselineTracker.computeAnomaly({
        text: options.text,
        source: options.source,
        trustLevel: options.trustLevel,
        containsInstruction: hasInstruction,
      });

      // Add anomaly info to detection result
      detection = {
        ...detection,
        anomaly: {
          score: anomalyResult.score,
          signals: anomalyResult.signals,
          inLearningPeriod: anomalyResult.inLearningPeriod,
        },
      };

      // If anomaly score is high, flag content
      if (anomalyResult.score >= 0.7 && !anomalyResult.inLearningPeriod) {
        detection = {
          ...detection,
          passed: false,
          score: Math.max(detection.score, anomalyResult.score),
          reason: detection.reason + `; Anomaly: ${anomalyResult.signals.map(s => s.description).join(', ')}`,
        };
      }

      // Record memory in baseline (for learning)
      await this.baselineTracker.recordMemory({
        text: options.text,
        source: options.source,
        trustLevel: options.trustLevel,
        containsInstruction: hasInstruction,
      });
    }

    // Create provenance record
    const provenance = this.provenanceStore.create({
      source: options.source,
      trustLevel: options.trustLevel,
      sessionId,
      triggerContext: options.triggerContext,
      detectionScore: detection.score,
      flags: detection.layer1.patterns,
    });

    // If detection failed, quarantine the content
    if (!detection.passed) {
      const quarantined = this.quarantineStore.add({
        text: options.text,
        source: options.source,
        trustLevel: options.trustLevel,
        layer1Flags: detection.layer1.patterns,
        layer2Similarity: detection.layer2.similarity,
        layer2Exemplar: detection.layer2.matchedExemplar,
        layer3Verdict: detection.layer3?.verdict,
        layer3Reasoning: detection.layer3?.reasoning,
      });

      // Send notification
      if (this.notifier) {
        this.notifier.notify(quarantined, detection.reason).catch((err) => {
          console.error('[memfw] Notification error:', err);
        });
      }

      return {
        allowed: false,
        provenance,
        detection,
        quarantineId: quarantined.id,
      };
    }

    return {
      allowed: true,
      provenance,
      detection,
      needsAgentEvaluation: !!detection.agentJudgeRequest,
    };
  }

  /**
   * Quick tag without full detection (Layer 1 only)
   * Useful for high-volume, trusted sources
   */
  quickTag(options: TagOptions): {
    provenance: MemoryProvenance;
    suspicious: boolean;
    patterns: string[];
  } {
    const sessionId = options.sessionId ?? this.currentSessionId;

    // Run quick check (Layer 1 only)
    const quickResult = this.detector.quickCheck(options.text);

    // Create provenance record
    const provenance = this.provenanceStore.create({
      source: options.source,
      trustLevel: options.trustLevel,
      sessionId,
      triggerContext: options.triggerContext,
      detectionScore: quickResult.suspicious ? 0.5 : 0,
      flags: quickResult.patterns,
    });

    return {
      provenance,
      suspicious: quickResult.suspicious,
      patterns: quickResult.patterns,
    };
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.currentSessionId;
  }

  /**
   * Start a new session
   */
  newSession(): string {
    this.currentSessionId = uuidv4();
    return this.currentSessionId;
  }

  /**
   * Classify trust level from source identifier
   */
  static classifyTrust(source: string): TrustLevel {
    const sourceLower = source.toLowerCase();

    // User input
    if (sourceLower === 'user' || sourceLower.startsWith('user:')) {
      return TrustLevel.USER;
    }

    // Verified tools
    const verifiedTools = ['github', 'gitlab', 'jira', 'slack', 'notion'];
    for (const tool of verifiedTools) {
      if (sourceLower === `tool:${tool}` || sourceLower.includes(tool)) {
        return TrustLevel.TOOL_VERIFIED;
      }
    }

    // Unverified tools
    if (sourceLower.startsWith('tool:')) {
      return TrustLevel.TOOL_UNVERIFIED;
    }

    // Agent-generated
    if (sourceLower === 'agent' || sourceLower.startsWith('agent:')) {
      return TrustLevel.AGENT;
    }

    // External sources
    return TrustLevel.EXTERNAL;
  }
}
