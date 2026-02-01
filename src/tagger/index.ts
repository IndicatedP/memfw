import { v4 as uuidv4 } from 'uuid';
import { TrustLevel, MemoryProvenance, DetectionResult } from '../core/types.js';
import { Detector } from '../core/detector.js';
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
  private currentSessionId: string;

  constructor(options: {
    detector: Detector;
    provenanceStore: ProvenanceStore;
    quarantineStore: QuarantineStore;
    sessionId?: string;
  }) {
    this.detector = options.detector;
    this.provenanceStore = options.provenanceStore;
    this.quarantineStore = options.quarantineStore;
    this.currentSessionId = options.sessionId ?? uuidv4();
  }

  /**
   * Tag incoming content with provenance and run detection
   */
  async tag(options: TagOptions): Promise<TagResult> {
    const sessionId = options.sessionId ?? this.currentSessionId;

    // Run detection pipeline
    const detection = await this.detector.detect(options.text, options.trustLevel);

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
      });

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
