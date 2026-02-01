import {
  TrustLevel,
  DetectionResult,
  DEFAULT_TRUST_THRESHOLDS,
  DEFAULT_SIMILARITY_THRESHOLD,
} from './types.js';
import { layer1Triage, PatternMatch } from './patterns.js';
import { EmbeddingClient, findMostSimilar } from './embeddings.js';
import { getExemplarTexts, getExemplarByText } from './exemplars.js';
import { LLMJudge, JudgeResult } from './judge.js';

/**
 * Detection pipeline combining Layer 1 (pattern), Layer 2 (semantic), and Layer 3 (LLM) analysis
 */
export class Detector {
  private embeddingClient: EmbeddingClient | null = null;
  private llmJudge: LLMJudge | null = null;
  private exemplarEmbeddings: Map<string, number[]> = new Map();
  private initialized = false;
  private enableLayer2: boolean;
  private enableLayer3: boolean;
  private baseSimilarityThreshold: number;
  private trustThresholds: Record<TrustLevel, number>;

  constructor(options: {
    openaiApiKey?: string;
    enableLayer2?: boolean;
    enableLayer3?: boolean;
    layer3Model?: string;
    similarityThreshold?: number;
    trustThresholds?: Partial<Record<TrustLevel, number>>;
  }) {
    this.enableLayer2 = options.enableLayer2 ?? true;
    this.enableLayer3 = options.enableLayer3 ?? false;
    this.baseSimilarityThreshold = options.similarityThreshold ?? DEFAULT_SIMILARITY_THRESHOLD;
    this.trustThresholds = {
      ...DEFAULT_TRUST_THRESHOLDS,
      ...options.trustThresholds,
    };

    if (options.openaiApiKey) {
      if (this.enableLayer2) {
        this.embeddingClient = new EmbeddingClient(options.openaiApiKey);
      }
      if (this.enableLayer3) {
        this.llmJudge = new LLMJudge({
          apiKey: options.openaiApiKey,
          model: options.layer3Model,
        });
      }
    }
  }

  /**
   * Initialize the detector by loading exemplar embeddings
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    if (this.enableLayer2 && this.embeddingClient) {
      const exemplarTexts = getExemplarTexts();
      this.exemplarEmbeddings = await this.embeddingClient.getEmbeddings(exemplarTexts);
    }

    this.initialized = true;
  }

  /**
   * Get the similarity threshold for a given trust level
   */
  private getThreshold(trustLevel: TrustLevel): number {
    return this.trustThresholds[trustLevel];
  }

  /**
   * Run detection pipeline on text
   */
  async detect(text: string, trustLevel: TrustLevel = TrustLevel.EXTERNAL, source?: string): Promise<DetectionResult> {
    // Layer 1: Pattern matching
    const layer1Matches = layer1Triage(text);
    const layer1Triggered = layer1Matches.length > 0;

    // If Layer 2 is disabled, make decision based on Layer 1 only
    if (!this.enableLayer2 || !this.embeddingClient) {
      return this.buildResult(layer1Matches, null, null, null, layer1Triggered, trustLevel);
    }

    // Ensure initialized
    if (!this.initialized) {
      await this.initialize();
    }

    // Layer 2: Semantic similarity (only if Layer 1 triggers or trust level is low)
    const shouldRunLayer2 = layer1Triggered || trustLevel === TrustLevel.EXTERNAL;

    if (!shouldRunLayer2) {
      return this.buildResult(layer1Matches, null, null, null, false, trustLevel);
    }

    const textEmbedding = await this.embeddingClient.getEmbedding(text);
    const bestMatch = findMostSimilar(textEmbedding, this.exemplarEmbeddings);

    const threshold = this.getThreshold(trustLevel);
    const layer2Triggered = bestMatch !== null && bestMatch.similarity >= threshold;

    // Layer 3: LLM Judge for borderline cases
    let layer3Result: JudgeResult | null = null;
    if (this.enableLayer3 && this.llmJudge && !layer2Triggered) {
      const shouldEvaluate = LLMJudge.shouldEvaluate({
        layer1Triggered,
        layer2Similarity: bestMatch?.similarity ?? 0,
        layer2Threshold: threshold,
        trustLevel,
      });

      if (shouldEvaluate) {
        layer3Result = await this.llmJudge.evaluate({
          text,
          source: source ?? 'unknown',
          trustLevel,
          layer1Flags: layer1Matches.map(m => `${m.category}: ${m.matched}`),
          layer2Similarity: bestMatch?.similarity ?? 0,
          layer2Exemplar: bestMatch?.text,
        });
      }
    }

    // Determine if flagged based on all layers
    const layer3Triggered = layer3Result?.verdict === 'DANGEROUS' ||
                            layer3Result?.verdict === 'SUSPICIOUS';
    const flagged = layer1Triggered || layer2Triggered || layer3Triggered;

    return this.buildResult(layer1Matches, bestMatch, threshold, layer3Result, flagged, trustLevel);
  }

  /**
   * Build detection result object
   */
  private buildResult(
    layer1Matches: PatternMatch[],
    layer2Match: { text: string; similarity: number } | null,
    threshold: number | null,
    layer3Result: JudgeResult | null,
    flagged: boolean,
    trustLevel: TrustLevel
  ): DetectionResult {
    const layer1Triggered = layer1Matches.length > 0;
    const layer2Triggered = layer2Match !== null && threshold !== null && layer2Match.similarity >= threshold;
    const layer3Triggered = layer3Result?.verdict === 'DANGEROUS' || layer3Result?.verdict === 'SUSPICIOUS';

    // Calculate overall score
    let score = 0;
    if (layer1Triggered) {
      score += 0.5 + (layer1Matches.length * 0.1); // Base 0.5, +0.1 per pattern
    }
    if (layer2Match) {
      score = Math.max(score, layer2Match.similarity);
    }
    if (layer3Result) {
      // Layer 3 can boost or reduce score based on verdict
      if (layer3Result.verdict === 'DANGEROUS') {
        score = Math.max(score, 0.9);
      } else if (layer3Result.verdict === 'SUSPICIOUS') {
        score = Math.max(score, 0.7);
      } else if (layer3Result.verdict === 'SAFE' && layer3Result.confidence > 0.8) {
        score = Math.min(score, 0.3); // High-confidence SAFE can reduce score
      }
    }
    score = Math.min(score, 1);

    // Build reason
    const reasons: string[] = [];
    if (layer1Triggered) {
      const categories = [...new Set(layer1Matches.map(m => m.category))];
      reasons.push(`Layer 1 patterns matched: ${categories.join(', ')}`);
    }
    if (layer2Triggered && layer2Match) {
      const exemplar = getExemplarByText(layer2Match.text);
      reasons.push(
        `Layer 2 similarity ${(layer2Match.similarity * 100).toFixed(1)}% ` +
        `(threshold: ${((threshold ?? 0) * 100).toFixed(1)}%) ` +
        `matched "${exemplar?.category ?? 'unknown'}" attack pattern`
      );
    }
    if (layer3Result) {
      reasons.push(
        `Layer 3 LLM judge: ${layer3Result.verdict} (${(layer3Result.confidence * 100).toFixed(0)}% confidence)`
      );
    }
    if (!flagged) {
      reasons.push('Content passed all detection layers');
    }

    return {
      passed: !flagged,
      score,
      layer1: {
        triggered: layer1Triggered,
        patterns: layer1Matches.map(m => `${m.category}: ${m.matched}`),
      },
      layer2: {
        triggered: layer2Triggered,
        similarity: layer2Match?.similarity ?? 0,
        matchedExemplar: layer2Match?.text,
      },
      layer3: layer3Result ? {
        evaluated: true,
        verdict: layer3Result.verdict,
        confidence: layer3Result.confidence,
        reasoning: layer3Result.reasoning,
      } : undefined,
      reason: reasons.join('; '),
    };
  }

  /**
   * Quick Layer 1 only check (no API calls)
   */
  quickCheck(text: string): { suspicious: boolean; patterns: string[] } {
    const matches = layer1Triage(text);
    return {
      suspicious: matches.length > 0,
      patterns: matches.map(m => `${m.category}: ${m.matched}`),
    };
  }

  /**
   * Check if detector is ready
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Check if Layer 2 is enabled
   */
  isLayer2Enabled(): boolean {
    return this.enableLayer2 && this.embeddingClient !== null;
  }

  /**
   * Check if Layer 3 is enabled
   */
  isLayer3Enabled(): boolean {
    return this.enableLayer3 && this.llmJudge !== null;
  }
}

/**
 * Create and initialize a detector
 */
export async function createDetector(options: {
  openaiApiKey?: string;
  enableLayer2?: boolean;
  enableLayer3?: boolean;
  layer3Model?: string;
  similarityThreshold?: number;
  trustThresholds?: Partial<Record<TrustLevel, number>>;
}): Promise<Detector> {
  const detector = new Detector(options);
  await detector.initialize();
  return detector;
}
