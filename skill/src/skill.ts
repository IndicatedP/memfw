/**
 * memfw Skill Core
 *
 * Main skill class that wraps the memfw-core library
 * for use within OpenClaw.
 */

import path from 'path';
import fs from 'fs';
import {
  Detector,
  ProvenanceStore,
  QuarantineStore,
  IngressTagger,
  TrustLevel,
  DetectionResult,
  QuarantinedMemory,
  MemoryProvenance,
  Notifier,
  createNotifier,
} from 'memfw';
import type { SkillContext, MemoryContext } from './index.js';

/**
 * Skill configuration
 */
export interface SkillConfig {
  detection: {
    enabled: boolean;
    enableLayer3: boolean;
    useAgentJudge: boolean; // Use agent's own LLM for Layer 3 evaluation
    layer3Model: string;
    sensitivity: 'low' | 'medium' | 'high';
    embeddingProvider: 'local' | 'openai';
  };
  trust: Record<string, TrustLevel>;
  notifications: {
    onQuarantine: boolean;
    minRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
    channel: string | null;
  };
  storage: {
    dataDir: string;
  };
}

/**
 * Tag result from the ingress tagger
 */
export interface TagResult {
  allowed: boolean;
  provenance: MemoryProvenance;
  detection: DetectionResult;
  quarantineId?: string;
  /** If present, agent should self-evaluate using this prompt */
  agentJudgePrompt?: string;
}

/**
 * Result from agent self-evaluation
 */
export interface AgentJudgeResponse {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  confidence: number;
  reasoning: string;
}

/**
 * Main skill class
 */
export class MemfwSkill {
  private detector: Detector | null = null;
  private provenanceStore: ProvenanceStore | null = null;
  private quarantineStore: QuarantineStore | null = null;
  private tagger: IngressTagger | null = null;
  private config: SkillConfig | null = null;
  private skillDir: string = '';
  private initialized = false;

  /**
   * Initialize the skill
   */
  async initialize(context: SkillContext): Promise<void> {
    if (this.initialized) return;

    this.skillDir = context.skillDir;

    // Load configuration
    this.config = this.loadConfig();

    // Set up data directory
    const dataDir = path.resolve(this.skillDir, this.config.storage.dataDir);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Initialize stores
    this.provenanceStore = new ProvenanceStore(path.join(dataDir, 'provenance.db'));
    this.quarantineStore = new QuarantineStore(path.join(dataDir, 'quarantine.db'));

    // Initialize detector
    const openaiApiKey = process.env.OPENAI_API_KEY;
    const enableLayer2 = this.config.detection.enabled && !!openaiApiKey;
    // Only use external LLM judge if explicitly enabled AND not using agent judge
    const enableLayer3 = this.config.detection.enableLayer3 &&
                         !this.config.detection.useAgentJudge &&
                         !!openaiApiKey;

    this.detector = new Detector({
      openaiApiKey,
      enableLayer2,
      enableLayer3,
      useAgentJudge: this.config.detection.useAgentJudge,
      layer3Model: this.config.detection.layer3Model,
      similarityThreshold: this.getSensitivityThreshold(),
    });

    if (enableLayer2) {
      await this.detector.initialize();
    }

    // Initialize notifier
    const notifier = this.config.notifications.onQuarantine
      ? createNotifier({
          enabled: true,
          channels: ['console'],
          minRiskLevel: this.config.notifications.minRiskLevel,
        })
      : undefined;

    // Initialize tagger
    this.tagger = new IngressTagger({
      detector: this.detector,
      provenanceStore: this.provenanceStore,
      quarantineStore: this.quarantineStore,
      notifier,
    });

    this.initialized = true;
  }

  /**
   * Load configuration from file
   */
  private loadConfig(): SkillConfig {
    const configPath = path.join(this.skillDir, 'config', 'policy.json');

    const defaultConfig: SkillConfig = {
      detection: {
        enabled: true,
        enableLayer3: false,
        useAgentJudge: true, // Default to agent-as-judge (zero external cost)
        layer3Model: 'gpt-4o-mini',
        sensitivity: 'medium',
        embeddingProvider: 'openai',
      },
      trust: {},
      notifications: {
        onQuarantine: true,
        minRiskLevel: 'LOW',
        channel: null,
      },
      storage: {
        dataDir: './data',
      },
    };

    if (fs.existsSync(configPath)) {
      try {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        return { ...defaultConfig, ...fileConfig };
      } catch {
        return defaultConfig;
      }
    }

    return defaultConfig;
  }

  /**
   * Save configuration to file
   */
  saveConfig(): void {
    if (!this.config) return;

    const configPath = path.join(this.skillDir, 'config', 'policy.json');
    const configDir = path.dirname(configPath);

    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
  }

  /**
   * Get sensitivity threshold based on config
   */
  private getSensitivityThreshold(): number {
    const thresholds = {
      low: 0.88,
      medium: 0.82,
      high: 0.75,
    };
    return thresholds[this.config?.detection.sensitivity ?? 'medium'];
  }

  /**
   * Analyze and tag incoming content
   */
  async analyzeContent(content: string, context: MemoryContext): Promise<TagResult> {
    if (!this.tagger || !this.config) {
      throw new Error('Skill not initialized');
    }

    // Determine trust level
    const trustLevel = this.classifySource(context.source);

    // Run detection
    const result = await this.tagger.tag({
      text: content,
      source: context.source,
      trustLevel,
      sessionId: context.sessionId,
      triggerContext: context.triggerContext,
    });

    // If agent-as-judge is needed, include the prompt
    if (result.detection.agentJudgeRequest) {
      return {
        ...result,
        agentJudgePrompt: result.detection.agentJudgeRequest.evaluationPrompt,
      };
    }

    return result;
  }

  /**
   * Apply agent's self-evaluation verdict to a detection result
   *
   * This should be called after the agent processes the agentJudgePrompt
   * and returns its verdict.
   *
   * Safeguard: Layer 3 cannot override strong Layer 1+2 signals
   * If Layer 2 similarity > threshold + 0.1, SAFE verdict is ignored
   */
  applyAgentJudgeVerdict(
    result: TagResult,
    agentResponse: AgentJudgeResponse
  ): TagResult {
    const detection = result.detection;

    // Check if we should apply the verdict (safeguard against manipulation)
    if (detection.agentJudgeRequest) {
      const { layer2Similarity, layer2Threshold } = detection.agentJudgeRequest.context;
      const strongSignalThreshold = layer2Threshold + 0.1;

      // If strong detection signal and agent says SAFE, ignore the verdict
      if (layer2Similarity >= strongSignalThreshold && agentResponse.verdict === 'SAFE') {
        return {
          ...result,
          detection: {
            ...detection,
            layer3: {
              evaluated: true,
              verdict: agentResponse.verdict,
              confidence: agentResponse.confidence,
              reasoning: `[IGNORED - Strong L2 signal] ${agentResponse.reasoning}`,
            },
            reason: detection.reason + '; Layer 3 SAFE verdict ignored due to strong Layer 2 signal',
          },
        };
      }
    }

    // Apply the verdict
    const layer3Triggered = agentResponse.verdict === 'DANGEROUS' ||
                            agentResponse.verdict === 'SUSPICIOUS';

    // Recalculate if content should be allowed
    const newPassed = detection.passed && !layer3Triggered;

    // Recalculate score based on Layer 3
    let newScore = detection.score;
    if (agentResponse.verdict === 'DANGEROUS') {
      newScore = Math.max(newScore, 0.9);
    } else if (agentResponse.verdict === 'SUSPICIOUS') {
      newScore = Math.max(newScore, 0.7);
    } else if (agentResponse.verdict === 'SAFE' && agentResponse.confidence > 0.8) {
      newScore = Math.min(newScore, 0.3);
    }

    return {
      ...result,
      allowed: newPassed,
      detection: {
        ...detection,
        passed: newPassed,
        score: newScore,
        layer3: {
          evaluated: true,
          verdict: agentResponse.verdict,
          confidence: agentResponse.confidence,
          reasoning: agentResponse.reasoning,
        },
        reason: detection.reason +
          `; Layer 3 agent judge: ${agentResponse.verdict} (${(agentResponse.confidence * 100).toFixed(0)}% confidence)`,
        agentJudgeRequest: undefined, // Clear the request
      },
    };
  }

  /**
   * Parse agent's response text into structured verdict
   */
  parseAgentResponse(responseText: string): AgentJudgeResponse {
    const lines = responseText.trim().split('\n');

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' = 'SUSPICIOUS';
    let confidence = 0.5;
    let reasoning = 'Unable to parse response.';

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('VERDICT:')) {
        const v = trimmed.replace('VERDICT:', '').trim().toUpperCase();
        if (v === 'SAFE' || v === 'SUSPICIOUS' || v === 'DANGEROUS') {
          verdict = v;
        }
      } else if (trimmed.startsWith('CONFIDENCE:')) {
        const c = parseFloat(trimmed.replace('CONFIDENCE:', '').trim());
        if (!isNaN(c) && c >= 0 && c <= 1) {
          confidence = c;
        }
      } else if (trimmed.startsWith('REASONING:')) {
        reasoning = trimmed.replace('REASONING:', '').trim();
      }
    }

    // Try to extract multi-line reasoning
    if (reasoning === 'Unable to parse response.') {
      const reasoningMatch = responseText.match(/REASONING:\s*(.+)/s);
      if (reasoningMatch) {
        reasoning = reasoningMatch[1].trim();
      }
    }

    return { verdict, confidence, reasoning };
  }

  /**
   * Classify source to trust level
   */
  classifySource(source: string): TrustLevel {
    // Check config overrides first
    if (this.config?.trust) {
      const sourceLower = source.toLowerCase();
      for (const [pattern, level] of Object.entries(this.config.trust)) {
        if (sourceLower.includes(pattern.toLowerCase())) {
          return level as TrustLevel;
        }
      }
    }

    // Fall back to default classification
    return IngressTagger.classifyTrust(source);
  }

  /**
   * Get status summary
   */
  getStatus(): {
    enabled: boolean;
    layer2Enabled: boolean;
    layer3Enabled: boolean;
    totalMemories: number;
    quarantineCounts: Record<string, number>;
    trustCounts: Record<string, number>;
  } {
    if (!this.provenanceStore || !this.quarantineStore || !this.detector) {
      throw new Error('Skill not initialized');
    }

    return {
      enabled: this.config?.detection.enabled ?? false,
      layer2Enabled: this.detector.isLayer2Enabled(),
      layer3Enabled: this.detector.isLayer3Enabled(),
      totalMemories: this.provenanceStore.getTotal(),
      quarantineCounts: this.quarantineStore.getCounts(),
      trustCounts: this.provenanceStore.getCountsByTrust(),
    };
  }

  /**
   * Get quarantined memories
   */
  getQuarantined(options?: {
    status?: 'pending' | 'approved' | 'rejected';
    limit?: number;
  }): QuarantinedMemory[] {
    if (!this.quarantineStore) {
      throw new Error('Skill not initialized');
    }

    return this.quarantineStore.list(options);
  }

  /**
   * Get a specific quarantined memory
   */
  getQuarantinedById(id: string): QuarantinedMemory | null {
    if (!this.quarantineStore) {
      throw new Error('Skill not initialized');
    }

    // Support partial ID matching
    const all = this.quarantineStore.list();
    return all.find((m) => m.id.startsWith(id)) ?? null;
  }

  /**
   * Approve a quarantined memory
   */
  approveQuarantined(id: string, reviewedBy?: string): boolean {
    if (!this.quarantineStore) {
      throw new Error('Skill not initialized');
    }

    const memory = this.getQuarantinedById(id);
    if (!memory) return false;

    return this.quarantineStore.approve(memory.id, reviewedBy);
  }

  /**
   * Reject a quarantined memory
   */
  rejectQuarantined(id: string, reviewedBy?: string): boolean {
    if (!this.quarantineStore) {
      throw new Error('Skill not initialized');
    }

    const memory = this.getQuarantinedById(id);
    if (!memory) return false;

    return this.quarantineStore.reject(memory.id, reviewedBy);
  }

  /**
   * Get audit log
   */
  getAuditLog(options?: {
    days?: number;
    source?: string;
    limit?: number;
  }): MemoryProvenance[] {
    if (!this.provenanceStore) {
      throw new Error('Skill not initialized');
    }

    const entries = this.provenanceStore.list({
      source: options?.source,
      limit: options?.limit ?? 100,
    });

    // Filter by date if specified
    if (options?.days) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - options.days);
      return entries.filter((e) => e.timestamp >= cutoff);
    }

    return entries;
  }

  /**
   * Get current configuration
   */
  getConfig(): SkillConfig | null {
    return this.config;
  }

  /**
   * Update configuration
   */
  setConfig(key: string, value: unknown): boolean {
    if (!this.config) return false;

    const parts = key.split('.');

    if (parts[0] === 'detection') {
      if (parts[1] === 'enabled') {
        this.config.detection.enabled = value === true || value === 'true';
      } else if (parts[1] === 'sensitivity') {
        if (['low', 'medium', 'high'].includes(value as string)) {
          this.config.detection.sensitivity = value as 'low' | 'medium' | 'high';
        } else {
          return false;
        }
      } else if (parts[1] === 'enableLayer3') {
        this.config.detection.enableLayer3 = value === true || value === 'true';
      } else if (parts[1] === 'useAgentJudge') {
        this.config.detection.useAgentJudge = value === true || value === 'true';
      } else {
        return false;
      }
    } else if (parts[0] === 'notifications') {
      if (parts[1] === 'onQuarantine') {
        this.config.notifications.onQuarantine = value === true || value === 'true';
      } else {
        return false;
      }
    } else if (parts[0] === 'trust' && parts[1]) {
      const validLevels = Object.values(TrustLevel);
      if (validLevels.includes(value as TrustLevel)) {
        this.config.trust[parts[1]] = value as TrustLevel;
      } else {
        return false;
      }
    } else {
      return false;
    }

    this.saveConfig();
    return true;
  }

  /**
   * Check if initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    this.provenanceStore?.close();
    this.quarantineStore?.close();
    this.initialized = false;
  }
}
