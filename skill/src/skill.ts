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
} from 'memfw';
import type { SkillContext, MemoryContext } from './index.js';

/**
 * Skill configuration
 */
export interface SkillConfig {
  detection: {
    enabled: boolean;
    useLlmJudge: boolean;
    sensitivity: 'low' | 'medium' | 'high';
    embeddingProvider: 'local' | 'openai';
  };
  trust: Record<string, TrustLevel>;
  notifications: {
    onQuarantine: boolean;
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

    this.detector = new Detector({
      openaiApiKey,
      enableLayer2,
      similarityThreshold: this.getSensitivityThreshold(),
    });

    if (enableLayer2) {
      await this.detector.initialize();
    }

    // Initialize tagger
    this.tagger = new IngressTagger({
      detector: this.detector,
      provenanceStore: this.provenanceStore,
      quarantineStore: this.quarantineStore,
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
        useLlmJudge: false,
        sensitivity: 'medium',
        embeddingProvider: 'openai',
      },
      trust: {},
      notifications: {
        onQuarantine: true,
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

    return result;
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
      } else if (parts[1] === 'useLlmJudge') {
        this.config.detection.useLlmJudge = value === true || value === 'true';
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
