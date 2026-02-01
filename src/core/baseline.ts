/**
 * Behavioral Baseline
 *
 * Tracks normal patterns for a user/agent to detect anomalies.
 * Anomalies can indicate novel attack vectors that don't match
 * known patterns but deviate from typical behavior.
 */

import Database from 'better-sqlite3';
import { TrustLevel } from './types.js';
import { EmbeddingClient, cosineSimilarity } from './embeddings.js';

/**
 * Rolling average calculator
 */
class RollingAverage {
  private values: number[] = [];
  private maxSize: number;

  constructor(maxSize: number = 100) {
    this.maxSize = maxSize;
  }

  add(value: number): void {
    this.values.push(value);
    if (this.values.length > this.maxSize) {
      this.values.shift();
    }
  }

  get average(): number {
    if (this.values.length === 0) return 0;
    return this.values.reduce((a, b) => a + b, 0) / this.values.length;
  }

  get count(): number {
    return this.values.length;
  }

  get stdDev(): number {
    if (this.values.length < 2) return 0;
    const avg = this.average;
    const squareDiffs = this.values.map(v => Math.pow(v - avg, 2));
    return Math.sqrt(squareDiffs.reduce((a, b) => a + b, 0) / this.values.length);
  }

  toJSON(): { values: number[]; maxSize: number } {
    return { values: this.values, maxSize: this.maxSize };
  }

  static fromJSON(data: { values: number[]; maxSize: number }): RollingAverage {
    const ra = new RollingAverage(data.maxSize);
    ra.values = data.values;
    return ra;
  }
}

/**
 * Baseline statistics
 */
export interface BaselineStats {
  /** Total memories processed */
  totalMemories: number;
  /** Memories per day (rolling average) */
  memoriesPerDay: number;
  /** Ratio of memories containing instructions */
  instructionRatio: number;
  /** Most common domains seen */
  topDomains: Array<{ domain: string; count: number }>;
  /** Most common sources */
  topSources: Array<{ source: string; count: number }>;
  /** Learning period status */
  learningComplete: boolean;
  /** Days of data collected */
  daysCollected: number;
  /** Baseline start date */
  startDate: Date;
}

/**
 * Anomaly detection result
 */
export interface AnomalyResult {
  /** Overall anomaly score (0-1, higher = more anomalous) */
  score: number;
  /** Individual anomaly signals */
  signals: AnomalySignal[];
  /** Whether this is during learning period */
  inLearningPeriod: boolean;
}

/**
 * Individual anomaly signal
 */
export interface AnomalySignal {
  type: 'new_domain' | 'new_source' | 'novel_topic' | 'unusual_instruction' | 'frequency_spike';
  description: string;
  severity: number; // 0-1
}

/**
 * Baseline configuration
 */
export interface BaselineConfig {
  /** Minimum days before learning is complete (default: 7) */
  learningPeriodDays: number;
  /** Minimum memories before learning is complete (default: 50) */
  minMemoriesForLearning: number;
  /** Maximum topic embeddings to store (default: 500) */
  maxTopicEmbeddings: number;
  /** Novelty threshold for topic detection (default: 0.7) */
  topicNoveltyThreshold: number;
  /** Enable topic embedding storage (requires API calls) */
  enableTopicTracking: boolean;
}

const DEFAULT_CONFIG: BaselineConfig = {
  learningPeriodDays: 7,
  minMemoriesForLearning: 50,
  maxTopicEmbeddings: 500,
  topicNoveltyThreshold: 0.7,
  enableTopicTracking: false,
};

/**
 * Behavioral baseline tracker
 */
export class BaselineTracker {
  private db: Database.Database;
  private config: BaselineConfig;
  private embeddingClient: EmbeddingClient | null = null;

  // In-memory statistics
  private memoriesPerDay: RollingAverage;
  private instructionRatio: RollingAverage;
  private domainCounts: Map<string, number> = new Map();
  private sourceCounts: Map<string, number> = new Map();
  private topicEmbeddings: Array<{ text: string; embedding: number[] }> = [];

  // Metadata
  private startDate: Date = new Date();
  private lastUpdateDate: Date = new Date();
  private totalMemories: number = 0;
  private dailyMemoryCount: number = 0;

  constructor(dbPath: string, config?: Partial<BaselineConfig>, embeddingClient?: EmbeddingClient) {
    this.db = new Database(dbPath);
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.embeddingClient = embeddingClient ?? null;

    this.memoriesPerDay = new RollingAverage(30); // 30-day rolling window
    this.instructionRatio = new RollingAverage(100);

    this.initSchema();
    this.loadState();
  }

  /**
   * Initialize database schema
   */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS baseline_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS baseline_domains (
        domain TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS baseline_sources (
        source TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS baseline_topics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        embedding TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_topics_created ON baseline_topics(created_at);
    `);
  }

  /**
   * Load state from database
   */
  private loadState(): void {
    const getState = this.db.prepare('SELECT value FROM baseline_state WHERE key = ?');

    // Load rolling averages
    const memoriesPerDayData = getState.get('memoriesPerDay') as { value: string } | undefined;
    if (memoriesPerDayData) {
      this.memoriesPerDay = RollingAverage.fromJSON(JSON.parse(memoriesPerDayData.value));
    }

    const instructionRatioData = getState.get('instructionRatio') as { value: string } | undefined;
    if (instructionRatioData) {
      this.instructionRatio = RollingAverage.fromJSON(JSON.parse(instructionRatioData.value));
    }

    // Load metadata
    const startDateData = getState.get('startDate') as { value: string } | undefined;
    if (startDateData) {
      this.startDate = new Date(startDateData.value);
    }

    const lastUpdateData = getState.get('lastUpdateDate') as { value: string } | undefined;
    if (lastUpdateData) {
      this.lastUpdateDate = new Date(lastUpdateData.value);
    }

    const totalData = getState.get('totalMemories') as { value: string } | undefined;
    if (totalData) {
      this.totalMemories = parseInt(totalData.value, 10);
    }

    const dailyData = getState.get('dailyMemoryCount') as { value: string } | undefined;
    if (dailyData) {
      this.dailyMemoryCount = parseInt(dailyData.value, 10);
    }

    // Load domain counts
    const domains = this.db.prepare('SELECT domain, count FROM baseline_domains').all() as Array<{ domain: string; count: number }>;
    for (const { domain, count } of domains) {
      this.domainCounts.set(domain, count);
    }

    // Load source counts
    const sources = this.db.prepare('SELECT source, count FROM baseline_sources').all() as Array<{ source: string; count: number }>;
    for (const { source, count } of sources) {
      this.sourceCounts.set(source, count);
    }

    // Load topic embeddings (limited)
    if (this.config.enableTopicTracking) {
      const topics = this.db.prepare(
        'SELECT text, embedding FROM baseline_topics ORDER BY created_at DESC LIMIT ?'
      ).all(this.config.maxTopicEmbeddings) as Array<{ text: string; embedding: string }>;

      this.topicEmbeddings = topics.map(t => ({
        text: t.text,
        embedding: JSON.parse(t.embedding),
      }));
    }
  }

  /**
   * Save state to database
   */
  private saveState(): void {
    const upsert = this.db.prepare(`
      INSERT OR REPLACE INTO baseline_state (key, value) VALUES (?, ?)
    `);

    upsert.run('memoriesPerDay', JSON.stringify(this.memoriesPerDay.toJSON()));
    upsert.run('instructionRatio', JSON.stringify(this.instructionRatio.toJSON()));
    upsert.run('startDate', this.startDate.toISOString());
    upsert.run('lastUpdateDate', this.lastUpdateDate.toISOString());
    upsert.run('totalMemories', this.totalMemories.toString());
    upsert.run('dailyMemoryCount', this.dailyMemoryCount.toString());
  }

  /**
   * Record a new memory for baseline tracking
   */
  async recordMemory(options: {
    text: string;
    source: string;
    trustLevel: TrustLevel;
    containsInstruction: boolean;
  }): Promise<void> {
    const now = new Date();

    // Check if we've moved to a new day
    if (!this.isSameDay(this.lastUpdateDate, now)) {
      // Record previous day's count
      if (this.dailyMemoryCount > 0) {
        this.memoriesPerDay.add(this.dailyMemoryCount);
      }
      this.dailyMemoryCount = 0;
    }

    this.dailyMemoryCount++;
    this.totalMemories++;
    this.lastUpdateDate = now;

    // Track instruction ratio
    this.instructionRatio.add(options.containsInstruction ? 1 : 0);

    // Track source
    const currentSourceCount = this.sourceCounts.get(options.source) ?? 0;
    this.sourceCounts.set(options.source, currentSourceCount + 1);
    this.db.prepare(`
      INSERT OR REPLACE INTO baseline_sources (source, count) VALUES (?, ?)
    `).run(options.source, currentSourceCount + 1);

    // Extract and track domains
    const domains = this.extractDomains(options.text);
    for (const domain of domains) {
      const currentCount = this.domainCounts.get(domain) ?? 0;
      this.domainCounts.set(domain, currentCount + 1);
      this.db.prepare(`
        INSERT OR REPLACE INTO baseline_domains (domain, count) VALUES (?, ?)
      `).run(domain, currentCount + 1);
    }

    // Track topic embedding (if enabled and client available)
    if (this.config.enableTopicTracking && this.embeddingClient) {
      try {
        const embedding = await this.embeddingClient.getEmbedding(options.text);
        this.topicEmbeddings.unshift({ text: options.text.substring(0, 200), embedding });

        // Trim to max size
        if (this.topicEmbeddings.length > this.config.maxTopicEmbeddings) {
          this.topicEmbeddings = this.topicEmbeddings.slice(0, this.config.maxTopicEmbeddings);
        }

        // Store in database
        this.db.prepare(`
          INSERT INTO baseline_topics (text, embedding, created_at) VALUES (?, ?, ?)
        `).run(options.text.substring(0, 200), JSON.stringify(embedding), now.toISOString());

        // Clean up old topics
        this.db.prepare(`
          DELETE FROM baseline_topics WHERE id NOT IN (
            SELECT id FROM baseline_topics ORDER BY created_at DESC LIMIT ?
          )
        `).run(this.config.maxTopicEmbeddings);
      } catch (error) {
        console.error('[memfw] Failed to track topic embedding:', error);
      }
    }

    this.saveState();
  }

  /**
   * Compute anomaly score for a memory
   */
  async computeAnomaly(options: {
    text: string;
    source: string;
    trustLevel: TrustLevel;
    containsInstruction: boolean;
  }): Promise<AnomalyResult> {
    const signals: AnomalySignal[] = [];
    const inLearningPeriod = !this.isLearningComplete();

    // During learning period, don't flag anomalies
    if (inLearningPeriod) {
      return { score: 0, signals: [], inLearningPeriod: true };
    }

    // Check for new domains
    const domains = this.extractDomains(options.text);
    for (const domain of domains) {
      if (!this.domainCounts.has(domain)) {
        signals.push({
          type: 'new_domain',
          description: `New domain: ${domain}`,
          severity: 0.6,
        });
      }
    }

    // Check for new source
    if (!this.sourceCounts.has(options.source)) {
      signals.push({
        type: 'new_source',
        description: `New source: ${options.source}`,
        severity: 0.4,
      });
    }

    // Check for unusual instruction pattern
    const avgInstructionRatio = this.instructionRatio.average;
    if (options.containsInstruction && avgInstructionRatio < 0.1) {
      signals.push({
        type: 'unusual_instruction',
        description: `Instructions are rare (${(avgInstructionRatio * 100).toFixed(1)}% baseline)`,
        severity: 0.5,
      });
    }

    // Check for topic novelty (if enabled)
    if (this.config.enableTopicTracking && this.embeddingClient && this.topicEmbeddings.length > 10) {
      try {
        const embedding = await this.embeddingClient.getEmbedding(options.text);
        const noveltyScore = this.computeTopicNovelty(embedding);

        if (noveltyScore > this.config.topicNoveltyThreshold) {
          signals.push({
            type: 'novel_topic',
            description: `Unusual topic (${(noveltyScore * 100).toFixed(0)}% novel)`,
            severity: noveltyScore * 0.7,
          });
        }
      } catch (error) {
        // Skip topic novelty on error
      }
    }

    // Check for frequency spike
    const avgDaily = this.memoriesPerDay.average;
    const stdDev = this.memoriesPerDay.stdDev;
    if (avgDaily > 0 && this.dailyMemoryCount > avgDaily + 2 * stdDev) {
      signals.push({
        type: 'frequency_spike',
        description: `High activity (${this.dailyMemoryCount} today vs ${avgDaily.toFixed(1)} avg)`,
        severity: 0.3,
      });
    }

    // Compute overall score
    const score = signals.length > 0
      ? Math.min(1, signals.reduce((sum, s) => sum + s.severity, 0) / signals.length)
      : 0;

    return { score, signals, inLearningPeriod: false };
  }

  /**
   * Compute topic novelty score
   */
  private computeTopicNovelty(embedding: number[]): number {
    if (this.topicEmbeddings.length === 0) return 0;

    // Find most similar topic
    let maxSimilarity = 0;
    for (const topic of this.topicEmbeddings) {
      const similarity = cosineSimilarity(embedding, topic.embedding);
      if (similarity > maxSimilarity) {
        maxSimilarity = similarity;
      }
    }

    // Novelty is inverse of similarity
    return 1 - maxSimilarity;
  }

  /**
   * Extract domains from text
   */
  private extractDomains(text: string): string[] {
    const urlRegex = /https?:\/\/([^\/\s]+)/gi;
    const domains: string[] = [];
    let match;

    while ((match = urlRegex.exec(text)) !== null) {
      domains.push(match[1].toLowerCase());
    }

    return [...new Set(domains)];
  }

  /**
   * Check if two dates are the same day
   */
  private isSameDay(date1: Date, date2: Date): boolean {
    return date1.toDateString() === date2.toDateString();
  }

  /**
   * Check if learning period is complete
   */
  isLearningComplete(): boolean {
    const daysSinceStart = Math.floor(
      (Date.now() - this.startDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    return (
      daysSinceStart >= this.config.learningPeriodDays &&
      this.totalMemories >= this.config.minMemoriesForLearning
    );
  }

  /**
   * Get baseline statistics
   */
  getStats(): BaselineStats {
    const daysSinceStart = Math.floor(
      (Date.now() - this.startDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    // Get top domains
    const topDomains = [...this.domainCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([domain, count]) => ({ domain, count }));

    // Get top sources
    const topSources = [...this.sourceCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([source, count]) => ({ source, count }));

    return {
      totalMemories: this.totalMemories,
      memoriesPerDay: this.memoriesPerDay.average,
      instructionRatio: this.instructionRatio.average,
      topDomains,
      topSources,
      learningComplete: this.isLearningComplete(),
      daysCollected: daysSinceStart,
      startDate: this.startDate,
    };
  }

  /**
   * Reset baseline (start fresh)
   */
  reset(): void {
    this.db.exec(`
      DELETE FROM baseline_state;
      DELETE FROM baseline_domains;
      DELETE FROM baseline_sources;
      DELETE FROM baseline_topics;
    `);

    this.memoriesPerDay = new RollingAverage(30);
    this.instructionRatio = new RollingAverage(100);
    this.domainCounts.clear();
    this.sourceCounts.clear();
    this.topicEmbeddings = [];
    this.startDate = new Date();
    this.lastUpdateDate = new Date();
    this.totalMemories = 0;
    this.dailyMemoryCount = 0;

    this.saveState();
  }

  /**
   * Close database connection
   */
  close(): void {
    this.saveState();
    this.db.close();
  }
}

/**
 * Check if text contains instruction-like patterns
 */
export function containsInstruction(text: string): boolean {
  const instructionPatterns = [
    /\b(always|never|must|should)\s+(do|use|send|run|execute|remember)/i,
    /\bfrom\s+now\s+on/i,
    /\bremember\s+(that|this|to)/i,
    /\bwhenever\s+(you|asked|prompted)/i,
    /\bupdate\s+(your|the)\s+(memory|preferences?|settings?)/i,
  ];

  return instructionPatterns.some(pattern => pattern.test(text));
}

/**
 * Create a baseline tracker
 */
export function createBaselineTracker(
  dbPath: string,
  config?: Partial<BaselineConfig>,
  embeddingClient?: EmbeddingClient
): BaselineTracker {
  return new BaselineTracker(dbPath, config, embeddingClient);
}
