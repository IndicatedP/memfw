/**
 * Notification System
 *
 * Handles notifications when content is quarantined.
 * Supports multiple notification channels.
 */

import { QuarantinedMemory, TrustLevel } from './types.js';

/**
 * Notification channel types
 */
export type NotificationChannel = 'console' | 'callback' | 'webhook';

/**
 * Notification payload
 */
export interface QuarantineNotification {
  id: string;
  timestamp: Date;
  source: string;
  trustLevel: TrustLevel;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  preview: string;
  reason: string;
  layer3Verdict?: string;
}

/**
 * Notification handler function type
 */
export type NotificationHandler = (notification: QuarantineNotification) => void | Promise<void>;

/**
 * Webhook configuration
 */
export interface WebhookConfig {
  url: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT';
}

/**
 * Notifier configuration
 */
export interface NotifierConfig {
  enabled: boolean;
  channels: NotificationChannel[];
  callback?: NotificationHandler;
  webhook?: WebhookConfig;
  /** Minimum risk level to notify (default: LOW) */
  minRiskLevel?: 'LOW' | 'MEDIUM' | 'HIGH';
}

/**
 * Notification manager for quarantine events
 */
export class Notifier {
  private config: NotifierConfig;
  private handlers: NotificationHandler[] = [];

  constructor(config: Partial<NotifierConfig> = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      channels: config.channels ?? ['console'],
      callback: config.callback,
      webhook: config.webhook,
      minRiskLevel: config.minRiskLevel ?? 'LOW',
    };

    // Set up default handlers based on channels
    if (this.config.channels.includes('console')) {
      this.handlers.push(this.consoleHandler.bind(this));
    }
    if (this.config.channels.includes('callback') && this.config.callback) {
      this.handlers.push(this.config.callback);
    }
    if (this.config.channels.includes('webhook') && this.config.webhook) {
      this.handlers.push(this.webhookHandler.bind(this));
    }
  }

  /**
   * Notify about a quarantined memory
   */
  async notify(memory: QuarantinedMemory, reason: string): Promise<void> {
    if (!this.config.enabled) return;

    const riskLevel = this.getRiskLevel(memory.layer2Similarity, memory.layer3Verdict);

    // Check minimum risk level
    if (!this.shouldNotify(riskLevel)) return;

    const notification: QuarantineNotification = {
      id: memory.id,
      timestamp: memory.quarantinedAt,
      source: memory.source,
      trustLevel: memory.trustLevel,
      riskLevel,
      preview: this.truncate(memory.text, 100),
      reason,
      layer3Verdict: memory.layer3Verdict,
    };

    // Run all handlers
    await Promise.all(
      this.handlers.map(async (handler) => {
        try {
          await handler(notification);
        } catch (error) {
          console.error('[memfw] Notification handler error:', error);
        }
      })
    );
  }

  /**
   * Add a custom notification handler
   */
  addHandler(handler: NotificationHandler): void {
    this.handlers.push(handler);
  }

  /**
   * Console notification handler
   */
  private consoleHandler(notification: QuarantineNotification): void {
    const riskColors: Record<string, string> = {
      LOW: '\x1b[34m',    // Blue
      MEDIUM: '\x1b[33m', // Yellow
      HIGH: '\x1b[31m',   // Red
    };
    const reset = '\x1b[0m';
    const color = riskColors[notification.riskLevel] ?? reset;

    console.log();
    console.log(`${color}[memfw] Content Quarantined${reset}`);
    console.log(`  ID: ${notification.id.substring(0, 8)}`);
    console.log(`  Risk: ${color}${notification.riskLevel}${reset}`);
    console.log(`  Source: ${notification.source}`);
    console.log(`  Preview: "${notification.preview}"`);
    if (notification.layer3Verdict) {
      console.log(`  LLM Verdict: ${notification.layer3Verdict}`);
    }
    console.log(`  Reason: ${notification.reason}`);
    console.log();
  }

  /**
   * Webhook notification handler
   */
  private async webhookHandler(notification: QuarantineNotification): Promise<void> {
    if (!this.config.webhook) return;

    try {
      const response = await fetch(this.config.webhook.url, {
        method: this.config.webhook.method ?? 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.config.webhook.headers,
        },
        body: JSON.stringify({
          event: 'memfw.quarantine',
          ...notification,
        }),
      });

      if (!response.ok) {
        console.error(`[memfw] Webhook failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('[memfw] Webhook error:', error);
    }
  }

  /**
   * Get risk level from similarity score and LLM verdict
   */
  private getRiskLevel(
    similarity: number,
    layer3Verdict?: string
  ): 'LOW' | 'MEDIUM' | 'HIGH' {
    // Layer 3 verdict takes precedence
    if (layer3Verdict === 'DANGEROUS') return 'HIGH';
    if (layer3Verdict === 'SUSPICIOUS') return 'MEDIUM';

    // Fall back to similarity score
    if (similarity >= 0.85) return 'HIGH';
    if (similarity >= 0.75) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Check if notification should be sent based on risk level
   */
  private shouldNotify(riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'): boolean {
    const levels = ['LOW', 'MEDIUM', 'HIGH'];
    const minIndex = levels.indexOf(this.config.minRiskLevel ?? 'LOW');
    const currentIndex = levels.indexOf(riskLevel);
    return currentIndex >= minIndex;
  }

  /**
   * Truncate text for preview
   */
  private truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<NotifierConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Check if notifications are enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }
}

/**
 * Create a notifier instance
 */
export function createNotifier(config?: Partial<NotifierConfig>): Notifier {
  return new Notifier(config);
}
