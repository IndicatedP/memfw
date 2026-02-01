/**
 * Memory Hooks
 *
 * Intercepts memory write operations to analyze content
 * before it's stored.
 */

import { MemfwSkill } from './skill.js';
import type { MemoryContext, MemoryWriteResult } from './index.js';

/**
 * Memory hook handler
 */
export class MemoryHook {
  private skill: MemfwSkill;

  constructor(skill: MemfwSkill) {
    this.skill = skill;
  }

  /**
   * Handle memory write operation
   *
   * This is called before content is written to memory.
   * Returns whether the write should proceed.
   */
  async onWrite(content: string, context: MemoryContext): Promise<MemoryWriteResult> {
    if (!this.skill.isInitialized()) {
      // If not initialized, allow the write (fail open)
      return { allowed: true };
    }

    try {
      // Analyze the content
      const result = await this.skill.analyzeContent(content, context);

      if (!result.allowed) {
        return {
          allowed: false,
          quarantineId: result.quarantineId,
          reason: result.detection.reason,
        };
      }

      return { allowed: true };
    } catch (error) {
      // On error, fail open to avoid blocking legitimate operations
      console.error('[memfw] Error analyzing content:', error);
      return { allowed: true };
    }
  }

  /**
   * Analyze content without blocking
   *
   * Useful for batch analysis or background scanning.
   */
  async analyze(content: string, context: MemoryContext): Promise<{
    score: number;
    patterns: string[];
    suspicious: boolean;
  }> {
    if (!this.skill.isInitialized()) {
      return { score: 0, patterns: [], suspicious: false };
    }

    try {
      const result = await this.skill.analyzeContent(content, context);
      return {
        score: result.detection.score,
        patterns: result.detection.layer1.patterns,
        suspicious: !result.allowed,
      };
    } catch {
      return { score: 0, patterns: [], suspicious: false };
    }
  }
}

/**
 * Source detection utilities
 *
 * Helps determine where memory content originated from.
 */
export class SourceDetector {
  /**
   * Detect source from OpenClaw context
   */
  static detectSource(context: {
    tool?: string;
    toolInput?: Record<string, unknown>;
    previousMessages?: Array<{ role: string; content: string }>;
    triggerType?: string;
  }): string {
    // Check if from a known tool
    if (context.tool) {
      return `tool:${context.tool.toLowerCase()}`;
    }

    // Check trigger type
    if (context.triggerType) {
      switch (context.triggerType) {
        case 'user_message':
          return 'user';
        case 'moltbook_post':
          return 'moltbook';
        case 'email':
          return 'email';
        case 'web_fetch':
          return 'web_fetch';
        case 'web_search':
          return 'web_search';
        case 'auto_compact':
          return 'agent:auto_compact';
        case 'skill':
          return 'agent:skill';
      }
    }

    // Check for web URLs in content context
    if (context.toolInput?.url) {
      const url = String(context.toolInput.url);
      try {
        const hostname = new URL(url).hostname;
        return `web:${hostname}`;
      } catch {
        return 'web:unknown';
      }
    }

    // Default to unknown external
    return 'external:unknown';
  }

  /**
   * Extract source hints from content
   */
  static extractSourceHints(content: string): string[] {
    const hints: string[] = [];

    // Check for URLs
    const urlMatch = content.match(/https?:\/\/[^\s]+/);
    if (urlMatch) {
      try {
        const hostname = new URL(urlMatch[0]).hostname;
        hints.push(`web:${hostname}`);
      } catch {
        // Ignore invalid URLs
      }
    }

    // Check for email patterns
    if (content.match(/from:.*@|received from|forwarded from/i)) {
      hints.push('email');
    }

    // Check for Moltbook patterns
    if (content.match(/moltbook|molted|@\w+\s+posted/i)) {
      hints.push('moltbook');
    }

    // Check for code/tool output patterns
    if (content.match(/```[\w]*\n|output:|result:|response:/i)) {
      hints.push('tool_output');
    }

    return hints;
  }
}

/**
 * File watcher for memory files
 *
 * Watches MEMORY.md and memory/*.md for changes and triggers analysis.
 */
export class MemoryFileWatcher {
  private skill: MemfwSkill;
  private watchedFiles: Map<string, string> = new Map();

  constructor(skill: MemfwSkill) {
    this.skill = skill;
  }

  /**
   * Track a file's content for change detection
   */
  trackFile(filePath: string, content: string): void {
    this.watchedFiles.set(filePath, content);
  }

  /**
   * Detect changes to a memory file
   */
  detectChanges(filePath: string, newContent: string): string | null {
    const oldContent = this.watchedFiles.get(filePath);
    if (!oldContent) {
      // New file, return all content
      return newContent;
    }

    // Find added content (simple diff)
    if (newContent.length > oldContent.length && newContent.startsWith(oldContent)) {
      return newContent.substring(oldContent.length).trim();
    }

    // Content was modified or replaced
    if (newContent !== oldContent) {
      // Return the new content for analysis
      return newContent;
    }

    return null;
  }

  /**
   * Analyze changes to a memory file
   */
  async analyzeFileChanges(
    filePath: string,
    newContent: string,
    context: Partial<MemoryContext>
  ): Promise<MemoryWriteResult> {
    const addedContent = this.detectChanges(filePath, newContent);

    if (!addedContent) {
      // No changes detected
      return { allowed: true };
    }

    // Determine source from file path
    let source = context.source ?? 'file:memory';
    if (filePath.includes('MEMORY.md')) {
      source = 'file:MEMORY.md';
    } else if (filePath.match(/memory\/\d{4}-\d{2}-\d{2}\.md/)) {
      source = 'file:daily';
    }

    const fullContext: MemoryContext = {
      source,
      agentId: context.agentId ?? 'unknown',
      sessionId: context.sessionId ?? 'unknown',
      triggerContext: context.triggerContext,
      filePath,
    };

    const hook = new MemoryHook(this.skill);
    const result = await hook.onWrite(addedContent, fullContext);

    // Update tracked content if allowed
    if (result.allowed) {
      this.trackFile(filePath, newContent);
    }

    return result;
  }
}
