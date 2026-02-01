/**
 * memfw OpenClaw Skill
 *
 * Entry point for the Memory Firewall skill.
 * Provides memory protection and slash command handling.
 */

import { MemfwSkill } from './skill.js';
import { CommandHandler } from './commands.js';
import { MemoryHook } from './hooks.js';

// Export the skill instance
export const skill = new MemfwSkill();

// Export command handler for slash commands
export const commands = new CommandHandler(skill);

// Export memory hook for intercepting writes
export const memoryHook = new MemoryHook(skill);

// Default export for OpenClaw skill loader
export default {
  name: 'memfw',
  version: '0.1.0',

  /**
   * Initialize the skill
   */
  async init(context: SkillContext): Promise<void> {
    await skill.initialize(context);
  },

  /**
   * Handle slash commands
   */
  async handleCommand(command: string, args: string[], context: CommandContext): Promise<CommandResult> {
    return commands.handle(command, args, context);
  },

  /**
   * Hook into memory write operations
   */
  async onMemoryWrite(content: string, context: MemoryContext): Promise<MemoryWriteResult> {
    return memoryHook.onWrite(content, context);
  },

  /**
   * Cleanup on skill unload
   */
  async cleanup(): Promise<void> {
    await skill.cleanup();
  },
};

/**
 * OpenClaw skill context
 */
export interface SkillContext {
  workspaceDir: string;
  skillDir: string;
  agentId: string;
  config: Record<string, unknown>;
}

/**
 * Command execution context
 */
export interface CommandContext {
  agentId: string;
  sessionId: string;
  userId?: string;
}

/**
 * Memory operation context
 */
export interface MemoryContext {
  source: string;
  agentId: string;
  sessionId: string;
  triggerContext?: string;
  filePath?: string;
}

/**
 * Command result
 */
export interface CommandResult {
  success: boolean;
  message: string;
  data?: unknown;
}

/**
 * Memory write result
 */
export interface MemoryWriteResult {
  allowed: boolean;
  quarantineId?: string;
  reason?: string;
}
