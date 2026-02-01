/**
 * Slash Command Handler
 *
 * Handles /memfw commands within OpenClaw.
 */

import { MemfwSkill } from './skill.js';
import { TrustLevel } from 'memfw';
import type { CommandContext, CommandResult } from './index.js';

/**
 * Command handler for /memfw commands
 */
export class CommandHandler {
  private skill: MemfwSkill;

  constructor(skill: MemfwSkill) {
    this.skill = skill;
  }

  /**
   * Handle a slash command
   */
  async handle(command: string, args: string[], context: CommandContext): Promise<CommandResult> {
    // Remove /memfw prefix if present
    const cmd = command.replace(/^\/memfw\s*/, '').trim();
    const subCommand = args[0]?.toLowerCase() ?? '';

    try {
      switch (cmd || subCommand) {
        case '':
        case 'status':
          return this.handleStatus();

        case 'help':
          return this.handleHelp();

        case 'quarantine':
          return this.handleQuarantine(args.slice(1), context);

        case 'audit':
          return this.handleAudit(args.slice(1));

        case 'config':
          return this.handleConfig(args.slice(1));

        default:
          return {
            success: false,
            message: `Unknown command: ${cmd || subCommand}. Use /memfw help for available commands.`,
          };
      }
    } catch (error) {
      return {
        success: false,
        message: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Handle /memfw status
   */
  private handleStatus(): CommandResult {
    const status = this.skill.getStatus();

    const lines = [
      '## Memory Firewall Status',
      '',
      `**Protection:** ${status.enabled ? 'Active' : 'Disabled'}`,
      `**Layer 2 (Semantic):** ${status.layer2Enabled ? 'Enabled' : 'Disabled'}`,
      `**Layer 3 (LLM Judge):** ${status.layer3Enabled ? 'Enabled' : 'Disabled'}`,
      '',
      '### Memory Statistics',
      `- Protected memories: ${status.totalMemories}`,
      `- Quarantined pending: ${status.quarantineCounts.pending ?? 0}`,
    ];

    if (status.quarantineCounts.approved) {
      lines.push(`- Approved: ${status.quarantineCounts.approved}`);
    }
    if (status.quarantineCounts.rejected) {
      lines.push(`- Rejected: ${status.quarantineCounts.rejected}`);
    }

    if (status.totalMemories > 0) {
      lines.push('', '### By Trust Level');
      for (const [level, count] of Object.entries(status.trustCounts)) {
        if (count > 0) {
          lines.push(`- ${level}: ${count}`);
        }
      }
    }

    return {
      success: true,
      message: lines.join('\n'),
      data: status,
    };
  }

  /**
   * Handle /memfw help
   */
  private handleHelp(): CommandResult {
    const help = `## Memory Firewall Commands

### Status
- \`/memfw\` or \`/memfw status\` - Show protection status

### Quarantine Management
- \`/memfw quarantine\` - List pending quarantined memories
- \`/memfw quarantine list [--all]\` - List all quarantined memories
- \`/memfw quarantine show <id>\` - Show details of a quarantined memory
- \`/memfw quarantine approve <id>\` - Approve a memory
- \`/memfw quarantine reject <id>\` - Reject a memory

### Audit
- \`/memfw audit [days]\` - Show recent activity (default: 7 days)
- \`/memfw audit --source <source>\` - Filter by source

### Configuration
- \`/memfw config\` - Show current configuration
- \`/memfw config set <key> <value>\` - Update configuration`;

    return {
      success: true,
      message: help,
    };
  }

  /**
   * Handle /memfw quarantine subcommands
   */
  private handleQuarantine(args: string[], context: CommandContext): CommandResult {
    const subCommand = args[0]?.toLowerCase() ?? 'list';

    switch (subCommand) {
      case 'list': {
        const showAll = args.includes('--all');
        const memories = showAll
          ? this.skill.getQuarantined()
          : this.skill.getQuarantined({ status: 'pending' });

        if (memories.length === 0) {
          return {
            success: true,
            message: showAll
              ? 'No quarantined memories found.'
              : 'No pending quarantined memories. Use `--all` to see reviewed ones.',
          };
        }

        const lines = ['## Quarantined Memories', ''];
        for (const memory of memories) {
          const riskLevel = this.getRiskLevel(memory.layer2Similarity, memory.layer3Verdict);
          const preview = this.truncate(memory.text, 60);
          lines.push(
            `### ${memory.id.substring(0, 8)} [${memory.status.toUpperCase()}]`,
            `- **Source:** ${memory.source}`,
            `- **Risk:** ${riskLevel}`,
            memory.layer3Verdict ? `- **LLM Verdict:** ${memory.layer3Verdict}` : '',
            `- **Content:** ${preview}`,
            ''
          );
        }

        return {
          success: true,
          message: lines.join('\n'),
          data: memories,
        };
      }

      case 'show': {
        const id = args[1];
        if (!id) {
          return { success: false, message: 'Usage: /memfw quarantine show <id>' };
        }

        const memory = this.skill.getQuarantinedById(id);
        if (!memory) {
          return { success: false, message: `Quarantined memory not found: ${id}` };
        }

        const lines = [
          `## Quarantined Memory: ${memory.id.substring(0, 8)}`,
          '',
          `**Status:** ${memory.status}`,
          `**Source:** ${memory.source}`,
          `**Trust Level:** ${memory.trustLevel}`,
          `**Quarantined:** ${memory.quarantinedAt.toISOString()}`,
          '',
          '### Detection Results',
          `- Layer 2 Similarity: ${(memory.layer2Similarity * 100).toFixed(1)}%`,
        ];

        if (memory.layer1Flags.length > 0) {
          lines.push(`- Layer 1 Flags: ${memory.layer1Flags.join(', ')}`);
        }

        if (memory.layer3Verdict) {
          lines.push(`- Layer 3 Verdict: **${memory.layer3Verdict}**`);
          if (memory.layer3Reasoning) {
            lines.push(`- Layer 3 Reasoning: ${memory.layer3Reasoning}`);
          }
        }

        if (memory.layer2Exemplar) {
          lines.push('', '### Matched Attack Pattern', `> ${memory.layer2Exemplar}`);
        }

        lines.push('', '### Content', '```', memory.text, '```');

        return {
          success: true,
          message: lines.join('\n'),
          data: memory,
        };
      }

      case 'approve': {
        const id = args[1];
        if (!id) {
          return { success: false, message: 'Usage: /memfw quarantine approve <id>' };
        }

        const success = this.skill.approveQuarantined(id, context.userId);
        if (!success) {
          return { success: false, message: `Failed to approve: ${id}` };
        }

        return {
          success: true,
          message: `Approved quarantined memory: ${id}`,
        };
      }

      case 'reject': {
        const id = args[1];
        if (!id) {
          return { success: false, message: 'Usage: /memfw quarantine reject <id>' };
        }

        const success = this.skill.rejectQuarantined(id, context.userId);
        if (!success) {
          return { success: false, message: `Failed to reject: ${id}` };
        }

        return {
          success: true,
          message: `Rejected quarantined memory: ${id}`,
        };
      }

      default:
        return {
          success: false,
          message: `Unknown quarantine command: ${subCommand}`,
        };
    }
  }

  /**
   * Handle /memfw audit
   */
  private handleAudit(args: string[]): CommandResult {
    let days = 7;
    let source: string | undefined;

    // Parse arguments
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--source' && args[i + 1]) {
        source = args[i + 1];
        i++;
      } else if (!isNaN(parseInt(args[i], 10))) {
        days = parseInt(args[i], 10);
      }
    }

    const entries = this.skill.getAuditLog({ days, source, limit: 50 });

    if (entries.length === 0) {
      return {
        success: true,
        message: source
          ? `No activity from "${source}" in the last ${days} days.`
          : `No memory activity in the last ${days} days.`,
      };
    }

    const lines = [
      `## Memory Audit (last ${days} days)`,
      source ? `Filtered by source: ${source}` : '',
      '',
    ];

    for (const entry of entries) {
      const score = entry.detectionScore?.toFixed(2) ?? '-';
      const flags = entry.flags?.length ? ` [${entry.flags.length} flags]` : '';
      lines.push(
        `- **${entry.timestamp.toISOString().substring(0, 16)}** | ` +
          `${entry.source} | ${entry.trustLevel} | score: ${score}${flags}`
      );
    }

    return {
      success: true,
      message: lines.join('\n'),
      data: entries,
    };
  }

  /**
   * Handle /memfw config
   */
  private handleConfig(args: string[]): CommandResult {
    const subCommand = args[0]?.toLowerCase();

    if (subCommand === 'set') {
      const key = args[1];
      const value = args[2];

      if (!key || value === undefined) {
        return { success: false, message: 'Usage: /memfw config set <key> <value>' };
      }

      const success = this.skill.setConfig(key, value);
      if (!success) {
        return { success: false, message: `Invalid config key or value: ${key} = ${value}` };
      }

      return {
        success: true,
        message: `Configuration updated: ${key} = ${value}`,
      };
    }

    // Show config
    const config = this.skill.getConfig();
    if (!config) {
      return { success: false, message: 'Configuration not loaded' };
    }

    const lines = [
      '## memfw Configuration',
      '',
      '### Detection',
      `- enabled: ${config.detection.enabled}`,
      `- sensitivity: ${config.detection.sensitivity}`,
      `- enableLayer3: ${config.detection.enableLayer3}`,
      '',
      '### Notifications',
      `- onQuarantine: ${config.notifications.onQuarantine}`,
      '',
      '### Trust Overrides',
    ];

    for (const [source, level] of Object.entries(config.trust)) {
      lines.push(`- ${source}: ${level}`);
    }

    return {
      success: true,
      message: lines.join('\n'),
      data: config,
    };
  }

  /**
   * Get risk level label
   */
  private getRiskLevel(similarity: number, layer3Verdict?: string): string {
    // Layer 3 verdict takes precedence
    if (layer3Verdict === 'DANGEROUS') return 'HIGH';
    if (layer3Verdict === 'SUSPICIOUS') return 'MEDIUM';
    if (layer3Verdict === 'SAFE') return 'LOW';

    // Fall back to similarity score
    if (similarity >= 0.85) return 'HIGH';
    if (similarity >= 0.75) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Truncate text
   */
  private truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
  }
}
