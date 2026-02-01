#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import { config } from 'dotenv';
import path from 'path';
import fs from 'fs';
import { QuarantineStore } from '../storage/quarantine.js';
import { ProvenanceStore } from '../storage/provenance.js';
import { TrustLevel, QuarantineStatus } from '../core/types.js';

// Load environment variables
config();

const VERSION = '0.1.0';

// Default database paths
const DEFAULT_DB_DIR = path.join(process.cwd(), 'data');
const getDbPath = (name: string) => {
  const envPath = process.env.MEMFW_DB_PATH;
  if (envPath) {
    // If env var is set, use its directory
    const dir = path.dirname(envPath);
    return path.join(dir, `${name}.db`);
  }
  // Otherwise use default data directory
  return path.join(DEFAULT_DB_DIR, `${name}.db`);
};

// Helper to ensure data directory exists
function ensureDataDir(): void {
  const dir = path.dirname(getDbPath('quarantine'));
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// Helper to truncate text
function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

// Helper to format date
function formatDate(date: Date): string {
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

// Helper to get risk level from similarity score
function getRiskLevel(similarity: number): string {
  if (similarity >= 0.85) return chalk.red('HIGH');
  if (similarity >= 0.75) return chalk.yellow('MEDIUM');
  return chalk.blue('LOW');
}

// Helper to format trust level
function formatTrustLevel(trust: TrustLevel): string {
  const colors: Record<TrustLevel, (s: string) => string> = {
    [TrustLevel.USER]: chalk.green,
    [TrustLevel.TOOL_VERIFIED]: chalk.cyan,
    [TrustLevel.TOOL_UNVERIFIED]: chalk.yellow,
    [TrustLevel.AGENT]: chalk.blue,
    [TrustLevel.EXTERNAL]: chalk.red,
  };
  return colors[trust](trust);
}

// Create the CLI program
const program = new Command();

program
  .name('memfw')
  .description('Memory Firewall - Protects agent memory from poisoning attacks')
  .version(VERSION);

// ==================== STATUS COMMAND ====================
program
  .command('status')
  .description('Show protection status and stats')
  .action(() => {
    ensureDataDir();

    const quarantineStore = new QuarantineStore(getDbPath('quarantine'));
    const provenanceStore = new ProvenanceStore(getDbPath('provenance'));

    try {
      const quarantineCounts = quarantineStore.getCounts();
      const totalMemories = provenanceStore.getTotal();
      const trustCounts = provenanceStore.getCountsByTrust();

      console.log();
      console.log(chalk.bold(`Memory Firewall v${VERSION}`));
      console.log(chalk.dim('─'.repeat(40)));
      console.log();

      // Protection summary
      console.log(chalk.bold('Protection Status:'), chalk.green('ACTIVE'));
      console.log();

      // Memory stats
      console.log(chalk.bold('Memory Statistics:'));
      console.log(`  Protected memories: ${chalk.cyan(totalMemories)}`);
      console.log(`  Quarantined:        ${chalk.yellow(quarantineCounts.pending)} pending review`);
      if (quarantineCounts.approved > 0) {
        console.log(`                      ${chalk.green(quarantineCounts.approved)} approved`);
      }
      if (quarantineCounts.rejected > 0) {
        console.log(`                      ${chalk.red(quarantineCounts.rejected)} rejected`);
      }
      console.log();

      // Trust level breakdown
      if (totalMemories > 0) {
        console.log(chalk.bold('Memories by Trust Level:'));
        for (const [level, count] of Object.entries(trustCounts)) {
          if (count > 0) {
            console.log(`  ${formatTrustLevel(level as TrustLevel)}: ${count}`);
          }
        }
        console.log();
      }

      // Flagged entries
      const flagged = provenanceStore.getFlagged(5);
      if (flagged.length > 0) {
        console.log(chalk.bold('Recently Flagged:'));
        for (const entry of flagged) {
          console.log(`  ${chalk.dim(entry.id.substring(0, 8))} - score: ${chalk.yellow(entry.detectionScore?.toFixed(2))} from ${entry.source}`);
        }
        console.log();
      }
    } finally {
      quarantineStore.close();
      provenanceStore.close();
    }
  });

// ==================== QUARANTINE COMMANDS ====================
const quarantine = program
  .command('quarantine')
  .description('Manage quarantined memories');

quarantine
  .command('list')
  .description('List quarantined memories')
  .option('-s, --status <status>', 'Filter by status (pending, approved, rejected)')
  .option('-l, --limit <number>', 'Limit results', '20')
  .action((options) => {
    ensureDataDir();
    const store = new QuarantineStore(getDbPath('quarantine'));

    try {
      const memories = store.list({
        status: options.status as QuarantineStatus | undefined,
        limit: parseInt(options.limit, 10),
      });

      if (memories.length === 0) {
        console.log(chalk.dim('\nNo quarantined memories found.\n'));
        return;
      }

      const table = new Table({
        head: [
          chalk.bold('ID'),
          chalk.bold('Source'),
          chalk.bold('Content'),
          chalk.bold('Risk'),
          chalk.bold('Status'),
        ],
        colWidths: [10, 15, 40, 8, 10],
        wordWrap: true,
      });

      for (const memory of memories) {
        const statusColors: Record<QuarantineStatus, (s: string) => string> = {
          pending: chalk.yellow,
          approved: chalk.green,
          rejected: chalk.red,
        };

        table.push([
          memory.id.substring(0, 8),
          memory.source,
          truncate(memory.text, 37),
          getRiskLevel(memory.layer2Similarity),
          statusColors[memory.status](memory.status),
        ]);
      }

      console.log();
      console.log(table.toString());
      console.log();
    } finally {
      store.close();
    }
  });

quarantine
  .command('show <id>')
  .description('Show full details of a quarantined memory')
  .action((id) => {
    ensureDataDir();
    const store = new QuarantineStore(getDbPath('quarantine'));

    try {
      // Support partial ID matching
      const memories = store.list();
      const memory = memories.find((m) => m.id.startsWith(id));

      if (!memory) {
        console.log(chalk.red(`\nQuarantined memory not found: ${id}\n`));
        process.exit(1);
      }

      console.log();
      console.log(chalk.bold('Quarantined Memory Details'));
      console.log(chalk.dim('─'.repeat(50)));
      console.log();
      console.log(chalk.bold('ID:'), memory.id);
      console.log(chalk.bold('Status:'), memory.status);
      console.log(chalk.bold('Source:'), memory.source);
      console.log(chalk.bold('Trust Level:'), formatTrustLevel(memory.trustLevel));
      console.log(chalk.bold('Quarantined At:'), formatDate(memory.quarantinedAt));
      if (memory.reviewedAt) {
        console.log(chalk.bold('Reviewed At:'), formatDate(memory.reviewedAt));
        if (memory.reviewedBy) {
          console.log(chalk.bold('Reviewed By:'), memory.reviewedBy);
        }
      }
      console.log();

      console.log(chalk.bold('Detection Results:'));
      console.log(`  Layer 2 Similarity: ${chalk.yellow(memory.layer2Similarity.toFixed(3))} ${getRiskLevel(memory.layer2Similarity)}`);
      if (memory.layer1Flags.length > 0) {
        console.log(`  Layer 1 Flags: ${memory.layer1Flags.join(', ')}`);
      }
      if (memory.layer2Exemplar) {
        console.log();
        console.log(chalk.bold('Matched Exemplar:'));
        console.log(chalk.dim(`  "${truncate(memory.layer2Exemplar, 70)}"`));
      }
      console.log();

      console.log(chalk.bold('Content:'));
      console.log(chalk.dim('─'.repeat(50)));
      console.log(memory.text);
      console.log(chalk.dim('─'.repeat(50)));
      console.log();
    } finally {
      store.close();
    }
  });

quarantine
  .command('approve <ids...>')
  .description('Approve quarantined memories')
  .option('-u, --user <name>', 'Reviewer name')
  .action((ids, options) => {
    ensureDataDir();
    const store = new QuarantineStore(getDbPath('quarantine'));

    try {
      const memories = store.list();
      let approved = 0;
      let notFound = 0;

      for (const id of ids) {
        const memory = memories.find((m) => m.id.startsWith(id));
        if (memory) {
          if (store.approve(memory.id, options.user)) {
            console.log(chalk.green(`✓ Approved: ${memory.id.substring(0, 8)}`));
            approved++;
          }
        } else {
          console.log(chalk.red(`✗ Not found: ${id}`));
          notFound++;
        }
      }

      console.log();
      console.log(`Approved: ${approved}, Not found: ${notFound}`);
    } finally {
      store.close();
    }
  });

quarantine
  .command('reject <ids...>')
  .description('Reject quarantined memories')
  .option('-u, --user <name>', 'Reviewer name')
  .action((ids, options) => {
    ensureDataDir();
    const store = new QuarantineStore(getDbPath('quarantine'));

    try {
      const memories = store.list();
      let rejected = 0;
      let notFound = 0;

      for (const id of ids) {
        const memory = memories.find((m) => m.id.startsWith(id));
        if (memory) {
          if (store.reject(memory.id, options.user)) {
            console.log(chalk.green(`✓ Rejected: ${memory.id.substring(0, 8)}`));
            rejected++;
          }
        } else {
          console.log(chalk.red(`✗ Not found: ${id}`));
          notFound++;
        }
      }

      console.log();
      console.log(`Rejected: ${rejected}, Not found: ${notFound}`);
    } finally {
      store.close();
    }
  });

// ==================== AUDIT COMMAND ====================
program
  .command('audit')
  .description('Show recent memory activity')
  .option('-d, --days <number>', 'Number of days to show', '7')
  .option('-s, --source <source>', 'Filter by source')
  .option('-l, --limit <number>', 'Limit results', '50')
  .action((options) => {
    ensureDataDir();
    const store = new ProvenanceStore(getDbPath('provenance'));

    try {
      const daysAgo = new Date();
      daysAgo.setDate(daysAgo.getDate() - parseInt(options.days, 10));

      const allEntries = store.list({
        source: options.source,
        limit: parseInt(options.limit, 10),
      });

      // Filter by date
      const entries = allEntries.filter((e) => e.timestamp >= daysAgo);

      if (entries.length === 0) {
        console.log(chalk.dim(`\nNo memory activity in the last ${options.days} days.\n`));
        return;
      }

      console.log();
      console.log(chalk.bold(`Memory Activity (last ${options.days} days)`));
      console.log(chalk.dim('─'.repeat(60)));
      console.log();

      const table = new Table({
        head: [
          chalk.bold('ID'),
          chalk.bold('Timestamp'),
          chalk.bold('Source'),
          chalk.bold('Trust'),
          chalk.bold('Score'),
          chalk.bold('Flags'),
        ],
        colWidths: [10, 21, 18, 16, 7, 20],
      });

      for (const entry of entries) {
        const score = entry.detectionScore !== undefined
          ? entry.detectionScore.toFixed(2)
          : '-';
        const flags = entry.flags?.join(', ') || '-';

        table.push([
          entry.id.substring(0, 8),
          formatDate(entry.timestamp),
          truncate(entry.source, 15),
          formatTrustLevel(entry.trustLevel),
          score,
          truncate(flags, 17),
        ]);
      }

      console.log(table.toString());
      console.log();

      // Summary stats
      const bySource = new Map<string, number>();
      for (const entry of entries) {
        bySource.set(entry.source, (bySource.get(entry.source) || 0) + 1);
      }

      console.log(chalk.bold('Summary:'));
      console.log(`  Total entries: ${entries.length}`);
      console.log(`  Sources: ${Array.from(bySource.keys()).join(', ')}`);
      console.log();
    } finally {
      store.close();
    }
  });

// ==================== CONFIG COMMANDS ====================
const configCmd = program
  .command('config')
  .description('Manage configuration');

const CONFIG_FILE = path.join(process.cwd(), 'memfw.config.json');

interface MemfwCliConfig {
  detection: {
    enabled: boolean;
    useLlmJudge: boolean;
    sensitivity: 'low' | 'medium' | 'high';
  };
  trust: Record<string, TrustLevel>;
}

const DEFAULT_CONFIG: MemfwCliConfig = {
  detection: {
    enabled: true,
    useLlmJudge: false,
    sensitivity: 'medium',
  },
  trust: {
    moltbook: TrustLevel.EXTERNAL,
    web_fetch: TrustLevel.EXTERNAL,
    web_search: TrustLevel.EXTERNAL,
  },
};

function loadConfig(): MemfwCliConfig {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const content = fs.readFileSync(CONFIG_FILE, 'utf-8');
      return { ...DEFAULT_CONFIG, ...JSON.parse(content) };
    } catch {
      return DEFAULT_CONFIG;
    }
  }
  return DEFAULT_CONFIG;
}

function saveConfig(cfg: MemfwCliConfig): void {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

configCmd
  .command('show')
  .description('Show current configuration')
  .action(() => {
    const cfg = loadConfig();
    console.log();
    console.log(chalk.bold('memfw Configuration'));
    console.log(chalk.dim('─'.repeat(40)));
    console.log();
    console.log(chalk.bold('Detection:'));
    console.log(`  enabled:      ${cfg.detection.enabled ? chalk.green('true') : chalk.red('false')}`);
    console.log(`  useLlmJudge:  ${cfg.detection.useLlmJudge ? chalk.green('true') : chalk.red('false')}`);
    console.log(`  sensitivity:  ${cfg.detection.sensitivity}`);
    console.log();
    console.log(chalk.bold('Trust Overrides:'));
    for (const [source, level] of Object.entries(cfg.trust)) {
      console.log(`  ${source}: ${formatTrustLevel(level)}`);
    }
    console.log();
    console.log(chalk.dim(`Config file: ${CONFIG_FILE}`));
    console.log();
  });

configCmd
  .command('set <key> <value>')
  .description('Set a configuration value')
  .action((key, value) => {
    const cfg = loadConfig();

    // Handle nested keys like "detection.enabled"
    const parts = key.split('.');

    if (parts[0] === 'detection') {
      if (parts[1] === 'enabled') {
        cfg.detection.enabled = value === 'true';
      } else if (parts[1] === 'useLlmJudge') {
        cfg.detection.useLlmJudge = value === 'true';
      } else if (parts[1] === 'sensitivity') {
        if (['low', 'medium', 'high'].includes(value)) {
          cfg.detection.sensitivity = value as 'low' | 'medium' | 'high';
        } else {
          console.log(chalk.red('Invalid sensitivity value. Use: low, medium, high'));
          process.exit(1);
        }
      } else {
        console.log(chalk.red(`Unknown detection key: ${parts[1]}`));
        process.exit(1);
      }
    } else if (parts[0] === 'trust') {
      if (Object.values(TrustLevel).includes(value as TrustLevel)) {
        cfg.trust[parts[1]] = value as TrustLevel;
      } else {
        console.log(chalk.red(`Invalid trust level. Use: ${Object.values(TrustLevel).join(', ')}`));
        process.exit(1);
      }
    } else {
      console.log(chalk.red(`Unknown config key: ${key}`));
      console.log(chalk.dim('Valid keys: detection.enabled, detection.useLlmJudge, detection.sensitivity, trust.<source>'));
      process.exit(1);
    }

    saveConfig(cfg);
    console.log(chalk.green(`✓ Set ${key} = ${value}`));
  });

// Parse and run
program.parse();
