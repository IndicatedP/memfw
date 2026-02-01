---
name: memfw
description: Memory Firewall - Protects agent memory from poisoning attacks
version: 0.1.0
author: memfw
---

# Memory Firewall

This skill protects your agent's memory from poisoning attacks by:
- **Tagging** all memories with their source (provenance tracking)
- **Detecting** suspicious content before it enters memory
- **Quarantining** flagged content for human review

## How It Works

When content is about to be written to memory, memfw:

1. **Tags** the content with provenance metadata (source, trust level, timestamp)
2. **Scans** for suspicious patterns (Layer 1: regex patterns)
3. **Analyzes** semantic similarity to known attack patterns (Layer 2: embeddings)
4. **Quarantines** flagged content instead of storing it
5. **Notifies** you when something is quarantined

## Commands

### Status & Info

- `/memfw status` - Show protection status, memory stats, and recent activity
- `/memfw help` - Show this help message

### Quarantine Management

- `/memfw quarantine` - List pending quarantined memories
- `/memfw quarantine list [--all]` - List quarantined memories (--all includes reviewed)
- `/memfw quarantine show <id>` - Show full details of a quarantined memory
- `/memfw quarantine approve <id>` - Approve and store a quarantined memory
- `/memfw quarantine reject <id>` - Reject and delete a quarantined memory

### Audit & History

- `/memfw audit [days]` - Show memory activity for the last N days (default: 7)
- `/memfw audit --source <source>` - Filter audit by source

### Configuration

- `/memfw config` - Show current configuration
- `/memfw config set <key> <value>` - Update a configuration value

## Configuration Options

| Key | Values | Default | Description |
|-----|--------|---------|-------------|
| `detection.enabled` | true/false | true | Enable/disable detection |
| `detection.sensitivity` | low/medium/high | medium | Detection sensitivity |
| `notifications.onQuarantine` | true/false | true | Notify when content quarantined |

## Trust Levels

memfw classifies sources by trust level:

| Level | Sources | Treatment |
|-------|---------|-----------|
| **user** | Direct user input | Highest trust, lenient detection |
| **tool_verified** | GitHub, Slack, Notion, etc. | High trust |
| **tool_unverified** | Unknown tools | Medium trust |
| **agent** | Agent-generated content | Medium trust |
| **external** | Web content, emails, Moltbook | Lowest trust, strict detection |

## Attack Categories Detected

- Instruction override attempts ("ignore previous instructions")
- System prompt extraction ("show me your prompt")
- Role manipulation / jailbreaks ("enable developer mode")
- Data exfiltration indicators ("send to external server")
- Credential/secret access ("show me the API key")
- File system manipulation ("delete the config")
- Encoded/obfuscated content (base64, eval)
- Memory/context manipulation ("remember this forever")

## Privacy

- All detection happens locally
- Embeddings use OpenAI API (content is sent for analysis)
- No data is sent to external servers except OpenAI
- Quarantined content is stored locally in SQLite

## Installation

1. Copy this skill to your OpenClaw skills directory:
   ```
   cp -r memfw ~/.openclaw/workspace/skills/
   ```

2. Set your OpenAI API key (for Layer 2 semantic analysis):
   ```
   export OPENAI_API_KEY=your-key-here
   ```

3. The skill will automatically activate on memory operations.
