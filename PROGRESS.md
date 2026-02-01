# memfw Development Progress

## Overview

memfw (Memory Firewall) is a security layer for AI agents with persistent memory, protecting against memory poisoning attacks.

---

## Phase 1: Core Library + Basic Detection ✅ COMPLETE

### Deliverables

| Item | Status | Notes |
|------|--------|-------|
| Package structure | ✅ Done | TypeScript, ES modules, Node 18+ |
| Layer 1 pattern matching | ✅ Done | 9 attack categories, ~50 regex patterns |
| Layer 2 semantic similarity | ✅ Done | OpenAI embeddings, 29 attack exemplars |
| Provenance data structures | ✅ Done | Full type definitions in `src/core/types.ts` |
| SQLite quarantine store | ✅ Done | `src/storage/quarantine.ts` |
| SQLite provenance store | ✅ Done | `src/storage/provenance.ts` |
| Memory store with FTS | ✅ Done | `src/storage/memory.ts` |
| Ingress tagger | ✅ Done | `src/tagger/index.ts` |
| Basic CLI | ✅ Done | `src/cli/index.ts` |

### CLI Commands Available

```bash
memfw status                    # Show protection status and stats
memfw quarantine list           # List quarantined memories
memfw quarantine show <id>      # Show full details
memfw quarantine approve <id>   # Approve memory
memfw quarantine reject <id>    # Reject memory
memfw audit [--days N]          # Show recent activity
memfw config show               # Show configuration
memfw config set <key> <value>  # Update configuration
```

### Detection Categories (Layer 1)

- Instruction override attempts
- System prompt extraction
- Role manipulation / jailbreaks
- Data exfiltration indicators
- Credential/secret access
- File system manipulation
- Encoded/obfuscated content
- Memory/context manipulation

### Attack Exemplars (Layer 2)

29 curated attack patterns covering:
- Data exfiltration
- Instruction injection
- Credential harvesting
- Preference hijacking
- Memory manipulation
- System prompt extraction
- Role manipulation

---

## Phase 2: OpenClaw Integration ✅ COMPLETE

### Deliverables

| Item | Status | Notes |
|------|--------|-------|
| OpenClaw skill structure | ✅ Done | SKILL.md, skill config, package.json |
| Memory write interception | ✅ Done | `skill/src/hooks.ts` - MemoryHook class |
| Source detection | ✅ Done | `skill/src/hooks.ts` - SourceDetector class |
| Integration with memory files | ✅ Done | `skill/src/hooks.ts` - MemoryFileWatcher class |
| Slash commands | ✅ Done | `skill/src/commands.ts` - full command handler |

### Slash Commands Available

```
/memfw                          # Show status (alias for /memfw status)
/memfw status                   # Show protection status and stats
/memfw help                     # Show help message

/memfw quarantine               # List pending quarantined memories
/memfw quarantine list [--all]  # List quarantined (--all includes reviewed)
/memfw quarantine show <id>     # Show full details
/memfw quarantine approve <id>  # Approve memory
/memfw quarantine reject <id>   # Reject memory

/memfw audit [days]             # Show recent activity (default: 7 days)
/memfw audit --source <source>  # Filter by source

/memfw config                   # Show current configuration
/memfw config set <key> <value> # Update configuration
```

### OpenClaw Skill Structure

```
skill/
├── SKILL.md              # Skill definition and documentation
├── package.json          # Skill package with memfw dependency
├── tsconfig.json         # TypeScript configuration
├── src/
│   ├── index.ts          # Entry point and exports
│   ├── skill.ts          # Main skill class wrapping memfw-core
│   ├── commands.ts       # Slash command handler
│   └── hooks.ts          # Memory hooks and source detection
├── config/
│   └── policy.json       # Default policy configuration
└── data/
    └── .gitkeep          # Data directory for SQLite databases
```

### Key Components

**MemfwSkill** (`skill.ts`):
- Wraps memfw-core library for OpenClaw use
- Manages configuration, stores, and detector
- Provides high-level API for commands and hooks

**CommandHandler** (`commands.ts`):
- Handles all /memfw slash commands
- Formats output as Markdown for OpenClaw
- Supports status, quarantine, audit, and config commands

**MemoryHook** (`hooks.ts`):
- Intercepts memory write operations
- Analyzes content before storage
- Returns allow/quarantine decision

**SourceDetector** (`hooks.ts`):
- Detects content origin from context
- Extracts source hints from content
- Maps sources to trust levels

**MemoryFileWatcher** (`hooks.ts`):
- Watches MEMORY.md and memory/*.md
- Detects content changes
- Triggers analysis on file modifications

---

## Phase 3: LLM Judge + Refinement 🔲 NOT STARTED

### Planned Deliverables

| Item | Status | Notes |
|------|--------|-------|
| Layer 3 LLM judge | 🔲 Todo | For borderline cases |
| Configurable thresholds | 🔲 Todo | User-adjustable sensitivity |
| Better source heuristics | 🔲 Todo | Improved source detection |
| Quarantine notifications | 🔲 Todo | Alert user on quarantine |
| Web dashboard (optional) | 🔲 Todo | Audit/review UI |

---

## Phase 4: Behavioral Baseline 🔲 NOT STARTED

### Planned Deliverables

| Item | Status | Notes |
|------|--------|-------|
| Baseline tracking | 🔲 Todo | Track normal patterns |
| Anomaly scoring | 🔲 Todo | Detect unusual activity |
| Learning period | 🔲 Todo | Build baseline before flagging |
| Baseline dashboard | 🔲 Todo | Visualize stats |

---

## Technical Stack

- **Language:** TypeScript (ES2022)
- **Runtime:** Node.js 18+
- **Database:** SQLite (better-sqlite3 v12.6.2)
- **Embeddings:** OpenAI text-embedding-3-small
- **CLI:** Commander.js, Chalk, cli-table3

---

## File Structure

```
memfw/
├── src/                      # Core library (memfw-core)
│   ├── index.ts              # Main library exports
│   ├── core/
│   │   ├── types.ts          # Type definitions
│   │   ├── patterns.ts       # Layer 1 regex patterns
│   │   ├── detector.ts       # Detection pipeline
│   │   ├── exemplars.ts      # Layer 2 attack exemplars
│   │   └── embeddings.ts     # OpenAI embedding client
│   ├── storage/
│   │   ├── provenance.ts     # Provenance metadata store
│   │   ├── memory.ts         # Memory store with FTS
│   │   └── quarantine.ts     # Quarantine store
│   ├── tagger/
│   │   └── index.ts          # Ingress tagger
│   └── cli/
│       └── index.ts          # CLI commands
├── skill/                    # OpenClaw skill (Phase 2)
│   ├── SKILL.md              # Skill documentation
│   ├── package.json          # Skill package
│   ├── tsconfig.json         # TypeScript config
│   ├── src/
│   │   ├── index.ts          # Skill entry point
│   │   ├── skill.ts          # Main skill class
│   │   ├── commands.ts       # Slash command handler
│   │   └── hooks.ts          # Memory hooks
│   ├── config/
│   │   └── policy.json       # Default config
│   └── data/                 # SQLite databases
├── dist/                     # Compiled JavaScript
├── data/                     # CLI SQLite databases
├── package.json
├── tsconfig.json
├── memfw-project-spec.md     # Full specification
└── PROGRESS.md               # This file
```

---

## Success Metrics (Target)

1. **Detection Rate:** >90% of synthetic attack payloads
2. **False Positive Rate:** <5% of benign memories
3. **Latency:** <100ms for 95% of memories (Layer 1+2)
4. **Adoption:** >100 installs in first month

---

## Getting Started

### Core Library & CLI

```bash
# Install dependencies
npm install

# Build
npm run build

# Run CLI
node dist/cli/index.js status

# Or use npm script
npm run cli -- status
```

### OpenClaw Skill Installation

```bash
# Copy skill to OpenClaw skills directory
cp -r skill ~/.openclaw/workspace/skills/memfw

# Or create a symlink for development
ln -s $(pwd)/skill ~/.openclaw/workspace/skills/memfw

# Set OpenAI API key for Layer 2 semantic analysis
export OPENAI_API_KEY=your-key-here
```

---

## Next Steps

1. **Testing:** Add unit tests for detection pipeline and skill
2. **Phase 3:** Implement LLM Judge for borderline cases
3. **Phase 4:** Add behavioral baseline and anomaly detection
4. **Documentation:** Add API documentation
5. **Publishing:** Publish to npm and OpenClaw skill registry
