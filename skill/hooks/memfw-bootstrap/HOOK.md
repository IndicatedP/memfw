---
name: memfw-bootstrap
description: Injects memory protection protocol into agent bootstrap
metadata:
  emoji: "🛡️"
  events:
    - agent:bootstrap
  author: memfw
  version: "0.1.0"
---

# memfw Bootstrap Hook

This hook automatically injects the Memory Firewall protection protocol into your agent's SOUL.md during bootstrap.

## What It Does

On every `agent:bootstrap` event (before workspace files are injected), this hook:

1. Checks if SOUL.md exists in the workspace
2. Appends the memfw Memory Protection Protocol if not already present
3. Ensures your agent always scans content before writing to memory

## Installation

The hook is automatically installed when you set up the memfw skill:

```bash
# Copy hook to OpenClaw hooks directory
cp -r ~/.openclaw/workspace/skills/memfw/hooks/memfw-bootstrap ~/.openclaw/workspace/hooks/

# Enable the hook
openclaw hooks enable memfw-bootstrap
```

## Manual Override

If you need to disable memory protection for a session, you can:

```bash
openclaw hooks disable memfw-bootstrap
```

## How It Works

The agent receives instructions to run `memfw scan` before any memory write. This is instruction-based protection - the agent follows the protocol as part of its core behavior.
