# TinyClaw

> Local-first information triage desk. One binary. No cloud.

A lightweight local-first triage desk built with Rust. It brings email, news, and AI chat into one workspace, all running locally in under 50MB of RAM.

**Website**: [tinyclaw.net](https://tinyclaw.net)

## Download

### Pre-built Binaries

| Platform | File | Minimum OS |
|----------|------|------------|
| macOS (Apple Silicon) | [Download](../../releases/latest) | macOS 11+ |
| macOS (Intel) | [Download](../../releases/latest) | macOS 11+ |
| Windows (x64) | [Download](../../releases/latest) | Windows 10+ |
| Linux (x64) | [Download](../../releases/latest) | glibc 2.31+ (Ubuntu 20.04+, Debian 11+) |

All releases are published on the [Releases](../../releases) page.

### Quick Install

```bash
# macOS / Linux
curl -fsSL https://tinyclaw.net/install.sh | sh

# Or download directly from Releases
```

## Features

- **Today Briefing** — Open TinyClaw and see what matters first across cached email and news
- **Email Workspace** — IMAP read + SMTP send, plus local triage and detail view for recent mail
- **News Workspace** — Subscribe to feeds, cache unread stories, and let AI help you read deeper
- **AI Chat** — Streaming responses, multi-provider, tool invocation. Built-in model works out of the box — no API key required
- **Skill System** — OpenClaw-compatible, drop a `SKILL.md` and it works
- **Feishu Bot** — WebSocket connection, no public IP needed
- **Built-in Web UI** — Setup, Today, email, news, chat, skills, settings
- **~12MB Binary** — Runs on Raspberry Pi, old laptops, anything

## Quick Start

```bash
# 1. Download the binary for your platform
# 2. Run it
./tinyclaw

# 3. Open http://localhost:3198
```

That's it. No Docker, no cloud, no config required to start.

## Resource Usage

| Metric | Value |
|--------|-------|
| Binary Size | ~12 MB |
| Runtime RAM | ~40 MB |
| Startup Time | < 1 second |
| Dependencies | Zero |

## License

This repository (website + docs) is MIT licensed.

The TinyClaw core engine is proprietary. See the [website](https://tinyclaw.net) for details.

## Links

- [Website](https://tinyclaw.net)
- [Releases](../../releases)
- [Issues](../../issues)
- [Core Repository](https://github.com/momo2029/tinyclaw) (private)
