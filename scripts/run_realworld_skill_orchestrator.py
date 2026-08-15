#!/usr/bin/env python3
"""Compatibility entrypoint for the real-world SkillPulse/ProvLoom orchestrator."""

from __future__ import annotations

from scripts.run_realworld_skill_scan import main


if __name__ == "__main__":
    raise SystemExit(main())
