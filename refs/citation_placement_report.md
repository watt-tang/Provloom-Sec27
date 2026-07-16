# Citation Placement Report

Generated on 2026-05-13.

## Introduction

- Added agent/runtime-action background citations near the opening sentence: `injecagent2024`, `asb2024`, `ipiguard2025`.
- Added prompt-injection and unsafe-tool-selection citations directly after the system-behavior claim: `liu2024promptinjection`, `greshake2023notwhat`, `injecagent2024`, `toolhijacker2026`.
- Added skill-packaging and skill-ecosystem citations next to the sentence about instructions, local artifacts, helper scripts, and metadata: `skillscan2026`, `skillfortify2026`, `agentaudit2026`.
- Added supply-chain and setup-risk citations in the setup/maintenance paragraph: `ohm2020backstabber`, `zimmermann2019smallworld`, `duan2020packagemanager`, `torresarias2019intoto`, `skillfortify2026`, `agentaudit2026`.
- Added scanner, provenance, and static-analysis comparison citations close to the specific capability/limitation claims: `skillscan2026`, `skillfortify2026`, `agentaudit2026`, `ciscoSkillScanner2026`, `clawvet2026`, `hossain2017sleuth`, `hassan2019nodoze`, `pasquier2018camquery`, `han2020unicorn`, `cheng2024kairos`, `yama2014cpg`, `tripp2009taj`, `livshits2005static`, `sui2016svf`.
- Left the benchmark description and contribution bullets mostly uncited because they are the paper's own scope statement, dataset description, and contribution claims.

## Problem Definition / Threat Model

- Added citations for attacker control over skill content: `skillscan2026`, `skillfortify2026`, `agentaudit2026`.
- Added citations for LLM-mediated tool-selection manipulation and indirect prompt injection: `liu2024promptinjection`, `greshake2023notwhat`, `injecagent2024`, `toolhijacker2026`.
- Added citations for installation, package-manager, remote-script, persistence, and global-state threats: `ohm2020backstabber`, `duan2020packagemanager`, `zimmermann2019smallworld`, `torresarias2019intoto`.
- Added citations for runtime threat mechanisms and latent instruction-derived paths: `injecagent2024`, `asb2024`, `toolhijacker2026`, `agentaudit2026`, `skillfortify2026`, `hossain2017sleuth`, `hassan2019nodoze`.
- Left the formal task definition paragraph uncited because it defines this paper's analysis task and output contract.

## Design

- Added provenance-method citations to LoomCore, telemetry normalization, and EPG paragraphs: `pasquier2018camquery`, `hossain2017sleuth`, `han2020unicorn`, `cheng2024kairos`.
- Added attack-path reconstruction citations to observed primary-chain reconstruction: `king2005backtracking`, `hossain2017sleuth`, `gao2018aiql`, `ma2016protracer`, `ji2017rain`.
- Added setup-time and supply-chain citations to instruction-level provenance recovery: `ohm2020backstabber`, `duan2020packagemanager`, `zimmermann2019smallworld`, `torresarias2019intoto`, `skillfortify2026`, `agentaudit2026`.
- Added alert-triage and scanner-comparison citations to evidence-typed decision logic: `hassan2019nodoze`, `hossain2017sleuth`, `skillscan2026`, `agentaudit2026`, `skillfortify2026`.
- Left algorithm steps and paper-specific heuristics uncited because they describe ProvLoom's own design choices rather than prior art claims.

## Evaluation

- Added benchmark-background citations in `Setup and Scope`: `liu2024promptinjection`, `asb2024`, `injecagent2024`.
- Updated SkillScan baseline citations to the new key `skillscan2026` and placed them on the baseline-description sentence.
- Added external-positioning citations around the comparison of static tools, ToolHijacker, and host provenance systems: `skillscan2026`, `agentaudit2026`, `toolhijacker2026`, `pasquier2018camquery`, `hossain2017sleuth`, `hassan2019nodoze`, `cheng2024kairos`.
- Added static-indicator versus chain-evidence citations: `yama2014cpg`, `tripp2009taj`, `livshits2005static`, `sui2016svf`, `skillscan2026`.
- Added runtime-provenance cost/benefit citations: `pasquier2018camquery`, `hossain2017sleuth`, `hassan2019nodoze`, `cheng2024kairos`.
- Added external scanner/software artifact citations in the real-world comparison section: `skillscan2026`, `agentaudit2026`, `skillfortify2026`, `ciscoSkillScanner2026`, `clawvet2026`, `toolhijacker2026`, `syedabbastSkillScanner2026`.
- Left benchmark metric values, case-study outputs, threshold counts, manual annotation totals, and the paper's own interpretation of those results uncited because they are this paper's empirical results.

## Related Work

- Rewrote the section into five subsections:
  - `Agent and Skill Security`
  - `Prompt Injection and Tool-Mediated Attacks`
  - `Software Supply Chain and Setup-Time Risk`
  - `System Provenance and Attack Reconstruction`
  - `Static Analysis and Source-to-Sink Security Reasoning`
- Added agent/skill ecosystem citations: `skillscan2026`, `agentaudit2026`, `asb2024`, `skillfortify2026`, `ciscoSkillScanner2026`, `clawvet2026`, `injecagent2024`, `toolhijacker2026`, `ipiguard2025`.
- Added prompt-injection and jailbreak citations: `liu2024promptinjection`, `greshake2023notwhat`, `injecagent2024`, `toolhijacker2026`, `ipiguard2025`, `zou2023universal`, `wei2023jailbroken`, `gradsafe2024`.
- Added software-supply-chain citations: `ohm2020backstabber`, `zimmermann2019smallworld`, `duan2020packagemanager`, `torresarias2019intoto`, `skillfortify2026`, `agentaudit2026`.
- Added provenance and attack-reconstruction citations: `king2005backtracking`, `hossain2017sleuth`, `hassan2019nodoze`, `pasquier2018camquery`, `han2020unicorn`, `gao2018aiql`, `ma2016protracer`, `cheng2024kairos`, `xie2020pagoda`, `ji2017rain`.
- Added static-analysis citations: `yama2014cpg`, `tripp2009taj`, `livshits2005static`, `sui2016svf`.
- Left the final ProvLoom-difference sentences mostly uncited when they only state the paper's own positioning claim.

## Not Added on Purpose

- I did not add external citations to contribution statements, benchmark numbers, table values, or the paper's own claims about what ProvLoom proposes, implements, or measures.
- I did not cite Cisco AI Defense Skill Scanner or ClawVet as papers; both are treated as software artifacts.
- I kept wording around `Agent Audit`, `SkillScan`, and `SkillFortify` conservative in places where they are recent preprints or recent work rather than established conference papers.

## Literature Not Used or Used with Caution

- No requested paper was dropped entirely from the target sections. Every requested research item now appears in the manuscript, except that the two GitHub artifacts are cited only where software artifacts make sense.
- `xie2020pagoda` and `tripp2009taj` are used with caution because the provided direct PDF links failed. Their BibTeX metadata was confirmed conservatively from authority index/landing pages, and that limitation is also recorded in `refs/download_report.md`.
