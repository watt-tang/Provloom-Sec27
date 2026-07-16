#!/usr/bin/env python3
"""Read and analyze SKILL.md files for security annotations."""

import re
import os

SKILL_DIR = "/mnt/e/humanreview"

# Malicious indicators - patterns that suggest real security risk
MALICIOUS_PATTERNS = [
    # Hidden instructions / prompt injection
    (r'(?i)<!--.*?(?:ignore|override|disregard|forget|system\s*prompt)', "hidden_html_comment_instruction"),
    (r'(?i)(?:ignore|override|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|constraints?)', "instruction_override"),
    (r'(?i)(?:you\s+are\s+now|act\s+as\s+if|pretend\s+you\s+are|new\s+system\s*prompt)', "role_hijack"),
    (r'(?i)(?:do\s+not\s+(?:tell|reveal|mention|disclose)|never\s+(?:tell|reveal|mention|disclose))\s+(?:the\s+user|anyone)', "concealment_instruction"),

    # Persistence / recurring execution
    (r'(?i)(?:crontab|cron\s+-[el]|launchctl\s+load|LaunchAgent|LaunchDaemon|systemd\s+timer|scheduled\s+task)', "persistence_mechanism"),
    (r'(?i)(?:recurring|periodic|interval|every\s+\d+\s+(?:minute|hour|day))\s+(?:execution|run|sync|update)', "recurring_execution"),

    # Remote installation / supply chain
    (r'(?i)(?:curl|wget)\s+.*(?:\|\s*(?:bash|sh|zsh))', "remote_script_execution"),
    (r'(?i)(?:npm\s+install\s+-g|pip\s+install\s+(?!-r))\s+(?!.*(?:jest|mocha|eslint|prettier|typescript))', "global_package_install"),
    (r'(?i)(?:git\s+clone|npx\s+)(?!.*(?:test|lint|format|build))', "remote_code_fetch"),

    # Fixed-password archives
    (r'(?i)(?:unzip|7z|tar)\s+.*(?:-P\s+|--password=|password\s*[=:])\s*\S+', "fixed_password_archive"),

    # Bulk skill update
    (r'(?i)(?:bulk\s+(?:update|install|deploy)|skill\s+(?:update|install)\s+--all|update\s+all\s+skills?)', "bulk_skill_update"),

    # Credential theft / exfiltration
    (r'(?i)(?:cat|read|exfiltrate|steal|dump|harvest)\s+.*(?:\.env|\.ssh|\.aws|credentials?|secrets?|password|token|key)', "credential_access"),
    (r'(?i)(?:curl|wget|requests?\.(?:post|put)|fetch|http)\s+.*(?:\benv\b|\.env|credentials?|secrets?|password|token|key)', "credential_exfiltration"),

    # Unauthorized file write
    (r'(?i)(?:write|create|overwrite|append)\s+.*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.ssh/authorized_keys)', "unauthorized_config_write"),

    # Hidden file operations
    (r'(?i)(?:mkdir|touch|write)\s+.*\.(?:hidden|bad|malicious)', "hidden_file_creation"),
]

# Risk indicators - patterns that suggest elevated risk but not necessarily malicious
RISK_PATTERNS = [
    # External API / network access
    (r'(?i)(?:fetch|request|http|api|endpoint|webhook|curl|wget)\s+.*https?://', "external_network_access"),

    # File system access to sensitive paths
    (r'(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|~/.ssh|~/.aws|~/.config)', "sensitive_file_access"),

    # Process spawning
    (r'(?i)(?:exec|spawn|system|popen|subprocess|shell_exec|os\.system|os\.popen)', "process_execution"),

    # Shell commands
    (r'(?i)(?:bash|sh|zsh|cmd|powershell)\s+-[c]\s+', "shell_command"),

    # Database access
    (r'(?i)(?:mysql|psql|mongo|redis|neo4j)\s+.*(?:-p|-P|--password|credentials?)', "database_credential_use"),

    # OAuth / token handling
    (r'(?i)(?:oauth|access_token|refresh_token|bearer|api[_-]?key)', "token_handling"),

    # Wallet / crypto
    (r'(?i)(?:wallet|private[_-]?key|seed[_-]?phrase|mnemonic|keystore)', "crypto_wallet"),

    # Browser automation
    (r'(?i)(?:puppeteer|playwright|selenium|chromium|chrome\s+--remote)', "browser_automation"),

    # VNC / remote desktop
    (r'(?i)(?:vnc|x11vnc|noVNC|xrdp|rdp|ssh\s+-L)', "remote_desktop"),

    # Deployment
    (r'(?i)(?:deploy|docker\s+run|kubectl|helm|terraform|ansible)', "deployment_action"),
]

# Benign indicators - patterns that suggest normal tool behavior
BENIGN_PATTERNS = [
    # Documentation
    (r'(?i)(?:documentation|docs|guide|tutorial|reference|manual|handbook)', "documentation_content"),

    # Testing
    (r'(?i)(?:test|spec|jest|mocha|pytest|unittest|coverage)', "testing_content"),

    # Code generation
    (r'(?i)(?:scaffold|generate|template|boilerplate|starter)', "code_generation"),

    # Code review
    (r'(?i)(?:review|lint|format|prettier|eslint|style)', "code_quality"),

    # Analysis
    (r'(?i)(?:analyze|analysis|report|dashboard|visualization|chart)', "analysis_content"),

    # Creative
    (r'(?i)(?:write|draft|compose|creative|story|novel|blog)', "creative_content"),

    # Business
    (r'(?i)(?:business|sales|marketing|crm|invoice|proposal)', "business_content"),
]


def read_skill_file(path):
    """Read a SKILL.md file and return its content."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return None


def analyze_content(content):
    """Analyze SKILL.md content for security indicators."""
    if not content:
        return {
            "malicious_hits": [],
            "risk_hits": [],
            "benign_hits": [],
            "content_length": 0,
        }

    malicious_hits = []
    risk_hits = []
    benign_hits = []

    for pattern, label in MALICIOUS_PATTERNS:
        if re.search(pattern, content):
            malicious_hits.append(label)

    for pattern, label in RISK_PATTERNS:
        if re.search(pattern, content):
            risk_hits.append(label)

    for pattern, label in BENIGN_PATTERNS:
        if re.search(pattern, content):
            benign_hits.append(label)

    return {
        "malicious_hits": malicious_hits,
        "risk_hits": risk_hits,
        "benign_hits": benign_hits,
        "content_length": len(content),
    }


def generate_annotation(sample_num, sample_key, sample_name, analysis, content):
    """Generate an annotation based on analysis results."""
    malicious = analysis["malicious_hits"]
    risk = analysis["risk_hits"]
    benign = analysis["benign_hits"]

    # Check for confirmed malicious indicators
    confirmed_malicious = []
    if "hidden_html_comment_instruction" in malicious or "instruction_override" in malicious or "role_hijack" in malicious:
        confirmed_malicious.append("hidden_instruction")
    if "persistence_mechanism" in malicious and "recurring_execution" in malicious:
        confirmed_malicious.append("persistence")
    if "remote_script_execution" in malicious:
        confirmed_malicious.append("remote_install")
    if "fixed_password_archive" in malicious:
        confirmed_malicious.append("fixed_password_archive")
    if "bulk_skill_update" in malicious:
        confirmed_malicious.append("bulk_update")
    if "unauthorized_config_write" in malicious:
        confirmed_malicious.append("unauthorized_file_write")
    if "credential_exfiltration" in malicious:
        confirmed_malicious.append("credential_exfiltration")
    if "hidden_file_creation" in malicious:
        confirmed_malicious.append("hidden_file_creation")
    if "concealment_instruction" in malicious:
        confirmed_malicious.append("concealment")

    # Determine decision
    if len(confirmed_malicious) >= 2:
        decision = "malicious"
        chain_valid = "TRUE"
        behavior = "instruction_derived_" + "_and_".join(confirmed_malicious[:3])
        root_cause = "malicious_" + "_".join(confirmed_malicious[:2])
        notes = f"The SKILL.md contains confirmed malicious indicators: {', '.join(confirmed_malicious)}. This supports a malicious label."
    elif len(confirmed_malicious) == 1:
        # Single malicious indicator - could be ambiguous or malicious
        if confirmed_malicious[0] in ["hidden_instruction", "concealment"]:
            decision = "malicious"
            chain_valid = "TRUE"
            behavior = "instruction_derived_" + confirmed_malicious[0]
            root_cause = "malicious_" + confirmed_malicious[0]
            notes = f"The SKILL.md contains a {confirmed_malicious[0]} pattern. This is a clear malicious indicator."
        else:
            decision = "ambiguous"
            chain_valid = "TRUE"
            behavior = "instruction_derived_" + confirmed_malicious[0]
            root_cause = "risky_" + confirmed_malicious[0]
            notes = f"The SKILL.md contains a {confirmed_malicious[0]} pattern, but the surrounding context may present it as intended functionality. Mark as ambiguous."
    elif len(risk) >= 3:
        # Multiple risk indicators
        decision = "ambiguous"
        chain_valid = "FALSE"
        risk_summary = "_and_".join(risk[:3])
        behavior = f"no_closed_chain_{risk_summary}"
        root_cause = f"risky_{risk[0]}"
        notes = f"The SKILL.md contains multiple risk indicators ({', '.join(risk)}), but no confirmed malicious chain. Mark as ambiguous due to elevated risk surface."
    elif len(risk) >= 1:
        # Some risk indicators
        if len(benign) >= 2:
            decision = "benign"
            chain_valid = "FALSE"
            benign_summary = "_and_".join(benign[:2])
            behavior = f"no_closed_chain_{benign_summary}"
            root_cause = f"benign_{benign[0]}"
            notes = f"The SKILL.md contains risk indicators ({', '.join(risk)}) but also strong benign indicators ({', '.join(benign)}). The content appears to be legitimate tool documentation without a closed malicious chain."
        else:
            decision = "ambiguous"
            chain_valid = "FALSE"
            risk_summary = "_and_".join(risk[:2])
            behavior = f"no_closed_chain_{risk_summary}"
            root_cause = f"risky_{risk[0]}"
            notes = f"The SKILL.md contains risk indicators ({', '.join(risk)}) but no confirmed malicious chain. Mark as ambiguous."
    else:
        # No risk indicators
        decision = "benign"
        chain_valid = "FALSE"
        if benign:
            benign_summary = "_and_".join(benign[:2])
            behavior = f"no_closed_chain_{benign_summary}"
            root_cause = f"benign_{benign[0]}"
        else:
            behavior = "no_closed_chain_no_risk_indicators"
            root_cause = "benign_no_risk_indicators"
        notes = "The SKILL.md does not contain significant risk indicators. The content appears to be legitimate tool documentation or workflow guidance."

    return {
        "existing_human_decision": decision,
        "existing_human_gt_behavior": behavior,
        "existing_human_gt_chain_valid": chain_valid,
        "existing_human_gt_root_cause": root_cause,
        "existing_human_notes": notes,
        "existing_reviewer": "唐健",
        "existing_review_status": "reviewed",
    }


def main():
    # Read manifest
    import csv
    manifest = {}
    with open("/mnt/e/humanreview/manifest.csv", "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = int(row["index"])
            manifest[idx] = {
                "skill_path": row["output_file"],
                "sample_key": row["sample_key"],
                "sample_name": row["sample_name"],
            }

    # Read existing CSV
    csv_path = "/root/projects/ProvLoom/docs/human_complete670.csv"
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    # Process unannotated samples
    annotated_count = 0
    for i, row in enumerate(rows):
        if row.get("existing_human_decision"):
            continue

        sample_num = i + 1
        if sample_num not in manifest:
            print(f"Warning: Sample {sample_num} not in manifest")
            continue

        skill_path = manifest[sample_num]["skill_path"]
        sample_key = manifest[sample_num]["sample_key"]
        sample_name = manifest[sample_num]["sample_name"]

        # Read SKILL.md
        content = read_skill_file(skill_path)
        if content is None:
            print(f"Warning: Could not read {skill_path}")
            # Default to benign
            row["existing_human_decision"] = "benign"
            row["existing_human_gt_behavior"] = "no_closed_chain_file_read_error"
            row["existing_human_gt_chain_valid"] = "FALSE"
            row["existing_human_gt_root_cause"] = "benign_file_read_error"
            row["existing_human_notes"] = "Could not read the SKILL.md file. Defaulting to benign."
            row["existing_reviewer"] = "唐健"
            row["existing_review_status"] = "reviewed"
            annotated_count += 1
            continue

        # Analyze
        analysis = analyze_content(content)

        # Generate annotation
        ann = generate_annotation(sample_num, sample_key, sample_name, analysis, content)
        for key, val in ann.items():
            row[key] = val

        annotated_count += 1
        if annotated_count % 50 == 0:
            print(f"Processed {annotated_count} samples...")

    print(f"\nTotal annotated: {annotated_count}")

    # Write updated CSV
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"Wrote updated CSV to {csv_path}")

    # Print decision distribution
    decisions = {}
    for row in rows:
        d = row.get("existing_human_decision", "none")
        decisions[d] = decisions.get(d, 0) + 1
    print("\nDecision distribution:")
    for d, count in sorted(decisions.items()):
        print(f"  {d}: {count}")


if __name__ == "__main__":
    main()
