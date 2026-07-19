from __future__ import annotations


def review_priority(chain_status: str, chain_type: str, evidence_levels: list[str], modalities: list[str], unresolved_links: list[str], external_endpoint: bool) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if chain_status == "closed":
        reasons.append(f"Closed instruction-derived {chain_type} path has continuous typed evidence.")
    if external_endpoint:
        reasons.append("The sink endpoint is external or not allowlisted.")
    if unresolved_links:
        reasons.append(f"Unresolved or ambiguous links remain: {', '.join(unresolved_links)}.")
    if any(modality in {"conditional", "optional"} for modality in modalities):
        reasons.append("The path is gated by optional or conditional modality.")
    if any(modality in {"prohibited", "example_only", "hypothetical", "quoted_untrusted"} for modality in modalities):
        return "informational", reasons + ["Suppressed modality prevents a closed executable static path."]
    if chain_status == "closed" and chain_type in {"credential_exfiltration", "dropper_multistage_execution"} and external_endpoint and not unresolved_links:
        return "critical", reasons
    if chain_status == "closed":
        return "high", reasons
    if chain_status in {"partial", "uncertain"}:
        return "medium", reasons or ["Partial or uncertain static path requires review."]
    if chain_status == "isolated":
        return "low", reasons or ["Only isolated security-relevant actions were found."]
    return "informational", reasons or ["No supported static path was formed; this is not a safety verdict."]
