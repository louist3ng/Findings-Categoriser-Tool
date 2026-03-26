"""Layer 6 — LLM fallback for ambiguous/obfuscated file paths (optional)."""

import json
from classifier import is_obfuscated_path, _normalize_path
from utils import log_verbose


def classify_with_llm(unclassified_findings, anthropic_api_key, verbose=False):
    """Attempt to classify unclassified findings using Claude API.

    If anthropic_api_key is None or empty, marks all as skipped.
    Returns the findings list with updated classification fields.
    """
    if not anthropic_api_key:
        for finding in unclassified_findings:
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "skipped_no_api_key"
        return unclassified_findings

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=anthropic_api_key)
    except Exception as e:
        print(f"Warning: Failed to initialize Anthropic client: {e}")
        for finding in unclassified_findings:
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "llm_error"
        return unclassified_findings

    total = len(unclassified_findings)
    for i, finding in enumerate(unclassified_findings):
        file_path = finding.get("file_path", "")
        if not file_path:
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "no_file_path"
            continue

        log_verbose(f"LLM classifying ({i+1}/{total}): {file_path}", verbose)

        try:
            norm_path = _normalize_path(file_path)
            result = _call_llm(
                client,
                file_path,
                severity=finding.get("severity", ""),
                cwe=finding.get("cwe", ""),
                description=finding.get("description", ""),
                is_obfuscated=is_obfuscated_path(norm_path),
            )
            finding["category"] = result.get("category", "unknown")
            finding["confidence"] = result.get("confidence", "low")
            finding["classified_by"] = "llm_fallback"
            finding["llm_reason"] = result.get("reason", "")
            log_verbose(f"  -> {finding['category']} ({finding['confidence']})", verbose)
        except Exception as e:
            log_verbose(f"  LLM error: {e}", verbose)
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "llm_error"

    return unclassified_findings


def _call_llm(client, file_path, severity="", cwe="", description="",
              is_obfuscated=False):
    """Call Claude API to classify a single file path with full vulnerability context."""
    prompt = (
        f"You are an Android APK analysis expert. Classify the following finding "
        f"from a decompiled Android APK.\n\n"
        f"File path: '{file_path}'\n"
        f"Severity: {severity}\n"
        f"CWE: {cwe}\n"
        f"Description: {description}\n"
        f"Path appears obfuscated: {is_obfuscated}\n\n"
        f"Classify as one of: app_code, third_party, android_code, obfuscated_unknown.\n"
        f"If the path is obfuscated, consider whether this vulnerability type "
        f"typically appears in app code vs library code based on the CWE and description.\n"
        f'Reply in JSON only:\n'
        f'{{"category": "...", "confidence": "high|medium|low", "reason": "..."}}'
    )

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )

    text = response.content[0].text.strip()
    # Parse JSON from the response — handle cases where it's wrapped in markdown
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1])

    result = json.loads(text)

    # Validate category
    valid_categories = {"app_code", "third_party", "android_code", "obfuscated_unknown"}
    if result.get("category") not in valid_categories:
        result["category"] = "unknown"

    valid_confidence = {"high", "medium", "low"}
    if result.get("confidence") not in valid_confidence:
        result["confidence"] = "low"

    return result
