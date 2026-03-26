"""Layer 6 — LLM fallback for ambiguous/obfuscated file paths (optional).

Supports multiple LLM providers: Anthropic (Claude) and Google (Gemini).
"""

import json
from classifier import is_obfuscated_path, _normalize_path
from utils import log_verbose

# Shared prompt template used by all providers
_PROMPT_TEMPLATE = (
    "You are an Android APK analysis expert. Classify the following finding "
    "from a decompiled Android APK.\n\n"
    "File path: '{file_path}'\n"
    "Severity: {severity}\n"
    "CWE: {cwe}\n"
    "Description: {description}\n"
    "Path appears obfuscated: {is_obfuscated}\n\n"
    "Classify as one of: app_code, third_party, android_code, obfuscated_unknown.\n"
    "If the path is obfuscated, consider whether this vulnerability type "
    "typically appears in app code vs library code based on the CWE and description.\n"
    'Reply in JSON only:\n'
    '{{"category": "...", "confidence": "high|medium|low", "reason": "..."}}'
)


def classify_with_llm(unclassified_findings, api_key, provider="anthropic",
                      verbose=False):
    """Attempt to classify unclassified findings using an LLM provider.

    Args:
        unclassified_findings: List of finding dicts to classify.
        api_key: API key for the chosen provider.
        provider: "anthropic" or "gemini".
        verbose: Print classification decisions.

    Returns the findings list with updated classification fields.
    """
    if not api_key:
        for finding in unclassified_findings:
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "skipped_no_api_key"
        return unclassified_findings

    try:
        client = _init_client(provider, api_key)
    except Exception as e:
        print(f"Warning: Failed to initialize {provider} client: {e}")
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
            prompt = _build_prompt(
                file_path,
                severity=finding.get("severity", ""),
                cwe=finding.get("cwe", ""),
                description=finding.get("description", ""),
                is_obfuscated=is_obfuscated_path(norm_path),
            )
            result = _call_llm(client, provider, prompt)
            finding["category"] = result.get("category", "unknown")
            finding["confidence"] = result.get("confidence", "low")
            finding["classified_by"] = f"llm_fallback_{provider}"
            finding["llm_reason"] = result.get("reason", "")
            log_verbose(f"  -> {finding['category']} ({finding['confidence']})", verbose)
        except Exception as e:
            log_verbose(f"  LLM error: {e}", verbose)
            finding["category"] = "unknown"
            finding["confidence"] = "low"
            finding["classified_by"] = "llm_error"

    return unclassified_findings


def _init_client(provider, api_key):
    """Initialize the LLM client for the given provider."""
    if provider == "gemini":
        from google import genai
        client = genai.Client(api_key=api_key)
        return client
    else:
        import anthropic
        return anthropic.Anthropic(api_key=api_key)


def _build_prompt(file_path, severity="", cwe="", description="",
                  is_obfuscated=False):
    """Build the classification prompt with full vulnerability context."""
    return _PROMPT_TEMPLATE.format(
        file_path=file_path,
        severity=severity,
        cwe=cwe,
        description=description,
        is_obfuscated=is_obfuscated,
    )


def _call_llm(client, provider, prompt):
    """Call the LLM API and parse the JSON response."""
    if provider == "gemini":
        text = _call_gemini(client, prompt)
    else:
        text = _call_anthropic(client, prompt)

    return _parse_response(text)


def _call_anthropic(client, prompt):
    """Call Claude API and return the raw text response."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text.strip()


def _call_gemini(client, prompt):
    """Call Gemini API and return the raw text response."""
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return response.text.strip()


def _parse_response(text):
    """Parse and validate the JSON response from any LLM provider."""
    # Handle cases where response is wrapped in markdown code blocks
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1])

    result = json.loads(text)

    valid_categories = {"app_code", "third_party", "android_code", "obfuscated_unknown"}
    if result.get("category") not in valid_categories:
        result["category"] = "unknown"

    valid_confidence = {"high", "medium", "low"}
    if result.get("confidence") not in valid_confidence:
        result["confidence"] = "low"

    return result
