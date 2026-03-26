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
    "App package name: {app_package}\n"
    "App manifest components: {manifest_count} (activities, services, receivers, providers)\n"
    "File path: '{file_path}'\n"
    "Vulnerability rule: {vuln_name}\n"
    "Severity: {severity}\n"
    "CVSS: {cvss}\n"
    "CWE: {cwe}\n"
    "OWASP Mobile: {owasp_mobile}\n"
    "MASVS: {masvs}\n"
    "Description: {description}\n"
    "Path appears obfuscated: {is_obfuscated}\n"
    "{api_profile_context}"
    "{sibling_context}\n"
    "Classify as one of: app_code, third_party, android_code, obfuscated_unknown.\n\n"
    "IMPORTANT context for obfuscated paths:\n"
    "- The app has {manifest_count} manifest components. A small app (< 10 components) "
    "typically has only a few source files — most obfuscated code is bundled "
    "third-party libraries (AndroidX, Jetpack, etc.) that were minified by R8.\n"
    "- Only classify as app_code if there is strong evidence the file belongs to "
    "the app itself (e.g. path matches app package, or the vulnerability is clearly "
    "app-specific like hardcoded secrets in app-specific storage).\n"
    "- AndroidX/Jetpack libraries (obfuscated to e/, k/, z/, s/, etc.) commonly "
    "trigger logging, reflection, and system service findings — these are third_party, "
    "not app_code.\n"
    "- API profiles like api_get_system_service, api_java_reflection, api_dexloading, "
    "api_clipboard are typical of AndroidX framework libraries.\n"
    "- When in doubt about an obfuscated path, prefer obfuscated_unknown over "
    "guessing app_code.\n\n"
    "Other considerations:\n"
    "- If sibling files are shown, use them to identify the package's origin.\n"
    "- Behaviour descriptions provide high-level intent.\n"
    "- The vulnerability rule name and CWE can reveal app-specific vs library patterns.\n\n"
    'Reply in JSON only:\n'
    '{{"category": "...", "confidence": "high|medium|low", "reason": "..."}}'
)


def classify_with_llm(unclassified_findings, api_key, provider="anthropic",
                      verbose=False, file_api_profiles=None,
                      app_package="", manifest_count=0):
    """Attempt to classify unclassified findings using an LLM provider.

    Args:
        unclassified_findings: List of finding dicts to classify.
        api_key: API key for the chosen provider.
        provider: "anthropic" or "gemini".
        verbose: Print classification decisions.
        file_api_profiles: Optional dict mapping file paths to lists of
                           API/behaviour strings from the MobSF report.
        app_package: The app's package name (e.g. "com.example.myapp").
        manifest_count: Number of manifest components (activities + services +
                        receivers + providers) — helps LLM gauge app size.

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

    # Pre-build sibling lookup: vuln_name → list of file paths
    from collections import defaultdict
    siblings = defaultdict(list)
    for f in unclassified_findings:
        vn = f.get("vuln_name", "")
        fp = f.get("file_path", "")
        if vn and fp:
            siblings[vn].append(fp)

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
            vuln_name = finding.get("vuln_name", "")
            # Sibling paths: other files under the same rule (excluding self)
            sibling_paths = [p for p in siblings.get(vuln_name, []) if p != file_path]
            # API/behaviour profile for this file
            api_profile = None
            if file_api_profiles:
                api_profile = file_api_profiles.get(file_path)
            prompt = _build_prompt(
                file_path,
                severity=finding.get("severity", ""),
                cwe=finding.get("cwe", ""),
                description=finding.get("description", ""),
                is_obfuscated=is_obfuscated_path(norm_path),
                vuln_name=vuln_name,
                cvss=finding.get("cvss", ""),
                owasp_mobile=finding.get("owasp_mobile", ""),
                masvs=finding.get("masvs", ""),
                sibling_paths=sibling_paths if sibling_paths else None,
                api_profile=api_profile,
                app_package=app_package,
                manifest_count=manifest_count,
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
                  is_obfuscated=False, vuln_name="", cvss="", owasp_mobile="",
                  masvs="", sibling_paths=None, api_profile=None,
                  app_package="", manifest_count=0):
    """Build the classification prompt with full vulnerability context.

    Args:
        sibling_paths: Optional list of other file paths flagged under the same
                       vulnerability rule.  Helps the LLM identify package patterns.
        api_profile: Optional list of API/behaviour strings for this file from
                     the MobSF report (e.g. ["api_http_connection",
                     "behaviour:Connect to a URL"]).
        app_package: The app's package name for context.
        manifest_count: Number of manifest components to indicate app size.
    """
    api_profile_context = ""
    if api_profile:
        apis = [a for a in api_profile if not a.startswith("behaviour:")]
        behaviours = [a.replace("behaviour:", "") for a in api_profile if a.startswith("behaviour:")]
        parts = []
        if apis:
            parts.append("Android APIs used: " + ", ".join(apis))
        if behaviours:
            parts.append("Behaviours detected: " + ", ".join(behaviours))
        api_profile_context = "\n".join(parts) + "\n"

    sibling_context = ""
    if sibling_paths:
        # Show up to 10 siblings for context, truncate to keep prompt small
        shown = sibling_paths[:10]
        sibling_context = (
            f"Other files flagged under the same rule ({len(sibling_paths)} total):\n"
            + "\n".join(f"  - {p}" for p in shown)
        )
        if len(sibling_paths) > 10:
            sibling_context += f"\n  ... and {len(sibling_paths) - 10} more"
        sibling_context += "\n"

    return _PROMPT_TEMPLATE.format(
        file_path=file_path,
        severity=severity,
        cwe=cwe,
        description=description,
        is_obfuscated=is_obfuscated,
        vuln_name=vuln_name,
        cvss=cvss,
        owasp_mobile=owasp_mobile,
        masvs=masvs,
        sibling_context=sibling_context,
        api_profile_context=api_profile_context,
        app_package=app_package or "unknown",
        manifest_count=manifest_count,
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
