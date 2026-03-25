"""Classification engine — Layers 1, 2, 3 (rule-based, whitelist, package inference)."""

import os
import yaml
from collections import Counter
from utils import log_verbose

# Layer 1: Android/platform prefixes
ANDROID_PREFIXES = (
    "android/",
    "java/",
    "javax/",
    "dalvik/",
    "kotlin/",
    "kotlinx/",
    "libcore/",
    "sun/",
    "org/xml/",
    "org/json/",
    "org/w3c/",
)


def load_third_party_prefixes(config_path=None):
    """Load third-party prefixes from a YAML config file."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "third_party_prefixes.yaml")

    if not os.path.isfile(config_path):
        print(f"Warning: Third-party prefixes file not found: {config_path}")
        return []

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return tuple(data.get("prefixes", []))


def classify_layer1(file_path):
    """Layer 1: Android code detection via known prefixes."""
    for prefix in ANDROID_PREFIXES:
        if file_path.startswith(prefix):
            return {
                "category": "android_code",
                "confidence": "high",
                "classified_by": "android_prefix",
            }
    return None


def classify_layer2(file_path, third_party_prefixes):
    """Layer 2: Third-party code detection via whitelist."""
    for prefix in third_party_prefixes:
        if file_path.startswith(prefix):
            return {
                "category": "third_party",
                "confidence": "high",
                "classified_by": "third_party_whitelist",
            }
    return None


def infer_app_package(report, third_party_prefixes):
    """Infer the app's root package from the MobSF report.

    Strategy:
    1. Try to extract package name from AndroidManifest.xml data in the report.
    2. Fall back to frequency analysis of file paths.

    Returns (package_prefix, confidence) where confidence is "high" or "medium".
    """
    # Strategy 1: Extract from manifest
    package_name = report.get("package_name") or report.get("packagename")
    if package_name:
        package_prefix = package_name.replace(".", "/") + "/"
        return package_prefix, "high"

    # Strategy 2: Frequency analysis of file paths
    all_paths = _collect_file_paths(report)
    if not all_paths:
        return None, None

    # Collect top-level package segments (first 2-3 segments like com/example/app)
    package_counts = Counter()
    for path in all_paths:
        parts = path.split("/")
        if len(parts) < 3:
            continue
        # Build candidate package: first 3 segments (e.g. com/example/myapp)
        candidate = "/".join(parts[:3]) + "/"

        # Skip if matches Android or third-party prefixes
        if any(candidate.startswith(p) for p in ANDROID_PREFIXES):
            continue
        if any(candidate.startswith(p) for p in third_party_prefixes):
            continue

        package_counts[candidate] += 1

    if not package_counts:
        return None, None

    top_package, top_count = package_counts.most_common(1)[0]
    total = sum(package_counts.values())

    # High confidence if this package accounts for >30% of paths
    confidence = "high" if (top_count / total) > 0.3 else "medium"
    return top_package, confidence


def classify_layer3(file_path, app_package, package_confidence):
    """Layer 3: App code detection via inferred package name."""
    if app_package and file_path.startswith(app_package):
        return {
            "category": "app_code",
            "confidence": package_confidence,
            "classified_by": "inferred_app_package",
        }
    return None


def _collect_file_paths(report):
    """Extract all file paths from the code_analysis.findings section."""
    paths = set()
    code_analysis = report.get("code_analysis", {})
    if not isinstance(code_analysis, dict):
        return paths
    findings = code_analysis.get("findings", {})
    if not isinstance(findings, dict):
        return paths
    for rule_id, rule_data in findings.items():
        if not isinstance(rule_data, dict):
            continue
        files_dict = rule_data.get("files", {})
        if isinstance(files_dict, dict):
            for file_path in files_dict.keys():
                paths.add(_normalize_path(file_path))
    return paths


def _normalize_path(path):
    """Normalize a file path for comparison."""
    # Strip leading slashes and smali/java prefixes
    path = path.lstrip("/")
    # Remove common decompiler prefixes
    for prefix in ("smali/", "smali_classes2/", "smali_classes3/",
                    "sources/", "java/"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    return path


def classify_findings(report, third_party_prefixes, verbose=False):
    """Classify all findings from the code_analysis section of a MobSF report.

    Only processes code_analysis.findings — skips summary and other sections.

    MobSF code_analysis structure:
        code_analysis:
          findings:
            rule_id:
              files: { "com/example/Foo.java": "12,34", ... }
              metadata: { cvss, cwe, masvs, owasp-mobile, ref, description, severity, ... }
          summary:
            high: N, warning: N, ...

    Returns (classified, unclassified) lists of annotated finding dicts.
    """
    classified = []
    unclassified = []

    # Infer app package (Layer 3 prep)
    app_package, pkg_confidence = infer_app_package(report, third_party_prefixes)
    if app_package:
        print(f"Inferred app package: {app_package} (confidence: {pkg_confidence})")
    else:
        print("Warning: Could not infer app package name.")

    # Only process code_analysis → findings
    code_analysis = report.get("code_analysis", {})
    if not isinstance(code_analysis, dict):
        print("Warning: code_analysis section not found or invalid.")
        return classified, unclassified

    findings_dict = code_analysis.get("findings", {})
    if not isinstance(findings_dict, dict):
        print("Warning: code_analysis.findings not found or invalid.")
        return classified, unclassified

    for rule_id, rule_data in findings_dict.items():
        if not isinstance(rule_data, dict):
            continue

        metadata = rule_data.get("metadata", {})
        severity = metadata.get("severity", "info")
        cwe = metadata.get("cwe", "")
        cvss = metadata.get("cvss", "")
        description = metadata.get("description", "")
        masvs = metadata.get("masvs", "")
        owasp = metadata.get("owasp-mobile", "")
        ref = metadata.get("ref", "")

        # MobSF files format: { "com/example/Foo.java": "12,34", ... }
        files_dict = rule_data.get("files", {})
        if not isinstance(files_dict, dict) or not files_dict:
            # Finding with no file paths
            finding = {
                "file_path": "",
                "line_numbers": "",
                "vuln_name": rule_id,
                "severity": severity,
                "cwe": cwe,
                "cvss": cvss,
                "description": description,
                "masvs": masvs,
                "owasp_mobile": owasp,
                "ref": ref,
                "section": "code_analysis",
                "category": "unknown",
                "confidence": "low",
                "classified_by": "no_file_path",
                "llm_reason": "",
            }
            classified.append(finding)
            continue

        for file_path, line_numbers in files_dict.items():
            norm_path = _normalize_path(file_path)
            finding = {
                "file_path": file_path,
                "line_numbers": str(line_numbers) if line_numbers else "",
                "vuln_name": rule_id,
                "severity": severity,
                "cwe": cwe,
                "cvss": cvss,
                "description": description,
                "masvs": masvs,
                "owasp_mobile": owasp,
                "ref": ref,
                "section": "code_analysis",
                "llm_reason": "",
            }

            # Layer 1
            result = classify_layer1(norm_path)
            if result:
                finding.update(result)
                log_verbose(f"L1 android_code: {file_path}", verbose)
                classified.append(finding)
                continue

            # Layer 2
            result = classify_layer2(norm_path, third_party_prefixes)
            if result:
                finding.update(result)
                log_verbose(f"L2 third_party: {file_path}", verbose)
                classified.append(finding)
                continue

            # Layer 3
            result = classify_layer3(norm_path, app_package, pkg_confidence)
            if result:
                finding.update(result)
                log_verbose(f"L3 app_code: {file_path}", verbose)
                classified.append(finding)
                continue

            # Unclassified — needs Layer 4 or fallback
            finding.update({
                "category": "unknown",
                "confidence": "low",
                "classified_by": "pending_layer4",
            })
            unclassified.append(finding)
            log_verbose(f"Unclassified: {file_path}", verbose)

    return classified, unclassified
