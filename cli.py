"""Entry point — argparse CLI, orchestrates the full workflow."""

import argparse
import os
import sys
import datetime

from config import load_config
from mobsf_client import MobSFClient
from classifier import load_third_party_prefixes, classify_findings, classify_obfuscated, _normalize_path, extract_file_api_profiles
from llm_fallback import classify_with_llm
from utils import save_json


def parse_args():
    parser = argparse.ArgumentParser(
        description="Findings Categoriser — Upload APK to MobSF, scan, classify SAST findings, and view results."
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file to scan")
    parser.add_argument("--output", default="classified_findings.json", help="Output file path (default: classified_findings.json)")
    parser.add_argument("--prefixes", default=None, help="Path to custom third_party_prefixes YAML config file")
    parser.add_argument("--mapping", default=None, help="Path to R8/ProGuard mapping.txt file for de-obfuscation (restores original class names before classification)")
    parser.add_argument("--no-llm", action="store_true", help="Skip Layer 5 LLM fallback entirely (findings go straight to obfuscation heuristic)")
    parser.add_argument("--llm-provider", choices=["anthropic", "gemini"], default=None,
                        help="LLM provider for Layer 5 fallback (default: auto-detect from available API keys)")
    parser.add_argument("--verbose", action="store_true", help="Print classification decisions to stdout")
    parser.add_argument("--timeout", type=int, default=600, help="MobSF scan polling timeout in seconds (default: 600)")
    parser.add_argument("--no-browser", action="store_true", help="Skip auto-launching the browser")
    parser.add_argument("--port", type=int, default=5000, help="Port for the Flask web server (default: 5000)")
    return parser.parse_args()


def main():
    args = parse_args()

    # Validate APK path
    if not os.path.isfile(args.apk):
        print(f"Error: APK file not found: {args.apk}")
        sys.exit(1)

    # Load configuration
    config = load_config()
    anthropic_key = config["anthropic_api_key"]
    gemini_key = config["gemini_api_key"]

    # Determine LLM provider and availability
    llm_provider = None
    llm_api_key = None
    if args.no_llm:
        print("Layer 5 LLM fallback disabled via --no-llm flag.")
    elif args.llm_provider == "gemini":
        if gemini_key:
            llm_provider = "gemini"
            llm_api_key = gemini_key
        else:
            print("GEMINI_API_KEY not set — Layer 5 LLM fallback disabled.")
    elif args.llm_provider == "anthropic":
        if anthropic_key:
            llm_provider = "anthropic"
            llm_api_key = anthropic_key
        else:
            print("ANTHROPIC_API_KEY not set — Layer 5 LLM fallback disabled.")
    else:
        # Auto-detect: prefer Anthropic, fall back to Gemini
        if anthropic_key:
            llm_provider = "anthropic"
            llm_api_key = anthropic_key
        elif gemini_key:
            llm_provider = "gemini"
            llm_api_key = gemini_key
        else:
            print("No LLM API key set (ANTHROPIC_API_KEY or GEMINI_API_KEY) — Layer 5 LLM fallback disabled.")

    llm_enabled = llm_provider is not None
    if llm_enabled:
        print(f"Layer 5 LLM fallback enabled (provider: {llm_provider}).")

    # Step 1-2: Upload APK to MobSF
    client = MobSFClient(config["mobsf_url"], config["mobsf_api_key"])
    file_hash = client.upload(args.apk)

    # Step 3: Trigger scan (synchronous — blocks until done) then fetch report
    client.scan(file_hash, timeout=args.timeout)
    report = client.get_report(file_hash)

    if not report:
        print("Error: Failed to retrieve scan report.")
        sys.exit(1)

    # Save raw MobSF report for debugging
    raw_report_path = os.path.join(os.path.dirname(os.path.abspath(args.output)), "raw_mobsf_report.json")
    save_json(report, raw_report_path)
    print(f"Raw MobSF report saved to {raw_report_path}")

    # Load R8 mapping file if provided
    r8_mapping = None
    if args.mapping:
        if not os.path.isfile(args.mapping):
            print(f"Error: Mapping file not found: {args.mapping}")
            sys.exit(1)
        from r8_mapping import parse_mapping_file
        r8_mapping = parse_mapping_file(args.mapping)
        print(f"Loaded R8 mapping file: {len(r8_mapping)} class mappings from {args.mapping}")

    # Step 4-5: Classify findings
    print("\nClassifying findings...")
    third_party_prefixes = load_third_party_prefixes(args.prefixes)
    classified, unclassified = classify_findings(
        report, third_party_prefixes, verbose=args.verbose, r8_mapping=r8_mapping
    )

    # Extract per-file API/behaviour profiles for LLM context
    file_api_profiles = extract_file_api_profiles(report)
    if file_api_profiles:
        print(f"Extracted API/behaviour profiles for {len(file_api_profiles)} files.")

    # Extract app context for LLM
    app_package = report.get("package_name", "")
    manifest_count = sum(
        len(report.get(k, []))
        for k in ("activities", "services", "receivers", "providers")
    )

    # Layer 5: LLM fallback for unclassified findings
    if unclassified:
        print(f"{len(unclassified)} findings unclassified after Layers 1-4.")
        if llm_enabled:
            print(f"Running Layer 5 LLM fallback ({llm_provider})...")
            unclassified = classify_with_llm(
                unclassified, llm_api_key, provider=llm_provider,
                verbose=args.verbose, file_api_profiles=file_api_profiles,
                app_package=app_package, manifest_count=manifest_count,
            )

    # Layer 6: Obfuscation heuristic — tag remaining unknown/failed findings
    for f in unclassified:
        if f["category"] == "unknown":
            norm_path = _normalize_path(f.get("file_path", ""))
            result = classify_obfuscated(norm_path)
            if result:
                f.update(result)

    all_findings = classified + unclassified

    # Step 6: Save results
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_data = {
        "metadata": {
            "apk_filename": os.path.basename(args.apk),
            "file_hash": file_hash,
            "scan_date": scan_date,
            "total_findings": len(all_findings),
            "r8_mapping": os.path.basename(args.mapping) if args.mapping else None,
            "llm_enabled": llm_enabled,
        },
        "findings": all_findings,
    }

    output_path = os.path.abspath(args.output)
    save_json(output_data, output_path)

    # Print summary
    categories = {}
    for f in all_findings:
        cat = f.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
    print(f"\nClassification summary ({len(all_findings)} total findings):")
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")

    # Step 7: Launch web UI
    print("\nStarting web server...")
    from web.app import launch_server
    launch_server(output_path, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
