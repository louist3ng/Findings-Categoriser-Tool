"""Entry point — argparse CLI, orchestrates the full workflow."""

import argparse
import os
import sys
import datetime

from config import load_config
from mobsf_client import MobSFClient
from classifier import load_third_party_prefixes, classify_findings, classify_obfuscated, _normalize_path
from llm_fallback import classify_with_llm
from utils import save_json


def parse_args():
    parser = argparse.ArgumentParser(
        description="Findings Categoriser — Upload APK to MobSF, scan, classify SAST findings, and view results."
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file to scan")
    parser.add_argument("--output", default="classified_findings.json", help="Output file path (default: classified_findings.json)")
    parser.add_argument("--prefixes", default=None, help="Path to custom third_party_prefixes YAML config file")
    parser.add_argument("--no-llm", action="store_true", help="Skip Layer 6 LLM fallback entirely")
    parser.add_argument("--llm-provider", choices=["anthropic", "gemini"], default=None,
                        help="LLM provider for Layer 6 fallback (default: auto-detect from available API keys)")
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
        print("Layer 6 LLM fallback disabled via --no-llm flag.")
    elif args.llm_provider == "gemini":
        if gemini_key:
            llm_provider = "gemini"
            llm_api_key = gemini_key
        else:
            print("GEMINI_API_KEY not set — Layer 6 LLM fallback disabled.")
    elif args.llm_provider == "anthropic":
        if anthropic_key:
            llm_provider = "anthropic"
            llm_api_key = anthropic_key
        else:
            print("ANTHROPIC_API_KEY not set — Layer 6 LLM fallback disabled.")
    else:
        # Auto-detect: prefer Anthropic, fall back to Gemini
        if anthropic_key:
            llm_provider = "anthropic"
            llm_api_key = anthropic_key
        elif gemini_key:
            llm_provider = "gemini"
            llm_api_key = gemini_key
        else:
            print("No LLM API key set (ANTHROPIC_API_KEY or GEMINI_API_KEY) — Layer 6 LLM fallback disabled.")

    llm_enabled = llm_provider is not None
    if llm_enabled:
        print(f"Layer 6 LLM fallback enabled (provider: {llm_provider}).")

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

    # Step 4-5: Classify findings
    print("\nClassifying findings...")
    third_party_prefixes = load_third_party_prefixes(args.prefixes)
    classified, unclassified = classify_findings(report, third_party_prefixes, verbose=args.verbose)

    # Layer 5: LLM fallback for unclassified findings
    if unclassified:
        print(f"{len(unclassified)} findings unclassified after Layers 1-4.")
        if llm_enabled:
            print(f"Running Layer 5 LLM fallback ({llm_provider})...")
            unclassified = classify_with_llm(
                unclassified, llm_api_key, provider=llm_provider, verbose=args.verbose
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
