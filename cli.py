"""Entry point — argparse CLI, orchestrates the full workflow."""

import argparse
import os
import sys
import datetime

from config import load_config
from mobsf_client import MobSFClient
from classifier import load_third_party_prefixes, classify_findings
from llm_fallback import classify_with_llm
from utils import save_json


def parse_args():
    parser = argparse.ArgumentParser(
        description="Findings Categoriser — Upload APK to MobSF, scan, classify SAST findings, and view results."
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file to scan")
    parser.add_argument("--output", default="classified_findings.json", help="Output file path (default: classified_findings.json)")
    parser.add_argument("--prefixes", default=None, help="Path to custom third_party_prefixes YAML config file")
    parser.add_argument("--no-llm", action="store_true", help="Skip Layer 4 LLM fallback entirely")
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

    # Determine LLM availability
    llm_enabled = not args.no_llm and bool(anthropic_key)
    if args.no_llm:
        print("Layer 4 LLM fallback disabled via --no-llm flag.")
    elif not anthropic_key:
        print("ANTHROPIC_API_KEY not set — Layer 4 LLM fallback disabled.")

    # Step 1-2: Upload APK to MobSF
    client = MobSFClient(config["mobsf_url"], config["mobsf_api_key"])
    file_hash = client.upload(args.apk)

    # Step 3: Trigger scan and poll
    client.scan(file_hash)
    report = client.poll_for_report(file_hash, timeout=args.timeout)

    if not report:
        print("Error: Failed to retrieve scan report.")
        sys.exit(1)

    # Step 4-5: Classify findings
    print("\nClassifying findings...")
    third_party_prefixes = load_third_party_prefixes(args.prefixes)
    classified, unclassified = classify_findings(report, third_party_prefixes, verbose=args.verbose)

    # Layer 4: LLM fallback for unclassified findings
    if unclassified:
        print(f"{len(unclassified)} findings unclassified after Layers 1-3.")
        if llm_enabled:
            print("Running Layer 4 LLM fallback...")
            unclassified = classify_with_llm(unclassified, anthropic_key, verbose=args.verbose)
        else:
            for f in unclassified:
                if args.no_llm:
                    f["classified_by"] = "skipped_no_api_key"
                elif not anthropic_key:
                    f["classified_by"] = "skipped_no_api_key"
                f["category"] = "unknown"
                f["confidence"] = "low"

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
