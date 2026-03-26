# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Python CLI tool that scans Android APKs using MobSF (Mobile Security Framework), then classifies the resulting findings into categories (Android platform code, third-party libraries, app code, or obfuscated) using a 6-layer waterfall classification engine. Handles both debug and R8/ProGuard-obfuscated APKs. Results are displayed in a Flask web dashboard with Chart.js visualizations.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the tool (APK required)
python cli.py --apk path/to/app.apk

# Run with common options
python cli.py --apk app.apk --output results.json --no-llm --verbose --port 8080

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_classifier.py -v

# Run a single test
python -m pytest tests/test_classifier.py::TestClassName::test_name -v
```

## Architecture

**Pipeline flow:** Upload APK → MobSF scan → Fetch report → Classify findings → Save JSON → Launch web UI

### Classification Layers (waterfall — each layer processes only unclassified remainders)

| Layer | File | Logic |
|-------|------|-------|
| 1 — Android Code | `classifier.py` | Hard-coded Android/platform package prefixes (survive R8) |
| 2 — Third-party | `classifier.py` | Whitelist matching from `third_party_prefixes.yaml` |
| 3 — Manifest Components | `classifier.py` | Cross-references AndroidManifest activities/services/receivers/providers (survive R8) |
| 4 — App Code | `classifier.py` | Infers app root package from manifest or frequency analysis (skips obfuscated paths) |
| 5 — Obfuscation Heuristic | `classifier.py` | Detects R8-obfuscated paths (single-letter directory segments like `a/b/c.java`) |
| 6 — LLM Fallback | `llm_fallback.py` | Claude or Gemini API with full vulnerability context (severity, CWE, description, obfuscation flag) |

### Key modules

- **`cli.py`** — Entry point. Orchestrates the full workflow and parses CLI args.
- **`mobsf_client.py`** — `MobSFClient` class wrapping MobSF REST API (`upload()`, `scan()`, `get_report()`).
- **`classifier.py`** — `classify_findings()` returns `(classified, unclassified)` tuples through Layers 1-5. Also exposes `is_obfuscated_path()`, `extract_manifest_components()`, `classify_manifest_component()`, `classify_obfuscated()`.
- **`llm_fallback.py`** — `classify_with_llm(findings, api_key, provider="anthropic")` supports both Anthropic (Claude Sonnet) and Google (Gemini Flash) for Layer 6. Provider is auto-detected from available API keys or set via `--llm-provider`.
- **`config.py`** — Loads `.env`, validates required vars (`MOBSF_URL`, `MOBSF_API_KEY`).
- **`utils.py`** — Shared logging, I/O, progress display helpers.
- **`web/app.py`** — Flask server with `/api/data` endpoint; `launch_server()` starts it.
- **`web/templates/index.html`** — Dashboard UI with pie chart and expandable findings table.

### External dependencies

- **MobSF instance** (default `http://localhost:8000`) — required, configured via `MOBSF_URL` and `MOBSF_API_KEY` in `.env`
- **Anthropic API** or **Gemini API** — optional (for Layer 6), configured via `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` in `.env`

## Configuration

Copy `.env.example` to `.env` and set values. `MOBSF_API_KEY` is required. For Layer 6 LLM fallback, set `ANTHROPIC_API_KEY` and/or `GEMINI_API_KEY` (both optional — if both are set, Anthropic is used by default; override with `--llm-provider gemini`).

The third-party library whitelist in `third_party_prefixes.yaml` is extensible — add package prefixes there for Layer 2 matching.

## Testing

Tests use `pytest` with `responses` for HTTP mocking. Test files mirror source modules:
- `tests/test_classifier.py` — Layers 1-5 classification logic (including obfuscation and manifest tests)
- `tests/test_llm_fallback.py` — Layer 6 LLM integration
- `tests/test_mobsf_client.py` — Mocked MobSF API client

Categories: `app_code`, `third_party`, `android_code`, `obfuscated_unknown`, `unknown`
