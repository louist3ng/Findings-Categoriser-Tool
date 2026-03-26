# Findings Categoriser Tool

A Python CLI tool that uploads an APK to a locally running MobSF instance, scans it, classifies SAST findings into categories (app code, third-party, Android platform, obfuscated, unknown), and launches a web UI to display the results. Handles both debug and R8/ProGuard-obfuscated APKs.

## Prerequisites

- **Python 3.10+**
- **MobSF** running locally (default: `http://localhost:8000`)
  - Install: https://mobsf.github.io/docs/#/installation
  - Get your API key from MobSF dashboard → **API Docs** (top-right menu)
- **MobSF REST API key** — required
- **Anthropic API key** or **Gemini API key** — optional (enables Layer 6 LLM fallback for ambiguous paths)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root (see `.env.example`):

```env
MOBSF_URL=http://localhost:8000
MOBSF_API_KEY=your_api_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here  # optional
GEMINI_API_KEY=your_gemini_key_here        # optional
```

- `MOBSF_URL` — Base URL of your MobSF instance (default: `http://localhost:8000`)
- `MOBSF_API_KEY` — **Required**. Your MobSF REST API key.
- `ANTHROPIC_API_KEY` — **Optional**. Enables Layer 6 LLM fallback using Claude.
- `GEMINI_API_KEY` — **Optional**. Enables Layer 6 LLM fallback using Gemini. If both keys are set, Anthropic is used by default (override with `--llm-provider gemini`).

## Usage

### Basic scan (no LLM fallback)

```bash
python cli.py --apk path/to/app.apk
```

This will:
1. Upload the APK to MobSF
2. Trigger a SAST scan and wait for completion
3. Classify all findings using Layers 1-5 (plus Layer 6 LLM if an API key is configured)
4. Save results to `classified_findings.json`
5. Launch a web UI at `http://localhost:5000` and open it in your browser

### With LLM fallback enabled

Set `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` in your `.env`, then run normally:

```bash
python cli.py --apk path/to/app.apk
```

### Use a specific LLM provider

```bash
python cli.py --apk path/to/app.apk --llm-provider gemini
python cli.py --apk path/to/app.apk --llm-provider anthropic
```

### Skip LLM even if API key is set

```bash
python cli.py --apk path/to/app.apk --no-llm
```

### Without auto-opening the browser

```bash
python cli.py --apk path/to/app.apk --no-browser
```

### Custom output file and port

```bash
python cli.py --apk path/to/app.apk --output results.json --port 8080
```

### Verbose mode (see classification decisions)

```bash
python cli.py --apk path/to/app.apk --verbose
```

## CLI Flags

| Flag          | Description                                     | Default                      |
|---------------|------------------------------------------------|------------------------------|
| `--apk`       | Path to the APK file (required)                | —                            |
| `--output`    | Output JSON file path                           | `classified_findings.json`   |
| `--prefixes`  | Custom third-party prefixes YAML file           | `third_party_prefixes.yaml`  |
| `--no-llm`    | Disable Layer 5 LLM fallback (unclassified findings skip straight to Layer 6 obfuscation heuristic) | off                          |
| `--llm-provider` | LLM provider for Layer 5: `anthropic` or `gemini` | auto-detect                  |
| `--verbose`   | Print classification decisions to stdout        | off                          |
| `--timeout`   | MobSF scan polling timeout (seconds)            | `600`                        |
| `--no-browser`| Don't auto-open browser after scan              | off                          |
| `--port`      | Flask web server port                           | `5000`                       |

## Classification Layers

Findings are classified using a waterfall of six layers, designed to handle both debug and R8/ProGuard-obfuscated APKs:

1. **Layer 1 — Android Code** (rule-based): Matches known Android/platform prefixes (`android/`, `java/`, `javax/`, etc.). These survive obfuscation.
2. **Layer 2 — Third-party Code** (whitelist): Matches known library prefixes (`com/google/`, `okhttp3/`, etc.) from `third_party_prefixes.yaml`.
3. **Layer 3 — Manifest Components** (manifest cross-reference): Activities, services, receivers, and providers declared in AndroidManifest.xml retain their real class names after R8. Files matching these components or their parent packages are classified as app code.
4. **Layer 4 — App Code** (inferred): Infers the app's package name from the manifest or file path frequency analysis. Obfuscated paths are excluded from frequency counting so that `-keep` survivors dominate the inference.
5. **Layer 5 — LLM Fallback** (optional): Uses Claude or Gemini API with full vulnerability context (severity, CWE, description, obfuscation status) to classify remaining ambiguous paths. Provider is auto-detected from available API keys or set explicitly via `--llm-provider`.
6. **Layer 6 — Obfuscation Fallback**: Findings that the LLM could not classify (or when LLM is disabled/errors) are checked against an obfuscation heuristic. Paths where all directory segments are 1-2 characters (e.g. `A/n.java`, `a/b/c.java`, `a0/x.java`) are tagged as `obfuscated_unknown` rather than left as generic unknowns.

Each layer assigns a `category`, `confidence` level, and records which layer made the decision.

## Extending the Third-party Whitelist

Edit `third_party_prefixes.yaml` to add more library prefixes:

```yaml
prefixes:
  - com/google/
  - com/facebook/
  - your/custom/library/
```

Or pass a custom file:

```bash
python cli.py --apk app.apk --prefixes my_prefixes.yaml
```

## Web UI

After classification, a Flask server launches automatically with:

- **Summary header** — APK info, scan date, finding count, LLM status
- **Pie chart** — Category breakdown (Chart.js)
- **Expandable findings table** — Click any row for full details
- **Export buttons** — Download JSON or CSV directly from the browser

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
├── cli.py                  # Entry point, argparse, workflow orchestration
├── config.py               # .env loader, config validation
├── utils.py                # Shared helpers (logging, file I/O, progress)
├── mobsf_client.py         # MobSF REST API client
├── classifier.py           # Layers 1-5 classification logic
├── llm_fallback.py         # Layer 6 LLM fallback (Anthropic/Gemini)
├── web/
│   ├── app.py              # Flask server
│   └── templates/
│       └── index.html      # Results UI (Chart.js, expandable table)
├── tests/
│   ├── test_classifier.py  # Layer 1-5 tests
│   ├── test_llm_fallback.py# Layer 6 tests (skip, prompt, parse, providers)
│   └── test_mobsf_client.py# MobSF client tests (mocked HTTP)
├── third_party_prefixes.yaml
├── requirements.txt
├── .env.example
└── README.md
```
