"""Shared helpers — logging, file I/O, progress display."""

import json
import time
import sys


def print_progress(message, elapsed_seconds):
    """Print a progress message with elapsed time to stdout."""
    mins, secs = divmod(int(elapsed_seconds), 60)
    sys.stdout.write(f"\r{message} elapsed: {mins:02d}:{secs:02d}")
    sys.stdout.flush()


def print_progress_done():
    """Move to next line after progress display."""
    print()


def save_json(data, filepath):
    """Save data to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {filepath}")


def load_json(filepath):
    """Load data from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def log_verbose(message, verbose=False):
    """Print a message only if verbose mode is enabled."""
    if verbose:
        print(f"  [VERBOSE] {message}")
