"""Configuration loader — reads .env and validates required vs optional vars."""

import os
import sys
from dotenv import load_dotenv


def load_config(env_path=None):
    """Load configuration from .env file and environment variables.

    Returns a dict with all configuration values.
    Exits with a clear error if required variables are missing.
    """
    if env_path:
        load_dotenv(env_path)
    else:
        load_dotenv()

    config = {
        "mobsf_url": os.getenv("MOBSF_URL", "http://localhost:8000").rstrip("/"),
        "mobsf_api_key": os.getenv("MOBSF_API_KEY"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "gemini_api_key": os.getenv("GEMINI_API_KEY"),
    }

    if not config["mobsf_api_key"]:
        print("Error: MOBSF_API_KEY is not set in .env file or environment.")
        print("Please create a .env file with your MobSF API key.")
        sys.exit(1)

    return config
