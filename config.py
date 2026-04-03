# loads api keys from environment variables, falls back to config.json

import os
import json
from pathlib import Path

# config.json sits next to this file and is gitignored
CONFIG_PATH = Path(__file__).parent / "config.json"


def load_config() -> dict:
    # start with all keys as none
    config = {
        "virustotal": None,
        "abuseipdb": None,
        "shodan": None,
    }

    # try to read config.json — skip silently if missing or broken
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                file_config = json.load(f)
            # only pull in keys we actually care about
            for key in config:
                if key in file_config:
                    config[key] = file_config[key]
        except json.JSONDecodeError:
            print("[warn] config.json is malformed, skipping")

    # env vars override anything from config.json
    env_map = {
        "virustotal": "VT_API_KEY",
        "abuseipdb": "ABUSEIPDB_API_KEY",
        "shodan": "SHODAN_API_KEY",
    }
    for key, env_var in env_map.items():
        value = os.environ.get(env_var)
        if value:
            config[key] = value

    return config
