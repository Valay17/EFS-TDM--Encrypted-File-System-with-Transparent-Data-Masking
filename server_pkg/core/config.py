"""
Server configuration loader.

Reads config/server_config.json (relative to server_pkg/) and merges with
built-in defaults. Missing keys in the file are filled from defaults, so a
partial config file is valid.
"""

import json
from pathlib import Path

_CONFIG_DIR = Path(__file__).parent.parent / "config"
_DEFAULT_CONFIG_PATH = _CONFIG_DIR / "server_config.json"

_DEFAULTS = {
    "server": {
        "host": "127.0.0.1",
        "port": 9999,
        "cert_path": "certs/cert.pem",
        "key_path": "certs/key.pem",
        "master_key_path": "certs/master.key",
    },
    "password_policy": {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_digit": True,
        "require_special": True,
    },
    "session": {
        "ttl_seconds": 1800,
    },
    "upload": {
        "max_bytes": 50 * 1024 * 1024,
    },
    "rate_limiting": {
        "login_window_seconds": 300,
        "login_max_failures": 10,
        "vfs_bucket_capacity": 60,
        "vfs_refill_rate": 10.0,
    },
    "web_rate_limiting": {
        "ip_window_seconds": 300,
        "ip_max_attempts": 10,
        "account_max_failures": 5,
        "account_lockout_seconds": 900,
    },
    "defaults": {
        "new_user_role": "Guest",
    },
    "acl": {
        "default_mode": "open",
    },
    "audit": {
        "default_query_limit": 100,
        "auto_rotate_max_entries": 10000,
        "auto_rotate_max_days": 30,
        "retention_max_archives": 12,
        "integrity_check_interval_seconds": 60,
        "integrity_full_scan_every_n_polls": 10,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, recursing into nested dicts."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_server_config(config_path: str | None = None) -> dict:
    """Load server config, merging file values over built-in defaults.

    Args:
        config_path: Path to JSON config file. Defaults to
                     config/server_config.json next to the package root.

    Returns:
        Complete config dict with all sections guaranteed present.
    """
    path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return _deep_merge(_DEFAULTS, data)
        except Exception:
            pass
    return dict(_DEFAULTS)
