"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


def install_token_path() -> Path:
    return CONFIG_DIR / "install_token"


_token_cache: str | None = None

def get_or_create_install_token() -> str:
    """Per-installation token used to authenticate WS adapter connections
    and /v1/control/* requests. Generated once and persisted to disk."""
    global _token_cache
    if _token_cache:
        return _token_cache
        
    # FIX for Leak 4: Allow binding token as an environment Secret so it 
    # never touches the shared disk volume.
    env_tok = os.getenv("GLC_INSTALL_TOKEN")
    if env_tok:
        _token_cache = env_tok.strip()
        return _token_cache

    p = install_token_path()
    if p.exists():
        _token_cache = p.read_text().strip()
        return _token_cache
        
    import secrets

    tok = secrets.token_urlsafe(32)
    p.write_text(tok)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
        
    _token_cache = tok
    return tok
