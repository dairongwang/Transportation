"""Load auth/totp.py directly from its file so scripts work with only the standard library."""

import importlib.util
from pathlib import Path


def load_totp():
    path = Path(__file__).resolve().parents[1] / "auth" / "totp.py"
    spec = importlib.util.spec_from_file_location("stdlib_totp", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
