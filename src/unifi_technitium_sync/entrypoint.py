"""Select direct credentials or Infisical without exposing secret values."""
import os
from pathlib import Path
import sys


def main():
    enabled = os.getenv("INFISICAL_ENABLED", "false").lower()
    if enabled not in {"true", "false"}:
        raise SystemExit("INFISICAL_ENABLED must be true or false")
    script = "infisical_bootstrap.py" if enabled == "true" else "sync.py"
    os.execv(sys.executable, [sys.executable, str(Path(__file__).with_name(script))])


if __name__ == "__main__":
    main()
