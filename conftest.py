import sys
from pathlib import Path

_root = Path(__file__).parent
sys.path.insert(0, str(_root / "server_pkg"))
sys.path.insert(0, str(_root / "client_pkg"))
