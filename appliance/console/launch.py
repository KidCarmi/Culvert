"""Isolated Python entry point: import only the root-owned installed directory."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from culvert_console import main

sys.exit(main())
