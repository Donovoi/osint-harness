"""Double-click on Windows after Python is installed."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from osint_harness.server import main
main()
