"""Worker bootstrap, included in both a checkout and an installed wheel."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from osint_harness.worker import main
if __name__ == '__main__': main()
