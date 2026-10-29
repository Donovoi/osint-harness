"""Qualified operator bootstrap: Python -I discards cwd/PYTHONPATH imports."""
import runpy
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
runpy.run_path(str(HERE/'start_case.py'), run_name='__main__')
