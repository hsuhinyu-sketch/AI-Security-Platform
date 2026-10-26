#!/usr/bin/env python3
"""Run the durable A2A inbox/recovery cases against a SQLite-capable composition."""
import runpy
import sys
from pathlib import Path
if __name__ == '__main__':
    sys.argv.append('--durable')
    runpy.run_path(str(Path(__file__).with_name('a2a_profile.py')), run_name='__main__')
