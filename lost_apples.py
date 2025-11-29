#!/usr/bin/env python3
"""
Quick launcher for Lost Apples GUI
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run the GUI
from searchpartyd_gui import main

if __name__ == "__main__":
    main()
