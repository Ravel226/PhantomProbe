#!/usr/bin/env python3
"""
PhantomProbe v0.7.0 - Entry Point
Reconnaissance Scanner for Penetration Testing
"""

import sys
import os

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(project_root, 'packages'))

from core.scanner import main, DashboardServer

__all__ = ['main', 'DashboardServer']

if __name__ == "__main__":
    main()
