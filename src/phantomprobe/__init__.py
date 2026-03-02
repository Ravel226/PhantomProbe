#!/usr/bin/env python3
"""
PhantomProbe v0.7.0 - Entry Point
Reconnaissance Scanner for Penetration Testing
"""

import sys
import os

# Add packages to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'packages'))

from core.scanner import main

if __name__ == "__main__":
    main()
