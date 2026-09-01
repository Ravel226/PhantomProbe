#!/usr/bin/env python3
"""
PhantomProbe - Entry point for `python -m phantomprobe`
"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
