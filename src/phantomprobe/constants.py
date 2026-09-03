#!/usr/bin/env python3
"""
Shared constants for PhantomProbe.

Single source of truth for the version string and the User-Agent sent by every
outbound request. Keep this module dependency-free so any other module can
import it without risking a circular import.
"""

__version__ = "0.9.0"

# Sent on every request PhantomProbe makes. Identifying the scanner honestly is
# deliberate: it lets target owners attribute traffic during authorized tests.
USER_AGENT = f"PhantomProbe/{__version__}"

# Some sites reject unknown agents outright; used where we need to look like a
# browser to retrieve client-side assets (HTML/JS analysis).
BROWSER_USER_AGENT = f"Mozilla/5.0 (compatible; PhantomProbe/{__version__})"
