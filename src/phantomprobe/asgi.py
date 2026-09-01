#!/usr/bin/env python3
"""
ASGI entry point for serving the dashboard on its own.

Run with:
    uvicorn phantomprobe.asgi:app --host 0.0.0.0 --port 8080

This serves an empty dashboard plus the /api/* endpoints. Use the CLI
(`phantomprobe <target> --dashboard`) when you want a scan to populate it.
"""

from .dashboard import DashboardServer

_server = DashboardServer()

# The ASGI application uvicorn/gunicorn will serve.
app = _server.app

__all__ = ["app"]
