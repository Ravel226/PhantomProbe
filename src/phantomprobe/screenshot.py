#!/usr/bin/env python3
"""
Screenshot capture via Playwright (optional dependency).

Install with: pip install "phantomprobe[screenshot]" && playwright install chromium
"""

import os
from typing import Dict, List, Optional
from urllib.parse import urlparse


class ScreenshotCapture:
    """Capture website screenshots for documentation"""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        self.playwright_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        """Check if Playwright is available"""
        try:
            from playwright.sync_api import sync_playwright
            return True
        except ImportError:
            return False

    def capture(self, url: str, output_file: str = None, full_page: bool = True, 
                viewport_width: int = 1920, viewport_height: int = 1080,
                timeout: int = 30000) -> Optional[str]:
        """
        Capture screenshot of a URL
        
        Args:
            url: Target URL to screenshot
            output_file: Output filename (default: screenshot-{domain}.png)
            full_page: Capture full page or viewport only
            viewport_width: Browser viewport width
            viewport_height: Browser viewport height
            timeout: Page load timeout in ms
            
        Returns:
            Path to screenshot file or None if failed
        """
        if not self.playwright_available:
            print("[!] Playwright not installed. Install with: pip install playwright && playwright install chromium")
            return None

        try:
            from playwright.sync_api import sync_playwright
            
            # Parse URL
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            
            # Generate output filename
            if not output_file:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
                output_file = f"screenshot-{domain}.png"
            
            output_path = f"{self.output_dir}/{output_file}"
            
            print(f"[*] Capturing screenshot: {url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': viewport_width, 'height': viewport_height},
                    ignore_https_errors=True
                )
                page = context.new_page()
                
                # Set timeout
                page.set_default_timeout(timeout)
                
                # Navigate and wait for load
                try:
                    page.goto(url, wait_until='networkidle', timeout=timeout)
                except Exception as e:
                    # Try with domcontentloaded if networkidle times out
                    page.goto(url, wait_until='domcontentloaded', timeout=timeout)
                
                # Take screenshot
                page.screenshot(path=output_path, full_page=full_page)
                
                browser.close()
            
            print(f"[+] Screenshot saved: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[!] Screenshot failed: {str(e)}")
            return None

    def capture_multiple(self, urls: List[str], output_dir: str = None) -> List[str]:
        """Capture screenshots for multiple URLs"""
        screenshots = []
        
        if output_dir:
            self.output_dir = output_dir
        
        for url in urls:
            screenshot = self.capture(url)
            if screenshot:
                screenshots.append(screenshot)
        
        return screenshots

    def capture_with_variants(self, domain: str) -> Dict[str, str]:
        """Capture screenshots of domain variants (http, https, www)"""
        variants = {
            'https': f"https://{domain}",
            'https_www': f"https://www.{domain}",
            'http': f"http://{domain}",
        }
        
        screenshots = {}
        
        for name, url in variants.items():
            output_file = f"screenshot-{domain}-{name}.png"
            result = self.capture(url, output_file=output_file)
            if result:
                screenshots[name] = result
        
        return screenshots

