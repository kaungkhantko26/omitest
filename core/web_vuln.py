"""Lightweight web security baseline checks for authorized targets.

These checks make one ordinary GET request and inspect response metadata. They
do not submit payloads, mutate data, brute force, or claim exploit confirmation.
"""

from typing import Dict, List, Optional
from urllib.parse import urlsplit

import httpx


def analyze_response(url: str, status_code: int, headers) -> List[Dict]:
    normalized = {str(k).lower(): str(v) for k, v in headers.items()}
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    common = {"host": parsed.hostname, "port": port, "service": "https" if parsed.scheme == "https" else "http",
              "source_tool": "web-baseline", "status": "potential", "reference_urls": []}
    findings: List[Dict] = []

    def add(name: str, description: str, risk: str = "low"):
        findings.append({**common, "name": name, "description": description,
                         "risk_level": risk, "cve_ids": []})

    if parsed.scheme == "https" and "strict-transport-security" not in normalized:
        add("Missing HTTP Strict Transport Security", "HTTPS response does not set Strict-Transport-Security.")
    if "content-security-policy" not in normalized:
        add("Missing Content Security Policy", "Response does not set Content-Security-Policy.")
    if "x-content-type-options" not in normalized:
        add("Missing MIME sniffing protection", "Response does not set X-Content-Type-Options: nosniff.")
    if "x-frame-options" not in normalized and "frame-ancestors" not in normalized.get("content-security-policy", ""):
        add("Missing clickjacking protection", "No X-Frame-Options or CSP frame-ancestors directive was observed.")
    if "referrer-policy" not in normalized:
        add("Missing Referrer Policy", "Response does not define a Referrer-Policy.", "unknown")
    if "permissions-policy" not in normalized:
        add("Missing Permissions Policy", "Response does not define a Permissions-Policy.", "unknown")

    acao = normalized.get("access-control-allow-origin", "")
    acac = normalized.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        add("Unsafe credentialed CORS policy", "Wildcard CORS origin is combined with credential allowance.", "high")

    server = normalized.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        add("Server version disclosure", f"Server header discloses software details: {server[:120]}", "unknown")

    set_cookie = normalized.get("set-cookie", "")
    if set_cookie:
        lower_cookie = set_cookie.lower()
        if parsed.scheme == "https" and "secure" not in lower_cookie:
            add("Cookie missing Secure attribute", "At least one HTTPS cookie lacks the Secure attribute.", "medium")
        if "httponly" not in lower_cookie:
            add("Cookie missing HttpOnly attribute", "At least one cookie lacks the HttpOnly attribute.", "medium")
        if "samesite" not in lower_cookie:
            add("Cookie missing SameSite attribute", "At least one cookie lacks an explicit SameSite attribute.", "low")

    if status_code >= 500:
        add("Public server error response", f"The root route returned HTTP {status_code}.", "medium")
    return findings


async def scan_web_target(host: str, timeout: float = 15.0) -> Dict:
    """Probe HTTPS then HTTP and return the first reachable baseline result."""
    host = (host or "").strip().strip("/")
    if not host:
        return {"success": False, "error": "empty host", "findings": []}
    candidates = [host] if host.startswith(("http://", "https://")) else [f"https://{host}/", f"http://{host}/"]
    error: Optional[str] = None
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
        follow_redirects=True,
        verify=True,
        headers={"User-Agent": "omitest-web-baseline/1.0"},
    ) as client:
        for url in candidates:
            try:
                response = await client.get(url)
                return {
                    "success": True,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "findings": analyze_response(str(response.url), response.status_code, response.headers),
                }
            except httpx.HTTPError as exc:
                error = f"{type(exc).__name__}: {exc}"
    return {"success": False, "error": error or "unreachable", "findings": []}
