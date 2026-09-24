from core.web_vuln import analyze_response


def test_secure_headers_produce_no_header_findings():
    findings = analyze_response("https://example.test/", 200, {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
    })
    assert findings == []


def test_missing_headers_use_real_https_port_not_zero():
    findings = analyze_response("https://example.test/", 200, {})
    assert findings
    assert all(item["port"] == 443 for item in findings)
    assert any(item["name"] == "Missing Content Security Policy" for item in findings)


def test_insecure_cookie_is_reported():
    findings = analyze_response("https://example.test/", 200, {
        "set-cookie": "session=abc; Path=/",
    })
    names = {item["name"] for item in findings}
    assert "Cookie missing Secure attribute" in names
    assert "Cookie missing HttpOnly attribute" in names
