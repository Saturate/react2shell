# Detection Templates

Templates for integrating CVE-2025-55182 detection into security testing tools.

## Nuclei

**File:** `nuclei.yaml`

```bash
nuclei -t templates/nuclei.yaml -u https://example.com
nuclei -t templates/nuclei.yaml -l urls.txt
```

## Burp Suite

**File:** `burp-scanner.json`

1. Open Burp Suite Professional
2. Scanner > Scan Configuration > Import
3. Select `burp-scanner.json`

Note: Requires Burp Suite Professional.

## OWASP ZAP

**File:** `zap-scan-policy.xml`

```bash
zap-cli active-scan -p zap-scan-policy.xml -u https://example.com
```

Or via GUI: Analyse > Scan Policy Manager > Import Policy

## Detection Method

All templates test for HTTP 500 responses when sending malicious Server Action payloads. Vulnerable systems crash, patched systems return HTTP 400.
