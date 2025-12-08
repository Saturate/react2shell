# CVE-2025-55182 Scanner

> [!NOTE]  
> I didn't have too much time to keep updating this, use https://github.com/assetnote/react2shell-scanner for more elaborate scanning and testing with PoC verification.

A vulnerability scanner for CVE-2025-55182, a critical RCE vulnerability in React Server Components and Next.js.

## Quick Start

```bash
git clone https://github.com/Saturate/CVE-2025-55182-Scanner.git
cd CVE-2025-55182-Scanner
chmod +x cve-2025-55182-check.sh

# Scan a single URL
./cve-2025-55182-check.sh https://example.com

# Scan multiple URLs
./cve-2025-55182-check.sh -f urls.txt

# JSON output
./cve-2025-55182-check.sh --json https://example.com
```

## Usage

```
Usage: cve-2025-55182-check.sh [OPTIONS] [URL...]

OPTIONS:
    -f, --file FILE         Read URLs from file (one per line)
    -v, --verbose           Verbose output (show curl details)
    -q, --quiet             Quiet mode (only show vulnerable sites)
    -n, --no-follow         Don't follow redirects
    -t, --timeout SECONDS   Request timeout in seconds (default: 10)
    -u, --user-agent STRING Custom User-Agent header
    --explain               Show detailed vulnerability information
    --json                  Output results in JSON format
    --validate-fix          Test for mitigation controls
    --single-payload        Use only the basic payload (faster)
    -h, --help              Show this help message
    -V, --version           Show version information
```

## Affected Versions

**React:** 19.0.0, 19.1.0, 19.1.1, 19.2.0
**Next.js:** >=14.3.0-canary.77, all 15.x and 16.x (before patches)

**Patched:**
React 19.0.1+, 19.1.2+, 19.2.1+
Next.js 16.0.7+, 15.5.7+, 15.4.8+, 15.3.6+, 15.2.6+, 15.1.9+, 15.0.5+

## Integration

Templates for security tools are in `templates/`:
- Nuclei (`templates/nuclei.yaml`)
- Burp Suite (`templates/burp-scanner.json`)
- OWASP ZAP (`templates/zap-scan-policy.xml`)

See [templates/README.md](templates/README.md) for usage.

## Technical Details

See [TECHNICAL.md](TECHNICAL.md) for vulnerability analysis.

## References

- **CVE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182
- **React Advisory (remediation steps):** https://react.dev/blog/2025/12/03/critical-security-vulnerability
- **Fix Commit:** https://github.com/facebook/react/commit/7dc903cd29

## License

MIT License - See LICENSE file for details

## Author

Allan Kimmer Jensen - https://akj.io
