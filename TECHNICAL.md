# CVE-2025-55182 Technical Analysis

CVE-2025-55182 is a critical RCE vulnerability in React Server Components (CVSS 10.0). Unauthenticated attackers can execute arbitrary code on servers running vulnerable versions of React or Next.js through insecure deserialization in the Flight protocol.

**Official Advisory:** https://react.dev/blog/2025/12/03/critical-security-vulnerability

**Affected:**
- React 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js >=14.3.0-canary.77, 15.x, 16.x (pre-patch)

**Fixed in:**
- React 19.0.1, 19.1.2, 19.2.1+
- Next.js 16.0.7, 15.5.7, 15.4.8, 15.3.6, 15.2.6, 15.1.9, 15.0.5+

## The Vulnerability

The Flight protocol in React Server Components deserializes client data without proper validation. Attackers can send malicious Server Action payloads that trigger prototype pollution and eventually execute arbitrary code.

More about React Server Components: https://react.dev/reference/rsc/server-components

Vulnerable packages:
- `react-server-dom-webpack`
- `react-server-dom-esm`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`

## Exploit Chain

Three weaknesses combine for RCE:

### 1. Unsanitized Path Traversal

Flight protocol references like `$1:property:nested` are split on colons and traversed without validation.

Vulnerable code in `ReactFlightReplyServer.js` ([lines 614-615](https://github.com/facebook/react/blob/36df5e8b42/packages/react-server/src/ReactFlightReplyServer.js#L614-L615)):

```javascript
for (let i = 1; i < path.length; i++) {
  value = value[path[i]];  // No property validation
}
```

Attackers can access:
- `$1:__proto__` - prototype chain
- `$1:constructor` - constructor function
- `$1:constructor:constructor` - Function constructor

### 2. Fake Chunk Injection

The system accepts any object with `status: "resolved_model"` as a valid chunk. No validation checks if chunks are legitimate.

Attacker payload:
```javascript
{
  "then": "$1:__proto__:then",      // Steals Chunk.prototype.then
  "status": "resolved_model",        // Mimics chunk
  "_response": {
    "_formData": {
      "get": "$1:constructor:constructor"  // Injects Function constructor
    }
  }
}
```

### 3. Function Constructor Injection

The exploit replaces `_formData.get` with the Function constructor. When processing blob references (`$B1337`), the code calls:

```javascript
response._formData.get("1337")
// But _formData.get is now Function, so this becomes:
Function("1337")()  // RCE
```

The attacker controls the code string, achieving remote code execution.

## Proof of Concept

Basic test payload that crashes vulnerable servers:

```bash
curl -X POST https://vulnerable-site.com/api/action \
  -H "Next-Action: 1337" \
  -F '0=["$1:a:a"]' \
  -F '1="{}"'
```

Vulnerable systems return HTTP 500 with TypeError. Patched systems return HTTP 400.

## The Fix

React fixed this in [commit 7dc903cd29](https://github.com/facebook/react/commit/7dc903cd29dac55efb4424853fd0442fef3a8700).

**Key files changed:**
- `ReactFlightDOMServerNode.js`
- `ReactFlightClientConfigBundlerParcel.js`
- `ReactFlightClientConfigBundlerTurbopack.js`

View all changes: https://github.com/facebook/react/commit/7dc903cd29dac55efb4424853fd0442fef3a8700

### Key Changes

**1. Property validation with hasOwnProperty**

```javascript
import hasOwnProperty from 'shared/hasOwnProperty';

if (hasOwnProperty.call(moduleExports, metadata[NAME])) {
  const value = moduleExports[metadata[NAME]];
} else {
  return undefined;
}
```

Blocks access to inherited properties (__proto__, constructor).

**2. Error handling with stream destruction**

```javascript
try {
  resolveField(chunk, value);
} catch (error) {
  busboyStream.destroy(error);
}
```

Stops processing on invalid input instead of crashing.

**3. Base64 upload rejection**

```javascript
if (encoding === 'base64') {
  busboyStream.destroy(new Error("React doesn't accept base64 encoded file uploads..."));
}
```

Blocks suspicious upload patterns.

## Detection Methodology

This scanner sends payloads that exploit the path traversal vulnerability. Vulnerable servers crash (HTTP 500) when trying to access invalid properties. Patched servers validate properties and return HTTP 400.

**Test payloads:**
- `$1:a:a` - Basic traversal (accesses undefined.a)
- `$1:constructor` - Constructor access
- `$1:__proto__:toString` - Prototype pollution
- `$1:a:b:c:d:e` - Deep traversal

**Response patterns:**
- HTTP 500 = Vulnerable
- HTTP 400 = Patched (safe)
- HTTP 404 = No Server Actions endpoint (safe)

## References

**Official:**
- React Advisory: https://react.dev/blog/2025/12/03/critical-security-vulnerability
- Fix Commit: https://github.com/facebook/react/commit/7dc903cd29dac55efb4424853fd0442fef3a8700
- CVE Entry: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182

**Security Research:**
- Wiz Security: https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182
- Datadog Security Labs: https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/
- Original Write-up: https://gist.github.com/HerringtonDarkholme/87f14efca45f7d38740be9f53849a89f

**Vendor Advisories:**
- Vercel: https://vercel.com/changelog/cve-2025-55182
- Google Cloud: https://cloud.google.com/blog/products/identity-security/responding-to-cve-2025-55182
