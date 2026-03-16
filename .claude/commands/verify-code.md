Perform a security review of the following code:

$ARGUMENTS

---

## Instructions

Review the code provided in the arguments above for security vulnerabilities. If no code is provided in the arguments, ask the user to paste the code they want reviewed, or specify a file path to read.

### Step 1 — Detect Technologies

Identify the language and frameworks from:
- File extension (`.py` → Python, `.ts` → TypeScript, `.go` → Go, etc.)
- Import statements (`import django`, `require('express')`, `import React`, etc.)
- Syntax patterns (`def`/`class` → Python, `func` → Go, `public class` → Java)
- Framework indicators (`@app.route` → Flask, `useState` → React, `@Controller` → Spring)

### Step 2 — Build Focus Areas

Based on detected technologies, check for these vulnerability classes:

**Python:**
- Command injection via `os.system()`, `subprocess` with `shell=True`
- Unsafe deserialization: `pickle.loads()` on untrusted data
- `eval()` / `exec()` with dynamic/user-controlled input
- SQL injection via string formatting in queries
- Path traversal in file operations

**JavaScript / TypeScript:**
- XSS via `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`
- Prototype pollution via object spread or `Object.assign`
- `eval()` or `new Function()` with dynamic content
- Insecure `postMessage` handlers
- Unvalidated redirects

**React:**
- `dangerouslySetInnerHTML` without sanitization
- User input rendered directly in JSX
- Sensitive data stored in component state or localStorage

**Java:**
- `Statement` instead of `PreparedStatement` for SQL
- `Runtime.exec()` with user-controlled input
- XML External Entity (XXE) vulnerabilities
- Unsafe deserialization

**Go:**
- SQL injection in raw queries
- Command injection in `exec.Command`
- Path traversal in file serving
- Race conditions in concurrent code

**SQL:**
- String concatenation in queries instead of parameterization
- Missing `WHERE` clause on `UPDATE`/`DELETE`
- `SELECT *` returning sensitive columns
- Privilege escalation via stored procedures

### Step 3 — Universal Security Checklist

Verify ALL of the following regardless of language:

**Secrets & Credentials:**
- [ ] No hardcoded passwords, API keys, tokens, or secrets
- [ ] Credentials loaded from environment variables or a secrets manager
- [ ] No secrets in comments or test data

**Injection:**
- [ ] No SQL queries built with string concatenation
- [ ] No shell commands built from user input
- [ ] No dynamic code execution (`eval`, `exec`) with user data

**Input Validation:**
- [ ] All user input is validated before use
- [ ] File uploads validate type, size, and content (not just extension)
- [ ] No reliance on client-side validation alone

**Authentication & Authorization:**
- [ ] Passwords hashed with bcrypt, argon2, or scrypt (not MD5/SHA1/plain)
- [ ] Session tokens are randomly generated and rotated after login
- [ ] Access control checks present before every sensitive operation
- [ ] No Insecure Direct Object References (IDOR) — ownership verified

**Cryptography:**
- [ ] No weak algorithms: MD5, SHA1, DES, RC4, ECB mode
- [ ] Cryptographic keys not hardcoded
- [ ] Secure random number generator used for tokens/nonces

**Error Handling & Logging:**
- [ ] No stack traces or internal details in error responses
- [ ] Sensitive data (passwords, tokens, PII) not written to logs
- [ ] Errors handled gracefully without crashing

**Data Exposure:**
- [ ] Sensitive fields not returned in API responses unnecessarily
- [ ] Pagination/limits applied to list endpoints

### Step 4 — Produce Security Review

Output a structured report:

---

## Security Code Review

**File:** [file path or "provided code"]
**Language/Frameworks:** [detected list]
**Risk Level:** [LOW | MEDIUM | HIGH | CRITICAL]

### Overall Assessment
[SECURE | NEEDS ATTENTION | INSECURE]

[1-2 sentence summary of the security posture]

### Findings

For each vulnerability found:

#### [SEVERITY] — [Vulnerability Type]
**Location:** [function name / line number if identifiable]
**Description:** [what the vulnerability is and why it's a security risk]

**Vulnerable code:**
```[language]
[the problematic snippet]
```

**Secure fix:**
```[language]
[the corrected code]
```

---

### Checklist Results

Go through the universal checklist and mark each item:
- ✅ [Item that passes]
- ❌ [Item that fails — with brief note]
- ⚠️ [Item that needs review — ambiguous or context-dependent]

### Recommendations

Prioritized list of actions:
1. **[Priority]** — [Action]
2. ...

---
