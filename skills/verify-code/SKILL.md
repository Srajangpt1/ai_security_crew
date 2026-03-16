---
name: verify-code
description: >
  Security review of code for vulnerabilities. Use this skill whenever the user wants to check
  code for security issues, asks "is this code secure?", "review this for vulnerabilities",
  "any security issues here?", or pastes code and asks for feedback. Also trigger when the user
  has just finished coding a feature (especially auth, APIs, file handling, database queries,
  or anything that handles user input) and wants to verify it before shipping. Trigger on phrases
  like "review the code", "check for vulnerabilities", "audit this", "is this safe?", "security
  check on this", or after generating code with an AI and wanting to validate it. Works with any
  language: Python, JavaScript, TypeScript, Java, Go, Ruby, SQL, etc.
---

Perform a security review of the following code:

$ARGUMENTS

---

## What to do

Review the code provided in the arguments above. If no code was provided, ask the user to paste the code or specify a file path to read. If a file path is mentioned, read the file first.

### Step 1 — Detect Technologies

Identify language and frameworks from:
- File extension: `.py` → Python, `.ts/.tsx` → TypeScript, `.go` → Go, `.java` → Java, `.rb` → Ruby, `.php` → PHP, `.sql` → SQL
- Import statements: `import django`, `require('express')`, `import React`, `use actix_web`
- Syntax patterns: `def`/`class` → Python, `func` → Go, `public class` → Java, `fn ` → Rust
- Framework indicators: `@app.route` → Flask, `useState` → React, `@Controller` → Spring

### Step 2 — Check for Vulnerabilities by Language

**Python:**
- Command injection: `os.system()`, `subprocess` with `shell=True`
- Unsafe deserialization: `pickle.loads()` on untrusted data
- Code execution: `eval()` / `exec()` with user-controlled input
- SQL injection via f-strings or `%` formatting in queries
- Path traversal in `open()` with user-supplied paths

**JavaScript / TypeScript:**
- XSS: `innerHTML`, `document.write()`, `dangerouslySetInnerHTML` without sanitization
- Prototype pollution via `Object.assign` / spread with user data
- `eval()` or `new Function()` with dynamic content
- Unvalidated `postMessage` handlers
- Sensitive data in `localStorage` or `sessionStorage`

**React:**
- `dangerouslySetInnerHTML` without DOMPurify or equivalent
- User input rendered directly in JSX without escaping
- Sensitive tokens/data stored in component state

**Java:**
- `Statement` instead of `PreparedStatement` for SQL
- `Runtime.exec()` with user-controlled input
- XXE vulnerabilities in XML parsers
- Unsafe deserialization (`ObjectInputStream`)

**Go:**
- SQL injection in raw `database/sql` queries
- Command injection in `exec.Command` with user input
- Path traversal in file serving handlers
- Race conditions in concurrent code without proper locking

**SQL:**
- String concatenation in queries instead of parameterized queries
- `UPDATE`/`DELETE` without `WHERE` clause
- `SELECT *` returning sensitive columns unnecessarily
- Overly permissive stored procedure privileges

### Step 3 — Universal Security Checklist

Verify ALL of these, regardless of language:

**Secrets & Credentials:**
- [ ] No hardcoded passwords, API keys, tokens, or secrets anywhere in the code
- [ ] Credentials loaded from environment variables or a secrets manager
- [ ] No secrets in comments or test fixtures

**Injection:**
- [ ] No SQL queries built with string concatenation or f-strings
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
- [ ] Ownership verified before returning or modifying resources (IDOR prevention)

**Cryptography:**
- [ ] No weak algorithms: MD5, SHA1, DES, RC4, ECB mode
- [ ] Cryptographic keys not hardcoded
- [ ] Secure random number generator used for tokens/nonces

**Error Handling & Logging:**
- [ ] No stack traces or internal details in responses
- [ ] Sensitive data (passwords, tokens, PII) not written to logs
- [ ] Errors handled gracefully

**Data Exposure:**
- [ ] Sensitive fields not returned in API responses unnecessarily
- [ ] Pagination/limits applied to list endpoints

### Step 4 — Output

Produce this exact structure:

---

## Security Code Review

**File:** [file path if known, or "provided code"]
**Language/Frameworks:** [detected list]
**Risk Level:** [LOW | MEDIUM | HIGH | CRITICAL]

### Overall Assessment
**[SECURE | NEEDS ATTENTION | INSECURE]**

[1–2 sentences summarizing the security posture]

### Findings

For each vulnerability found:

#### [SEVERITY: Critical/High/Medium/Low] — [Vulnerability Type]
**Location:** [function name or line number if identifiable]
**Description:** [what the vulnerability is and why it matters]

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
- ✅ [Item that passes]
- ❌ [Item that fails — brief note]
- ⚠️ [Item that needs review — context-dependent]

### Prioritized Recommendations
1. **[CRITICAL/HIGH]** — [Action to take]
2. ...
