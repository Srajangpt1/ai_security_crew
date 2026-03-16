---
name: threat-model
description: >
  Threat modeling for a feature, component, or system. Use this skill whenever the user wants
  to think through what could go wrong security-wise with something they're building, asks
  "what are the security threats for", "threat model this", "what attacks should I worry about",
  "help me think through the security of", or is designing a new feature and wants to identify
  risks before coding. Also trigger for phrases like "attack surface", "what can an attacker do",
  "security design review", or when building something involving auth, payments, file handling,
  multi-tenancy, external APIs, or sensitive data flows. This produces a concrete, developer-friendly
  threat model — not abstract frameworks — with actionable mitigations and an optional threat-model.md file.
---

Perform a threat model for the following feature or component:

$ARGUMENTS

---

## What to do

Produce a developer-focused threat model. If no description was provided in the arguments, ask:
1. What are you building? (feature name + description)
2. What tech stack is involved?
3. Do you have code snippets, data flows, or architecture notes to analyze?

Write threats in plain language — concrete attack scenarios a developer would understand, not abstract security categories. Every threat should link to specific evidence from the provided context.

### Step 1 — Understand the Feature

Extract:
- **Feature/component name** — what is this?
- **Description** — what does it do, what problem does it solve?
- **Tech stack** — languages, frameworks, databases, cloud services
- **Data touched** — credentials, PII, payment data, tokens, internal config, etc.
- **System boundaries** — what calls this? what does it call? external vs. internal?
- **Trust model** — who are the actors? (users, admins, anonymous, third-party services)

### Step 2 — Identify Attack Surfaces

Scan for:
- Authentication endpoints (login, registration, password reset, OAuth callbacks)
- File upload / download handlers
- External API integrations (third-party services, webhooks, callbacks)
- Admin / privileged operations
- Data exports or bulk operations
- Cross-tenant operations in multi-tenant systems
- Unauthenticated or public endpoints
- Async jobs or background workers that consume external data

And sensitive data patterns:
- Credentials and secrets (passwords, API keys, tokens, private keys)
- PII (names, emails, phone numbers, addresses, SSNs)
- Financial data (card numbers, account numbers, transaction history)
- Health data (PHI, medical records, diagnoses)
- Internal configuration or infrastructure details

### Step 3 — Generate Threats

Consider these attack dimensions:
- **Spoofing** — Can an attacker impersonate a user, service, or system?
- **Tampering** — Can data be modified in transit or at rest without detection?
- **Repudiation** — Can users deny actions due to missing audit trails?
- **Information Disclosure** — Can sensitive data leak through errors, logs, or responses?
- **Denial of Service** — Can an attacker exhaust resources or disrupt availability?
- **Elevation of Privilege** — Can a low-privilege user gain higher access?

Technology-specific risks to consider:
- **JWT**: algorithm confusion (`alg: none`), token theft, long-lived tokens, missing expiry checks
- **OAuth**: redirect URI manipulation, CSRF on callback, token leakage in logs/referrers
- **File uploads**: SSRF via URL fetch, path traversal, malicious file execution, unrestricted size
- **SQL databases**: injection via raw queries, excessive DB permissions, unencrypted sensitive columns
- **Redis/caches**: cache poisoning, unauthenticated access, insecure TTLs
- **Webhooks**: missing signature validation, replay attacks, SSRF via callback URLs
- **S3/blob storage**: public bucket misconfiguration, predictable key names, missing server-side encryption
- **Microservices**: missing service-to-service auth, internal SSRF, implicit trust between services

For each threat, provide:
- **ID**: TM-1, TM-2, ... (sequential)
- **What can go wrong**: Plain-language attack scenario — who does what, how, what they get
- **Impact**: Business consequence (account takeover, data breach, service disruption, etc.)
- **Likelihood**: high / medium / low — based on exploitability and attacker motivation
- **Data affected**: What data is at risk
- **Mitigation**: Specific fix — name the library, function, config option, or pattern to use
- **Status**: open (default unless user says otherwise)
- **Evidence**: What in the description/code/architecture justifies this threat

### Step 4 — Output the Threat Model

Produce this structure:

---

## Threat Model: [Feature/Component Name]

> **Author:** security-review
> **Created:** [today's date in YYYY-MM-DD]

### What Are We Building?

[Description of the feature]

### What Data Does It Touch?

- [Data item — be specific: "User passwords stored as bcrypt hashes in PostgreSQL users table"]
- [Data item]

### Technologies

[Comma-separated list]

### What Can Go Wrong?

#### TM-1: [Plain-language threat name]

- **Impact:** [Business impact — concrete consequence]
- **Likelihood:** [high | medium | low]
- **Data Affected:** [specific data types]
- **Status:** open

**Mitigation:** [Specific, actionable — name the algorithm, library, config flag, or code pattern]

**Evidence:** [What in the provided description/code makes this threat credible — quote or reference it]

#### TM-2: [Next threat]
...

### Summary

[2–3 sentences: overall risk level, the most critical threats, what mitigations are highest priority]

---

### Step 5 — Ask About Saving to File

After presenting the threat model, ask:

> **Would you like me to save this to `threat-model.md`?**

If yes:
- Ask for the file path (default: `threat-model.md` in the current directory)
- If a `threat-model.md` already exists, ask: **append** (add below existing content) or **replace**?
- Write the threat model as a well-formatted markdown document matching the structure above
- If appending, separate from existing content with `---`
