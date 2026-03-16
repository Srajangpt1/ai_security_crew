Perform a threat model for the following feature or component:

$ARGUMENTS

---

## Instructions

Produce a developer-focused threat model for the feature or component described above. If no description is provided, ask the user:
1. What are they building? (feature name + description)
2. What tech stack is involved?
3. Are there code snippets, data flows, or architecture notes to analyze?

Write threats in plain language — describe concrete attack scenarios a developer would understand, not abstract STRIDE categories. Every threat must link to evidence from the artifacts provided.

### Step 1 — Understand What We're Building

Extract from the input:
- **Feature/component name** — what is this thing?
- **Description** — what does it do, what problem does it solve?
- **Tech stack** — languages, frameworks, databases, cloud services
- **Data touched** — what data flows through this feature? (credentials, PII, payment data, tokens, internal config, etc.)
- **System boundaries** — what calls this? what does it call? external vs internal?
- **Architecture notes** — deployment model, trust boundaries, network zones

### Step 2 — Identify Security Signals

Scan the description and any provided artifacts for:

**Attack surfaces:**
- Authentication endpoints (login, registration, password reset, OAuth)
- File upload / download handlers
- External API integrations (third-party services, webhooks)
- Admin / privileged operations
- Data exports or bulk operations
- Cross-tenant operations in multi-tenant systems
- Unauthenticated or public endpoints

**Sensitive data patterns:**
- Credentials and secrets (passwords, API keys, tokens)
- PII (names, emails, phone numbers, addresses)
- Financial data (card numbers, account numbers, transactions)
- Health data (PHI, medical records)
- Internal configuration or infrastructure details

**Technology-specific risks:**
- JWT: algorithm confusion, none-algorithm, token theft, refresh token abuse
- OAuth: redirect URI manipulation, CSRF on callback, token leakage in logs
- SQL databases: injection, excessive permissions, unencrypted sensitive columns
- File handling: path traversal, unrestricted upload, SSRF via URL fetch
- Redis/caching: cache poisoning, insecure TTLs, unauthenticated access
- Microservices: service-to-service auth, internal SSRF, broken trust boundaries
- Webhooks: signature validation, replay attacks, SSRF via callback URLs

### Step 3 — Generate Threats

For each identified threat:

- **ID:** TM-1, TM-2, ... (sequential)
- **What can go wrong:** Plain-language attack scenario. Example: "Attacker forges a JWT by switching to the `none` algorithm, bypassing signature verification and gaining unauthorized access as any user"
- **Impact:** Business consequence. Example: "Full account takeover, access to all user data and payment methods"
- **Likelihood:** high / medium / low — based on exploitability and attacker motivation
- **Data affected:** What data is at risk (credentials, PII, tokens, etc.)
- **Mitigation:** What to implement. Be specific — name the function, config flag, or library.
- **Status:** open (default) / in_progress / mitigated / accepted
- **Evidence:** Link the threat to the artifact (code path, data flow, architecture note, description)

Consider threats across these dimensions:
- **Spoofing** — Can an attacker impersonate a user, service, or system?
- **Tampering** — Can data be modified in transit or at rest without detection?
- **Repudiation** — Can users deny actions due to missing audit trails?
- **Information Disclosure** — Can sensitive data leak through errors, logs, responses?
- **Denial of Service** — Can an attacker exhaust resources or disrupt availability?
- **Elevation of Privilege** — Can a low-privilege user gain higher access?

### Step 4 — Output the Threat Model

Produce the complete threat model in this format:

---

## Threat Model: [Feature/Component Name]

> **Author:** security-review
> **Created:** [today's date]

### What Are We Building?

[Description of the feature — what it does and what problem it solves]

### What Data Does It Touch?

- [Data item 1 — e.g., "User credentials (email + password hash)"]
- [Data item 2 — e.g., "JWT access tokens (15-min TTL)"]
- [Data item 3]
- ...

### Technologies

[Comma-separated list]

### What Can Go Wrong?

#### TM-1: [Plain-language threat name]

- **Impact:** [Business impact]
- **Likelihood:** [high | medium | low]
- **Data Affected:** [list of data types at risk]
- **Status:** [open | in_progress | mitigated | accepted]

**Mitigation:** [Specific, actionable mitigation — name algorithms, functions, config flags]

**Evidence:**
- `[artifact type]` — `[location/reference]` — [what this proves about the threat]
  ```
  [optional code snippet if relevant]
  ```

#### TM-2: [Next threat]
...

### Summary

[2-3 sentence overall risk assessment: what's the highest risk, what mitigations are most critical, what's the overall security posture]

---

### Step 5 — Ask About Saving to File

After presenting the threat model, ask the user:

> **Would you like me to save this threat model to `threat-model.md`?**
> - If yes, specify the file path (default: `threat-model.md` in the current directory)
> - If a `threat-model.md` already exists, ask whether to **append** this model or **replace** the file

If the user confirms, write the threat model to the specified file as a well-formatted markdown document with all sections above. If appending, add a horizontal rule (`---`) separator between models and preserve the existing content.
