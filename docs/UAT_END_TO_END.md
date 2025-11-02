# End-to-End UAT: Testing with Real User Queries

This guide tests the complete workflow: User query → Security assessment → AI agent picks relevant OWASP guidelines → Provides secure coding guidance.

## 🎯 What We're Testing

1. **MCP Tool Integration** - Does the security assessment tool work?
2. **Guideline Selection** - Are the right OWASP cheat sheets selected?
3. **AI Agent Usage** - Does the AI agent (like me) use the guidelines in responses?
4. **Practical Value** - Is the guidance actually helpful?

---

## 🚀 Setup

### 1. Start the MCP Server

```bash
cd /Users/deepika/Desktop/srajan-projects/ai_security_crew

# Start the server
uv run mcp-security-review
```

The server should start and be available for MCP clients (Cursor, Claude Desktop, etc.)

### 2. Verify MCP Connection

In your MCP client (Cursor), check that the `mcp-security-review` server is connected and available.

---

## 🧪 Test Scenarios

### Scenario 1: Authentication Implementation

**User Query:**
```
I need to implement user authentication for my web app. 
I'm using React frontend and Node.js backend with PostgreSQL. 
Users should be able to login with email/password and we want to support OAuth2 later.
Can you help me implement this securely?
```

**Expected AI Agent Behavior:**

1. **Should call the MCP tool:**
   ```
   lightweight_security_review(
     "Implement user authentication with email/password and OAuth2",
     "React, Node.js, PostgreSQL"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ Authentication Cheat Sheet
   - ✅ Password Storage Cheat Sheet
   - ✅ Session Management Cheat Sheet
   - ✅ OAuth2 Cheat Sheet
   - ✅ Credential Stuffing Prevention

3. **Should provide guidance covering:**
   - ✅ Password hashing (bcrypt/argon2)
   - ✅ Session management best practices
   - ✅ JWT token security (if using tokens)
   - ✅ OAuth2 implementation security
   - ✅ Rate limiting for login attempts
   - ✅ MFA recommendations

4. **Should reference OWASP guidelines:**
   - Mentions specific OWASP cheat sheets
   - Provides links or references
   - Follows OWASP best practices

**How to Test:**
1. Ask the query to the AI agent (me, in Cursor)
2. Observe if I call the MCP tool
3. Check if I mention OWASP guidelines
4. Verify the security advice is comprehensive

**Pass Criteria:**
- [ ] AI agent calls the security review tool
- [ ] Receives relevant authentication guidelines
- [ ] Provides secure implementation guidance
- [ ] References OWASP best practices
- [ ] Covers password hashing, session management, OAuth2

---

### Scenario 2: SQL Injection Fix

**User Query:**
```
I have a bug report about SQL injection in our user search feature.
The code looks like this:

const searchUsers = (query) => {
  const sql = `SELECT * FROM users WHERE name LIKE '%${query}%'`;
  return db.query(sql);
};

How should I fix this?
```

**Expected AI Agent Behavior:**

1. **Should recognize the security issue immediately**

2. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Fix SQL injection vulnerability in user search",
     "database, SQL"
   )
   ```

3. **Should receive guidelines including:**
   - ✅ SQL Injection Prevention Cheat Sheet
   - ✅ Input Validation Cheat Sheet
   - ✅ Query Parameterization Cheat Sheet
   - ✅ Database Security Cheat Sheet

4. **Should provide:**
   - ✅ Explanation of the vulnerability
   - ✅ Parameterized query solution
   - ✅ Input validation recommendations
   - ✅ ORM usage suggestions
   - ✅ Additional security measures

**Pass Criteria:**
- [ ] Identifies SQL injection vulnerability
- [ ] Calls security review tool
- [ ] Provides parameterized query solution
- [ ] References OWASP SQL Injection Prevention
- [ ] Suggests additional security measures

---

### Scenario 3: API Security

**User Query:**
```
I'm building a REST API for a mobile app. 
The API will handle user data, payments, and sensitive information.
What security measures should I implement?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Build secure REST API for mobile app with sensitive data",
     "REST API, mobile, payments"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ REST Security Cheat Sheet
   - ✅ API Security best practices
   - ✅ Mobile Application Security
   - ✅ Authentication Cheat Sheet
   - ✅ Authorization Cheat Sheet
   - ✅ Cryptographic Storage

3. **Should provide guidance on:**
   - ✅ API authentication (JWT, OAuth2, API keys)
   - ✅ Rate limiting and throttling
   - ✅ Input validation
   - ✅ HTTPS/TLS requirements
   - ✅ CORS configuration
   - ✅ Sensitive data encryption
   - ✅ Payment security (PCI compliance)
   - ✅ API versioning
   - ✅ Error handling

**Pass Criteria:**
- [ ] Comprehensive API security checklist provided
- [ ] References multiple OWASP cheat sheets
- [ ] Covers authentication, authorization, encryption
- [ ] Mentions rate limiting and input validation
- [ ] Addresses payment security specifically

---

### Scenario 4: XSS Vulnerability

**User Query:**
```
Our security scan found XSS vulnerabilities in our React app.
We're displaying user-generated content like comments and profiles.
How do we fix this?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Fix XSS vulnerabilities in React app with user-generated content",
     "React, JavaScript, XSS"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ Cross-Site Scripting Prevention
   - ✅ DOM-based XSS Prevention
   - ✅ Content Security Policy
   - ✅ Input Validation
   - ✅ HTML5 Security

3. **Should provide:**
   - ✅ Explanation of XSS types (stored, reflected, DOM-based)
   - ✅ React-specific guidance (JSX auto-escaping)
   - ✅ DOMPurify or similar sanitization library
   - ✅ Content Security Policy implementation
   - ✅ Input validation strategies
   - ✅ Output encoding recommendations

**Pass Criteria:**
- [ ] Explains XSS vulnerability types
- [ ] Provides React-specific solutions
- [ ] Recommends sanitization libraries
- [ ] Suggests CSP implementation
- [ ] References OWASP XSS Prevention

---

### Scenario 5: Cloud Security (AWS)

**User Query:**
```
We're deploying our application to AWS.
We'll use EC2, RDS, S3, and Lambda.
What security best practices should we follow?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Secure AWS deployment with EC2, RDS, S3, Lambda",
     "AWS, cloud, EC2, RDS, S3, Lambda"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ Secure Cloud Architecture
   - ✅ Serverless/FaaS Security
   - ✅ Infrastructure as Code Security
   - ✅ Secrets Management
   - ✅ Key Management

3. **Should provide guidance on:**
   - ✅ IAM roles and policies (least privilege)
   - ✅ Security groups and network isolation
   - ✅ S3 bucket security (encryption, access control)
   - ✅ RDS encryption and backup
   - ✅ Lambda function security
   - ✅ Secrets Manager for credentials
   - ✅ CloudTrail logging
   - ✅ VPC configuration

**Pass Criteria:**
- [ ] Covers all mentioned AWS services
- [ ] Provides IAM best practices
- [ ] Addresses encryption at rest and in transit
- [ ] Mentions secrets management
- [ ] References OWASP Cloud Security guidelines

---

### Scenario 6: Kubernetes Security

**User Query:**
```
We're containerizing our microservices and deploying to Kubernetes.
What security considerations should we be aware of?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Secure Kubernetes deployment for microservices",
     "Kubernetes, Docker, containers, microservices"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ Kubernetes Security Cheat Sheet
   - ✅ Docker Security
   - ✅ Microservices Security
   - ✅ Container Security

3. **Should provide:**
   - ✅ Pod security policies/standards
   - ✅ RBAC configuration
   - ✅ Network policies
   - ✅ Secrets management in K8s
   - ✅ Container image security
   - ✅ Runtime security
   - ✅ Service mesh considerations

**Pass Criteria:**
- [ ] Comprehensive K8s security checklist
- [ ] Covers RBAC and network policies
- [ ] Addresses container image security
- [ ] Mentions secrets management
- [ ] References OWASP Kubernetes guidelines

---

### Scenario 7: GDPR Compliance

**User Query:**
```
We need to ensure our application is GDPR compliant.
We collect user emails, names, and usage data.
What do we need to implement?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Implement GDPR compliance for user data collection",
     "GDPR, compliance, privacy, user data"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ User Privacy Protection (if available)
   - ✅ Data validation and sanitization
   - ✅ Cryptographic Storage
   - ✅ Logging (for audit trails)

3. **Should provide:**
   - ✅ Data subject rights (access, deletion, portability)
   - ✅ Consent management
   - ✅ Data encryption requirements
   - ✅ Data retention policies
   - ✅ Breach notification procedures
   - ✅ Privacy by design principles
   - ✅ Data processing records

**Pass Criteria:**
- [ ] Covers key GDPR requirements
- [ ] Addresses data subject rights
- [ ] Mentions consent and privacy
- [ ] Provides implementation guidance
- [ ] References relevant security guidelines

---

### Scenario 8: Mobile App Security

**User Query:**
```
I'm developing a mobile banking app for iOS and Android.
What security measures are critical?
```

**Expected AI Agent Behavior:**

1. **Should call MCP tool:**
   ```
   lightweight_security_review(
     "Secure mobile banking app for iOS and Android",
     "mobile, iOS, Android, banking, financial"
   )
   ```

2. **Should receive guidelines including:**
   - ✅ Mobile Application Security
   - ✅ Authentication Cheat Sheet
   - ✅ Cryptographic Storage
   - ✅ Certificate Pinning

3. **Should provide:**
   - ✅ Secure storage (Keychain/Keystore)
   - ✅ Certificate pinning
   - ✅ Biometric authentication
   - ✅ Jailbreak/root detection
   - ✅ Code obfuscation
   - ✅ Secure communication (TLS)
   - ✅ Session management
   - ✅ Input validation

**Pass Criteria:**
- [ ] Addresses mobile-specific security
- [ ] Covers both iOS and Android
- [ ] Mentions biometric authentication
- [ ] Addresses secure storage
- [ ] References OWASP Mobile Security

---

## 📊 UAT Execution Template

For each scenario, fill out:

```markdown
### Scenario: [Name]

**Date:** [Date]
**Tester:** [Name]

#### Test Execution

1. **Query Asked:**
   [Copy the exact query]

2. **AI Agent Response:**
   - [ ] Called MCP security tool? YES / NO
   - [ ] Tool parameters correct? YES / NO
   - [ ] Received relevant guidelines? YES / NO
   - [ ] Number of guidelines received: ___

3. **Guidelines Mentioned:**
   - [ ] [Guideline 1]
   - [ ] [Guideline 2]
   - [ ] [Guideline 3]

4. **Quality of Response:**
   - [ ] Comprehensive coverage
   - [ ] Specific and actionable
   - [ ] References OWASP
   - [ ] Code examples provided
   - [ ] Security best practices followed

5. **Overall Assessment:**
   - ✅ PASS / ❌ FAIL
   
6. **Notes:**
   [Any observations, issues, or improvements]
```

---

## 🎯 Quick Test Script

Here's a quick way to test if the system is working:

```python
# test_e2e.py
from mcp_security_review.security import SecurityAssessment

# Test scenarios
scenarios = [
    {
        "name": "Authentication",
        "ticket": {
            "summary": "Implement JWT authentication",
            "description": "Add JWT token-based authentication with OAuth2 support",
            "fields": {"issuetype": {"name": "Story"}, "labels": ["authentication"]}
        },
        "expected_categories": ["authentication", "api_security"],
        "expected_guidelines": ["jwt", "oauth", "authentication"]
    },
    {
        "name": "SQL Injection",
        "ticket": {
            "summary": "Fix SQL injection in user search",
            "description": "User input not sanitized in database queries",
            "fields": {"issuetype": {"name": "Bug"}, "labels": ["security", "database"]}
        },
        "expected_categories": ["database", "data_validation"],
        "expected_guidelines": ["sql injection", "parameterization"]
    },
    {
        "name": "API Security",
        "ticket": {
            "summary": "Secure REST API endpoints",
            "description": "Add authentication and rate limiting to API",
            "fields": {"issuetype": {"name": "Task"}, "labels": ["api", "security"]}
        },
        "expected_categories": ["api_security", "authentication"],
        "expected_guidelines": ["rest", "api", "rate limit"]
    }
]

assessment = SecurityAssessment()

print("🧪 End-to-End Testing\n")
print("=" * 60)

for scenario in scenarios:
    print(f"\n📝 Scenario: {scenario['name']}")
    print("-" * 60)
    
    result = assessment.assess_ticket(scenario["ticket"])
    
    print(f"Risk Level: {result.risk_level}")
    print(f"Categories: {result.security_categories}")
    print(f"Guidelines: {len(result.guidelines)}")
    
    # Check if expected categories are present
    expected_cats = set(scenario["expected_categories"])
    actual_cats = set(result.security_categories)
    
    if expected_cats.intersection(actual_cats):
        print("✅ Expected categories found")
    else:
        print(f"⚠️  Expected {expected_cats}, got {actual_cats}")
    
    # Check if expected guidelines are present
    guideline_titles = " ".join([g["title"].lower() for g in result.guidelines])
    found_keywords = []
    for keyword in scenario["expected_guidelines"]:
        if keyword.lower() in guideline_titles:
            found_keywords.append(keyword)
    
    print(f"✅ Found keywords: {found_keywords}")
    
    print(f"\nTop 3 Guidelines:")
    for g in result.guidelines[:3]:
        print(f"  • {g['title']} ({g['priority']})")

print("\n" + "=" * 60)
print("✅ End-to-End Test Complete!")
```

Run it:
```bash
cd /Users/deepika/Desktop/srajan-projects/ai_security_crew
python3 test_e2e.py
```

---

## ✅ Success Criteria

The integration is successful if:

1. **Tool Integration Works:**
   - [ ] MCP server starts without errors
   - [ ] AI agent can call security assessment tools
   - [ ] Tools return valid responses

2. **Guideline Selection is Accurate:**
   - [ ] Relevant OWASP cheat sheets are selected
   - [ ] Priority guidelines appear first
   - [ ] Category detection works correctly

3. **AI Agent Uses Guidelines:**
   - [ ] References OWASP in responses
   - [ ] Provides specific security guidance
   - [ ] Follows best practices from guidelines
   - [ ] Gives actionable recommendations

4. **Practical Value:**
   - [ ] Responses are comprehensive
   - [ ] Guidance is specific and actionable
   - [ ] Code examples follow security best practices
   - [ ] Covers all major security concerns

---

## 🐛 Troubleshooting

### AI Agent Doesn't Call the Tool

**Possible Causes:**
- MCP server not running
- Tool not registered properly
- Query not security-related enough

**Solution:**
- Restart MCP server
- Check MCP connection in client
- Make query more explicitly security-focused

### Wrong Guidelines Selected

**Possible Causes:**
- Category detection not working
- Keywords not matching
- Priority filtering issues

**Solution:**
- Check analyzer.py keyword mappings
- Verify guideline metadata
- Test with more specific queries

### AI Agent Doesn't Reference OWASP

**Possible Causes:**
- Guidelines not in prompt injection
- AI not recognizing guideline content
- Response too brief

**Solution:**
- Check prompt injection format
- Verify guideline content is clear
- Ask for more detailed security guidance

---

## 📞 Support

If you encounter issues:
1. Check MCP server logs
2. Verify guideline loading with `test_guidelines_standalone.py`
3. Test security assessment directly with Python
4. Review the UAT documentation

---

**Happy Testing! 🎉**

Now go ahead and **ask me those security questions** - let's see if I pick up the OWASP guidelines correctly!

