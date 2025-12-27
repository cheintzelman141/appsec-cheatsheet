# SQLMap

**Automated SQL injection detection and exploitation tool**

## Purpose

SQLMap automates the discovery and exploitation of SQL injection vulnerabilities. From an Application Security perspective, SQLMap serves three primary functions:

1. **Confirm exploitability** — Validate that identified injection points are actually exploitable
2. **Demonstrate real-world impact** — Show developers the actual risk (data exfiltration, not theoretical CVSS scores)
3. **Validate remediation** — Verify that fixes prevent exploitation

**Critical AppSec Note:** SQLMap should complement manual testing, not replace it. Automated tools miss context-dependent vulnerabilities and can generate false negatives.

---

## Basic Usage

### Test a Single URL Parameter
```bash
sqlmap -u "http://target.com/page.php?id=1"
```

**What this does:**
- Tests the `id` parameter for SQL injection
- Automatically detects DBMS type
- Attempts various injection techniques

### Test Using Request File (Recommended for AppSec)
```bash
sqlmap -r request.txt
```

**Why request files are better:**
- Preserves authentication context (cookies, tokens)
- Captures accurate parameter placement (GET/POST/JSON)
- Reduces false positives from incorrect request structure
- Enables testing of complex multi-parameter requests

**How to create request file:**
1. Intercept request in Burp Suite
2. Right-click → "Copy to file"
3. Save as `request.txt`

---

## Database Enumeration Workflow

### Step 1: Enumerate Databases
```bash
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

**Output:** List of all databases on the server

### Step 2: Enumerate Tables in Target Database
```bash
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables
```

**Output:** All tables in the specified database

### Step 3: Dump Table Contents
```bash
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T table_name --dump
```

**Output:** Full table contents (credentials, PII, business data)

### Step 4: Target Specific Columns (Surgical Extraction)
```bash
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users -C username,password --dump
```

**Why this matters:** Demonstrates precise data exfiltration for PoC reports

---

## Common Flags

| Flag | Purpose | When to Use |
|------|---------|------------|
| `--batch` | Non-interactive mode (accept defaults) | Automated scanning, CI/CD integration |
| `--level=5` | Increase test depth (1-5) | When initial scans miss vulnerability |
| `--risk=3` | Increase test risk (1-3) | Testing non-production environments |
| `--technique=U` | Use UNION-based injection only | Faster, cleaner exploitation for PoCs |
| `--threads=10` | Concurrent requests | Speed up enumeration (use cautiously) |
| `--random-agent` | Randomize User-Agent header | Bypass basic WAF fingerprinting |
| `--tamper=space2comment` | Apply evasion script | Bypass input filters/WAFs |

---

## AppSec Best Practices

### When to Use SQLMap

✅ **Appropriate use cases:**
- Confirming suspected SQL injection after manual code review
- Demonstrating exploitability to developers (PoC with real data extraction)
- Validating that prepared statements prevent injection
- Penetration testing authorized targets

❌ **When NOT to use:**
- First-line vulnerability discovery (manual testing finds more)
- Production systems without explicit authorization
- As a substitute for secure coding practices
- When you don't understand the underlying vulnerability

### Communicating SQLMap Findings to Developers

**Don't say:** "SQLMap found SQL injection"

**Do say:** "This endpoint accepts unsanitized input in the `id` parameter. I confirmed exploitability by extracting the first 10 rows of the `users` table, including plaintext passwords. Here's the vulnerable code and the prepared statement fix."

**Why:** Developers need:
1. **Root cause** (which parameter, why it's vulnerable)
2. **Proof of impact** (what data was accessed)
3. **Remediation path** (how to fix it)

### False Positive Handling

SQLMap can generate false positives when:
- Application returns errors for legitimate reasons
- Time-based detection triggers on slow servers
- WAF/IPS blocks requests, causing timeouts

**Always validate findings manually:**
```bash
# SQLMap claims time-based injection
# Verify with manual payloads:
http://target.com/page.php?id=1' AND SLEEP(5)--
```

---

## Integration with AppSec Workflows

### Secure Code Review → SQLMap Validation
```bash
# Found raw SQL in code review:
# $query = "SELECT * FROM users WHERE id = " . $_GET['id'];

# Validate exploitability:
sqlmap -u "http://target.com/user.php?id=1" --batch --technique=U -D app_db -T users --dump
```

### CI/CD Security Gate (Not Recommended for SQLMap)

SQLMap is **too slow and noisy** for CI/CD pipelines. Use SAST tools (Semgrep, SonarQube) instead.

**Better approach:**
- SAST in CI/CD (finds vulnerable patterns in code)
- SQLMap in manual penetration testing (proves exploitability)

---

## Example PoC Report Section
```markdown
## SQL Injection - User Profile Endpoint

**Severity:** Critical (CVSS 9.8)

**Affected Endpoint:** `/api/profile?user_id=`

**Vulnerability:** The `user_id` parameter is concatenated directly into a SQL query without sanitization.

**Proof of Exploitation:**
Using SQLMap, I extracted the first 5 rows of the `users` table:

| user_id | username | email | password_hash |
|---------|----------|-------|---------------|
| 1 | admin | admin@company.com | 5f4dcc3b5aa765d61d8327deb882cf99 |
| 2 | jdoe | jdoe@company.com | 098f6bcd4621d373cade4e832627b4f6 |

**Business Impact:**
- Complete database access (190,000 user records)
- PII exposure (emails, hashed passwords, addresses)
- Potential account takeover via password hash cracking
- Violates PCI-DSS Requirement 6.5.1 and GDPR Article 32

**Remediation:**
Use prepared statements in Laravel:

\`\`\`php
// Vulnerable code:
$user = DB::select("SELECT * FROM users WHERE id = " . $request->input('user_id'));

// Secure fix:
$user = DB::table('users')->where('id', $request->input('user_id'))->first();
\`\`\`

**Validation:**
After remediation, SQLMap confirms exploitation is no longer possible.
```

---

## Additional Resources

- **Official Documentation:** https://github.com/sqlmapproject/sqlmap/wiki
- **OWASP SQL Injection Guide:** https://owasp.org/www-community/attacks/SQL_Injection
- **Tamper Scripts:** https://github.com/sqlmapproject/sqlmap/tree/master/tamper

---

## Interview Talking Points

**If asked about SQLMap in an interview:**

> "SQLMap is excellent for proving exploitability and demonstrating business impact to developers. When I find a suspected SQL injection during code review, I use SQLMap to extract actual data—usually the first few rows of a sensitive table. That turns an abstract vulnerability report into a concrete business risk. However, I never rely solely on automated tools. Manual testing with Burp Suite often finds injection points that SQLMap misses, especially in complex authentication flows or API endpoints with non-standard parameter encoding."

**Follow-up question: "How do you prevent false positives?"**

> "I always validate SQLMap findings manually. If it claims time-based injection, I'll test with a manual `SLEEP()` payload in Burp to confirm the application actually delays. I also review the vulnerable code to understand *why* it's exploitable—sometimes SQLMap flags an error message that's not actually exploitable. The goal is defending every finding with code-level root cause, not just trusting the scanner output."
```
