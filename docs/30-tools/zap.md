# OWASP ZAP – Dynamic Application Testing

## Purpose
OWASP ZAP (Zed Attack Proxy) is an open-source dynamic analysis tool used to
identify common web application vulnerabilities.

From an AppSec perspective, ZAP is primarily used for:
- baseline security testing
- CI/CD integration
- regression detection

---

## Common Use Cases
- Automated baseline scans
- Passive vulnerability detection
- Quick coverage for common issues
- Supporting secure SDLC workflows

---

## ZAP in CI/CD
ZAP is often used in:
- pre-production testing
- pull request validation
- scheduled security scans

Automated scans help catch:
- obvious misconfigurations
- missing headers
- known vulnerability patterns

---

## Limitations
ZAP:
- cannot reliably detect logic flaws
- struggles with complex authentication
- produces false positives

It should not replace manual testing.

---

## AppSec Workflow Integration
Effective use includes:
- running baseline scans automatically
- triaging results manually
- validating findings with Burp
- tracking issues as engineering defects

---

## AppSec Notes
ZAP provides **breadth**, not depth.

High-impact vulnerabilities are still found through:
- understanding application logic
- manual authorization testing
- collaboration with developers

Automated DAST is a guardrail, not a substitute for AppSec engineering.
