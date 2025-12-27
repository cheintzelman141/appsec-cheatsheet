# OWASP Top 10 (Application Security)

## Purpose
The OWASP Top 10 is a widely adopted framework that identifies the most critical
web application security risks based on real-world data.

It is a **prioritization model**, not an exhaustive list of all vulnerabilities.
Its primary value is providing a shared language for engineering, security, and
business stakeholders.

---

## OWASP Top 10 – 2021

1. **A01 – Broken Access Control**  
2. **A02 – Cryptographic Failures**  
3. **A03 – Injection**  
4. **A04 – Insecure Design**  
5. **A05 – Security Misconfiguration**  
6. **A06 – Vulnerable and Outdated Components**  
7. **A07 – Identification and Authentication Failures**  
8. **A08 – Software and Data Integrity Failures**  
9. **A09 – Security Logging and Monitoring Failures**  
10. **A10 – Server-Side Request Forgery (SSRF)**  

---

## AppSec Perspective
From an Application Security standpoint, the most impactful findings are usually
not obscure exploits but **systemic weaknesses**, particularly:

- Broken access control (IDOR, privilege escalation)
- Logic flaws that bypass intended workflows
- Insecure design decisions made early in development

Most severe incidents stem from *how systems are designed and implemented*, not
from missing patches alone.

AppSec work focuses on:
- identifying patterns that lead to vulnerabilities
- fixing root causes instead of symptoms
- preventing recurrence through guardrails, testing, and secure design

---

## Practical Use in AppSec
OWASP Top 10 is commonly used to:

- Classify and communicate vulnerabilities consistently
- Prioritize remediation based on real-world impact
- Translate technical findings into business risk
- Align engineering teams on security expectations

While OWASP categories are helpful for reporting, effective AppSec work goes beyond
classification and emphasizes **prevention and resilience**.

---

## AppSec Notes
OWASP Top 10 should be treated as a **starting point**, not a checklist.

High-maturity AppSec programs focus on:
- secure-by-design architectures
- consistent authorization models
- automated detection and prevention
- developer enablement and education
