# Operational Surface

This document covers operational mechanisms that introduce AppSec risk when exposed, misused, or insufficiently controlled.

---

## File Transfer Techniques

File transfer techniques describe the legitimate mechanisms applications and infrastructure use to move files between systems. In AppSec, the concern is not how attackers move files, but how file transfer paths introduce risk when exposed, misused, or insufficiently controlled.

### Why It Matters (AppSec)

File transfer paths frequently bypass application-layer controls. When improperly secured, they enable data exfiltration, malware ingress, unauthorized uploads, and persistence mechanisms that operate outside normal request flows.

### Where It Shows Up

- File upload/download features
- CI/CD artifact handling
- Backup and restore processes
- Data export functionality
- Administrative or support tooling

### Common Risk Patterns

| Pattern | Description |
|---------|-------------|
| Unauthenticated Upload Endpoints | File upload without auth or authorization |
| Unrestricted File Types | Executables, scripts, or templates allowed |
| Out-of-Band Transfers | SCP, FTP, rsync used outside app controls |
| Insecure Storage Locations | World-readable temp or staging directories |

### Detection

**Manual:**
- Review upload/download endpoints
- Trace file lifecycle (upload → storage → retrieval)

**Automated:**
- API inventory
- Cloud storage exposure scans

### Mitigation

**Baseline:**
- Enforce auth and authorization on all transfers
- Restrict file types and sizes
- Store files outside web root

**Defense in Depth:**
- Malware scanning
- Content-type validation
- Audit logging of file access

> **Key Takeaway:** File transfer is an operational concern with AppSec impact when it bypasses application identity, authorization, and auditing controls.

---

## SIEM Fundamentals

> *Related: detection-and-response / security-operations*

### What It Is

A SIEM (Security Information and Event Management) system centralizes logs, normalizes events, correlates activity, and generates alerts. For AppSec, SIEMs provide visibility into how applications are actually used and abused in production.

### Why It Matters (AppSec)

Application vulnerabilities are often detected through behavior, not code review. SIEM data enables AppSec teams to validate threat models, detect exploitation attempts, and measure the real-world impact of security flaws.

### Where It Shows Up

- Authentication and authorization logs
- API access logs
- Error and exception logs
- WAF and gateway events
- Cloud audit logs

### AppSec-Relevant Use Cases

| Use Case | Signals |
|----------|---------|
| Access Control Abuse | Repeated ID changes, forbidden access patterns |
| Auth Attacks | Credential stuffing, brute force attempts |
| Injection Attempts | Suspicious payloads in request parameters |
| Post-Exploitation Signals | Unusual data access or export activity |

### Detection

**Effective AppSec Detection Requires:**
- High-quality, structured application logs
- User, request, and object identifiers
- Consistent event schemas

### Mitigation & Enablement

**AppSec Responsibilities:**
- Define what must be logged
- Ensure logs are tamper-resistant

**Security Operations Responsibilities:**
- Alert tuning
- Incident response workflows

> **Key Takeaway:** SIEMs do not replace AppSec controls. They validate assumptions, surface abuse, and close the loop between detection and remediation.
