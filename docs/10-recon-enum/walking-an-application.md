# Walking an Application

## Purpose
Walking an application is the process of systematically exploring functionality to
understand the full attack surface before attempting exploitation.

The goal is to build a mental model of:
- exposed functionality
- trust boundaries
- authentication and authorization flows
- hidden or undocumented behavior

This step precedes exploitation and enables targeted, efficient testing.

---

## What to Look For
During exploration, identify:

- All reachable endpoints (UI and API)
- Differences between authenticated and unauthenticated access
- Role-based behavior (user vs admin)
- File upload and download functionality
- API calls made by the frontend
- Error messages, redirects, and response codes

Pay close attention to how the application behaves when inputs change.

---

## Techniques

### Manual Browsing
- Click through all visible functionality
- Observe URL patterns and parameters
- Watch request and response behavior

Manual exploration often reveals logic flaws missed by automated tools.

---

### Proxy-Assisted Exploration
Use an intercepting proxy (e.g., Burp Suite) to:
- Inspect request parameters
- Identify hidden or undocumented API calls
- Replay and modify requests
- Observe differences between client-side and server-side enforcement

---

### Forced Browsing
Attempt direct access to common sensitive paths:
/admin
/dashboard
/api
/debug
/internal


Applications often rely on obscurity or frontend controls instead of proper
server-side authorization.

---

## Red Flags
Indicators of potential vulnerabilities include:

- Sensitive endpoints accessible without authentication
- Different responses when object IDs are modified
- Client-side role enforcement without backend checks
- Missing or inconsistent authorization validation

These patterns frequently lead to IDOR and authorization bypass issues.

---

## AppSec Notes
Walking the application is foundational AppSec work.

A strong understanding of application flow enables:
- effective threat modeling
- discovery of logic flaws
- identification of authorization weaknesses
- mapping attack paths before exploitation

Most impactful vulnerabilities are found by understanding **how the application is
supposed to work** — then testing where those assumptions break.
