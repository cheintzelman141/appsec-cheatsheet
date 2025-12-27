# Authentication & Authorization Bypass

## Overview
Authentication and authorization bypass vulnerabilities occur when an attacker
can access protected functionality without proper verification of identity or
permissions.

Authentication answers **who** a user is.  
Authorization answers **what** a user is allowed to do.

Failures in either can lead to serious security incidents.

- OWASP Top 10: A01 – Broken Access Control
- OWASP Top 10: A07 – Identification and Authentication Failures

---

## Common Causes
Authentication and authorization bypasses commonly occur due to:

- Missing authorization checks on backend routes
- Reliance on client-side role enforcement
- Inconsistent authorization logic across endpoints
- Insecure session or token handling
- Trust in user-controlled attributes (e.g., `role`, `is_admin`)

---

## Common Bypass Techniques
Attackers may attempt:

- Direct access to protected routes (e.g., `/admin`)
- Parameter tampering (e.g., `role=admin`)
- Token reuse, replay, or manipulation
- Session fixation or session reuse
- Direct interaction with API endpoints bypassing UI controls

---

## Testing Methodology

### 1. Map Authentication Boundaries
Identify and document:
- Public vs authenticated endpoints
- Role-based access differences
- Session or token usage
- Login, logout, and session expiration behavior

Understanding boundaries is required before testing enforcement.

---

### 2. Test Unauthorized Access
Attempt to:
- Access protected routes without authentication
- Access privileged functionality as a lower-privilege user
- Modify role or permission-related parameters
- Reuse or replay session tokens across contexts

---

### 3. Compare Responses
Evaluate server responses for:
- HTTP `200 OK` instead of `401 Unauthorized` or `403 Forbidden`
- Partial or full data exposure
- Error messages that reveal object existence
- Silent failures that still perform unauthorized actions

---

## Indicators of Bypass Vulnerabilities
Red flags include:
- Client-side role or permission checks
- Hidden UI elements without backend enforcement
- Authorization logic missing from APIs
- Trust in cookies or headers without verification

These indicators often precede IDOR or privilege escalation issues.

---

## Impact
- Privilege escalation
- Account takeover
- Unauthorized access to sensitive data
- Full system compromise in severe cases

Authentication and authorization failures often have **high business impact**.

---

## Remediation
Effective remediation requires consistent enforcement:

- Enforce authorization server-side on every request
- Centralize authentication and permission logic
- Apply least-privilege principles
- Validate roles and permissions at runtime
- Add regression tests for access control failures

---

## AppSec Notes
Authentication and authorization bypass issues are rarely isolated.

They often indicate:
- inconsistent security architecture
- duplicated or fragmented authorization logic
- missing guardrails in development workflows

Strong AppSec programs emphasize **consistent enforcement and prevention**, not
one-off fixes.
