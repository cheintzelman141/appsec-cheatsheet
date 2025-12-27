# Insecure Direct Object Reference (IDOR)

## Overview
Insecure Direct Object Reference (IDOR) is an authorization vulnerability where an
application exposes direct references to internal objects (IDs, UUIDs, filenames)
without verifying that the authenticated user is authorized to access them.

IDOR is a **Broken Access Control** issue and is one of the most common and impactful
real-world application security vulnerabilities.

- OWASP Top 10: A01 – Broken Access Control
- CWE: 639, 284

---

## Why IDOR Happens
IDOR typically occurs when:
- Authorization checks are missing or incomplete
- Developers assume object IDs are unguessable
- Access control is enforced only at the UI layer
- APIs rely on authentication but skip authorization

This is not a framework issue — it is a **design and implementation failure**.

---

## Types of IDOR

### Horizontal IDOR
Accessing objects belonging to another user at the same privilege level.

**Example:**
- User A accesses User B’s invoice
- User A reads another customer’s order

### Vertical IDOR
Accessing objects or functionality reserved for higher-privileged users.

**Example:**
- Normal user accessing admin-only resources
- Modifying role, permissions, or account status

---

## Common IDOR Indicators
- Numeric or sequential IDs (`/users/123`)
- UUIDs assumed to be secure but not authorized
- Object access controlled only by request parameters
- API endpoints returning different data based on ID alone
- Frontend hiding functionality without backend enforcement

---

## Testing Methodology

### 1. Identify Object References
Look for identifiers in:
- URL paths (`/users/{id}`)
- Query parameters (`?order_id=123`)
- JSON bodies (`"account_id": 456`)
- Headers or cookies

### 2. Modify the Identifier
Attempt:
- Incrementing/decrementing numeric IDs
- Replacing UUIDs with values from another session
- Reusing IDs observed in logs or responses

### 3. Test Authorization Boundaries
- Same-role user → different object
- Lower-role user → higher-privilege object
- Read vs write operations (GET vs PUT/PATCH/DELETE)

### 4. Observe Responses
Vulnerable behavior includes:
- Successful access to unauthorized data
- Partial data leakage
- Silent success (200 OK) on unauthorized actions
- Different error messages revealing object existence

---

## API-Specific IDOR Considerations
IDOR is especially common in APIs due to:
- Stateless design
- Heavy reliance on client-supplied IDs
- Token-based authentication without object-level authorization

Common risky patterns:
```json
GET /api/accounts/789
PATCH /api/users/456
DELETE /api/orders/123
