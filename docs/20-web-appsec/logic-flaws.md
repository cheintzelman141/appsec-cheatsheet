# Logic Flaws

## Overview
Logic flaws occur when an application’s intended business rules can be bypassed
or manipulated, even though technical security controls appear to be functioning
as designed.

These vulnerabilities are not caused by missing patches or misconfigurations,
but by **incorrect assumptions in application logic and workflow design**.

- OWASP Top 10: A04 – Insecure Design
- Commonly chained with: A01 – Broken Access Control

---

## Why Logic Flaws Exist
Logic flaws often arise when:

- Developers assume users will follow the “happy path”
- Business rules are enforced only client-side
- Edge cases are not considered during design
- Complex workflows lack server-side state validation
- Security reviews focus only on technical exploits

Automated scanners rarely detect logic flaws due to their contextual nature.

---

## Common Examples
- Skipping required steps in a workflow
- Reusing tokens, links, or actions multiple times
- Bypassing payment, approval, or verification steps
- Changing application state out of sequence
- Exploiting race conditions
- Abusing discounts, refunds, or credit systems

---

## Testing Methodology

### 1. Understand the Intended Flow
Before testing, identify:

- Required steps and prerequisites
- State transitions
- Validation points
- Assumed user behavior

Compare **how the system is intended to work** versus **how it actually behaves**.

---

### 2. Break Assumptions
Test scenarios such as:

- Skipping steps
- Repeating actions
- Reordering requests
- Using multiple sessions or tabs
- Modifying state-related parameters

---

### 3. Test Edge Cases
Ask questions such as:

- What happens if an action is repeated?
- Can steps be skipped or replayed?
- Are actions reversible?
- Is state consistently validated server-side?

---

## Indicators of Logic Flaws
Common indicators include:

- Client-side enforcement of business rules
- Missing server-side state validation
- Trust in hidden form fields
- Inconsistent responses across workflows
- Successful actions without required prerequisites

These patterns frequently lead to high-impact abuse cases.

---

## Impact
- Financial fraud
- Business rule abuse
- Data integrity violations
- Unauthorized privilege escalation
- Loss of customer trust and revenue

Logic flaws often have **high business impact** despite low technical complexity.

---

## Remediation
Effective remediation focuses on design and prevention:

- Enforce workflows server-side
- Explicitly validate state transitions
- Apply defense-in-depth checks
- Add regression tests for business logic
- Threat model workflows, not just individual endpoints

---

## AppSec Notes
Logic flaws require **contextual understanding**, not tooling.

Effective AppSec work involves:
- partnering with developers
- understanding business intent
- reviewing workflows holistically
- preventing recurrence through tests and design reviews

Many critical incidents originate from logic flaws that were technically
“working as designed.”
