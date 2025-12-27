# File Inclusion (LFI / RFI)

## Overview
File Inclusion vulnerabilities occur when an application allows attackers to
include files through user-controlled input.

Depending on configuration, this can lead to:
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)

These issues often result in sensitive data exposure or remote code execution.

- OWASP Top 10: A03 – Injection
- CWE: 98, 22

---

## Why File Inclusion Happens
File inclusion vulnerabilities typically arise when:
- File paths are constructed from user input
- Input validation is insufficient
- Directory traversal protections are missing
- Legacy configuration options are enabled
- Developers assume files are trusted

---

## Common Indicators
- Parameters such as `file=`, `page=`, `template=`
- Dynamic includes based on request parameters
- Error messages revealing file paths
- Legacy or custom templating logic

---

## Testing Methodology

### 1. Identify File Inclusion Points
Look for endpoints that:
- Load templates or views dynamically
- Include files based on parameters
- Reference filesystem paths

---

### 2. Attempt Path Traversal
Test payloads such as:
../../../../etc/passwd
../config/database.php

Test encoding variations where applicable.

---

### 3. Test Remote Inclusion (If Applicable)
In rare cases, attempt:

Modern frameworks usually block this by default.

---

## Impact
- Disclosure of sensitive configuration files
- Source code exposure
- Credential leakage
- Remote code execution (in severe cases)

---

## Remediation
- Avoid dynamic file includes based on user input
- Use strict allowlists for file references
- Normalize and validate file paths
- Disable remote file inclusion features
- Apply least-privilege filesystem permissions

---

## AppSec Notes
File inclusion vulnerabilities are less common in modern frameworks but still
appear in legacy code and custom implementations.

They often indicate broader issues with input handling and trust boundaries.
