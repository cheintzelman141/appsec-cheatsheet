# Security Misconfiguration

## What It Is

Security Misconfiguration occurs when applications, frameworks, runtimes, or supporting services are deployed with unsafe defaults, unnecessary features, or inconsistent hardening. It is a systemic class of failure rather than a single bug.

## Why It Matters (AppSec)

Misconfigurations frequently bypass secure code paths, expose sensitive internals, and are common in real production systems. Many major breaches originate from functionality that was never intended to be exposed.

## Where It Shows Up

- Application configuration files
- Framework defaults
- Debug or admin endpoints
- HTTP headers
- Cloud services and managed platforms
- CI/CD and deployment pipelines

## Common Failure Modes

### Debug / Dev Features Enabled

- Debug mode active in production
- Verbose stack traces exposed

### Default Credentials

- Vendor or framework defaults

### Excessive Permissions

- Over-privileged service accounts

### Unnecessary Services

- Admin panels exposed publicly

### Inconsistent Environments

- Security fixes applied unevenly

## Detection

### Manual

- Inspect error handling
- Enumerate endpoints
- Compare dev vs prod behavior

### Automated

- Configuration scanners
- Cloud posture tools

## Mitigation

### Baseline

- Disable debug features in production
- Enforce least privilege
- Remove unused endpoints

### Defense in Depth

- Infrastructure as Code
- Continuous configuration scanning
