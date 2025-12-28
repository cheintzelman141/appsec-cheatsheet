# Common Ports and Services

## Purpose

This section maps common network ports to services with direct relevance to application security. The focus is exposure risk, misconfiguration impact, and AppSec review considerations — not network exploitation.

---

## Web & Application Services

| Port | Service | Notes |
|------|---------|-------|
| `80` | HTTP | Primary application surface |
| `443` | HTTPS | Primary application surface (encrypted) |
| `8080` | HTTP (alt) | Alternate app or admin interfaces |
| `8443` | HTTPS (alt) | Often forgotten or poorly secured |

**Risks:** IDOR, auth bypass, injection, misconfiguration

---

## Administrative & Remote Access

| Port | Service | Risk |
|------|---------|------|
| `22` | SSH | Exposed management plane |
| `3389` | RDP | Credential exposure, lateral movement |

---

## Databases

| Port | Service | Notes |
|------|---------|-------|
| `3306` | MySQL | Should never be internet-exposed |
| `5432` | PostgreSQL | Should never be internet-exposed |

**Risk:** Direct data access bypassing application controls

---

## Internal Services

| Port | Service | Risk |
|------|---------|------|
| `6379` | Redis | Often deployed without auth — session theft, RCE |
| `9200` | Elasticsearch | Full data exposure if unauthenticated |

---

## AppSec Review Questions

- Is this service intended to be user-facing?
- Is authentication enforced?
- Can access bypass application logic?
- Is network exposure strictly required?
