# NetScope Security Policy & Controls

## 1. Security Architecture & Threat Model

NetScope is designed for authorized network infrastructure diagnostics and defensive security assessments within lab, staging, or corporate network boundaries.

```
       [ Client Request ]
               │
               ▼
   ┌──────────────────────┐
   │ SlowAPI Rate Limiter │  -> Rejects abusive request bursts (HTTP 429)
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │ Pydantic Validation  │  -> Blocks malformed inputs, excessive lengths (HTTP 422)
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │ Target Allowlist     │  -> Enforces permitted IP/CIDR/Hostnames (HTTP 403)
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │ Subprocess Sandbox   │  -> Argument array (no shell=True), timeout, semaphore
   └──────────────────────┘
```

---

## 2. Core Security Controls

### 2.1 Target Allowlist Guardrail
- Scanning arbitrary Internet hosts is blocked by default.
- Targets are parsed against the `ALLOWED_TARGETS` configuration in `.env`.
- Supported target definitions:
  - **Loopback addresses**: `127.0.0.1`, `127.0.0.0/8`, `::1`
  - **Private RFC-1918 networks**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - **Explicit hostnames**: e.g., `scanme.nmap.org`, `localhost`
- **DNS Rebinding Prevention**: Hostnames are resolved to IP addresses *prior* to scan execution. Both the resolved IP address and the provided hostname must satisfy the allowlist criteria.
- **Prohibited Destinations**: Cloud metadata endpoints (e.g., `169.254.169.254`, `metadata.google.internal`) are strictly prohibited unless specifically whitelisted in an isolated testing environment.

### 2.2 Subprocess Security & Injection Prevention
- All external tool invocations (`nmap`, `traceroute`) pass arguments as an explicit array (`list[str]`).
- `shell=True` is strictly forbidden across the codebase.
- User input is never concatenated or interpolated into shell command strings.
- Hardcoded, trusted binary paths or resolved system binaries with fixed argument flags are enforced.
- Execution timeouts (`NMAP_QUICK_TIMEOUT`, `NMAP_SERVICE_TIMEOUT`, `NMAP_VULN_TIMEOUT`) prevent runaway or hanging processes.
- An `asyncio.Semaphore` (`MAX_CONCURRENT_SCANS`, default: 2) bounds child process creation to prevent CPU/memory exhaustion.

### 2.3 Application & Transport Security
- **Strict CORS**: Wildcard origins (`*`) are disallowed in production. CORS origins must be explicitly configured via `CORS_ORIGINS`.
- **Rate Limiting**: Configured per endpoint via SlowAPI:
  - Diagnostics: Default 30 requests/minute.
  - Scans: Default 5 requests/minute.
- **Structured Error Sanitization**: Internal exceptions, stack traces, and system file paths are scrubbed from HTTP responses. Client responses return sanitized RFC-7807 problem details.
- **Request Tracing**: A unique `X-Request-ID` UUID is attached to every request and response for correlation in structured logs.

### 2.4 Container Hardening
- Backend Docker container creates and runs as an unprivileged user (`netscope:netscope`, UID: 10001).
- No Docker socket or host root directory mounts.
- Non-root containers prevent host privilege escalation in the event of an application vulnerability.

---

## 3. Assumptions and Known Limitations

1. **Defensive Assessment Only**: NetScope is intended for administrators inspecting systems they own or have written permission to test.
2. **TCP Connect vs SYN Scans**: NetScope runs TCP Connect scans (`-sT`) so it can operate without root / `CAP_NET_RAW` Linux privileges.
3. **Firewall & IDS Caveat**: Diagnostics and Nmap scans may be impacted or dropped by firewalls, NAT devices, or intrusion detection systems. Non-responsive ports cannot be guaranteed to be offline.

---

## 4. Reporting Security Vulnerabilities

If you discover a security vulnerability in NetScope, please report it responsibly:
- **Do not open a public GitHub issue.**
- Submit an email to the maintainers or use GitHub Private Vulnerability Reporting.
- Provide step-by-step reproduction instructions and impact assessment.
