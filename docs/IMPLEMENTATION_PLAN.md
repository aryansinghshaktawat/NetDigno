# NetScope — Implementation Plan

## 1. Existing Architecture (Pre-Transformation)

### Repository Overview
- **Project name:** vuln-scanner-webapp
- **Last commit:** 2e67251 "application fix"
- **Branch:** main

### Current Directory Structure
```
vuln-scanner-webapp/
├── backend/
│   ├── main.py           # Single-file FastAPI app (307 lines)
│   ├── requirements.txt  # 4 pinned dependencies
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── app/
│   │   ├── page.tsx      # Single-file Next.js UI (327 lines)
│   │   ├── layout.tsx
│   │   └── globals.css
│   ├── package.json      # Next.js 16 + React 19 + Tailwind 4
│   └── Dockerfile
└── docker-compose.yml
```

### Current Working Features
- GET /scan?target=<target> — full Nmap scan + CVE extraction via regex
- GET /scan/quick?target=<target> — port-only scan
- Basic target validation (IP address or DNS resolution check)
- Nmap availability check
- Frontend UI: target input, quick/full scan buttons, ports table, CVE list

---

## 2. Problems Found (Audit)

### Critical Security Issues
| # | Issue | Location | Severity |
|---|-------|----------|----------|
| 1 | allow_origins=["*"] — wildcard CORS | backend/main.py:19 | High |
| 2 | No allowlist for scan targets — any hostname accepted | main.py:30-42 | Critical |
| 3 | validate_target() resolves hostname to validate — inefficient | main.py:30 | Medium |
| 4 | No rate limiting on scan endpoints | main.py | High |
| 5 | Stack traces potentially leaked via HTTPException details | main.py:88 | Medium |

### Architecture Issues
| # | Issue | Location |
|---|-------|----------|
| 6 | All code in a single main.py — not modular | backend/ |
| 7 | No persistence — scan history lost on restart | backend/ |
| 8 | No tests — zero automated tests exist | entire repo |
| 9 | Nmap output parsed via regex on raw text — fragile, no XML parsing | main.py:105-132 |
| 10 | CVE extraction via bare regex — no evidence validation | main.py:200-203 |
| 11 | No versioned API routes | main.py |
| 12 | No health endpoint | main.py |
| 13 | .env.example references env vars that the backend never reads | .env.example |
| 14 | run_nmap_vuln silently discards non-zero exit code on retry | main.py:163-183 |
| 15 | No DNS diagnostics endpoint | missing |
| 16 | No TCP connectivity diagnostics endpoint | missing |
| 17 | No route/traceroute diagnostics endpoint | missing |
| 18 | No scan history UI or API | missing |
| 19 | No snapshot comparison | missing |
| 20 | Docker Compose has no health checks | docker-compose.yml |
| 21 | Backend runs as root in container | Dockerfile |
| 22 | No docs/ directory | repo root |

### Functional Issues
| # | Issue |
|---|-------|
| 23 | Frontend hardcodes 8000 fallback port |
| 24 | Timer in UI client-side only, not correlated to actual scan |
| 25 | CVE counter shown on quick scan (always 0) |
| 26 | Error message displays raw URL in user-facing text |

---

## 3. Proposed Changes

### Phase 1 — Repository Audit (this document)
### Phase 2 — Backend Restructure & Nmap Hardening
### Phase 3 — DNS, TCP, Route Diagnostics
### Phase 4 — Scan History & Persistence
### Phase 5 — Snapshot Comparison & Evidence-Based Findings
### Phase 6 — Frontend Dashboard
### Phase 7 — Tests, Logging, Security Controls
### Phase 8 — Docker & Documentation

---

## 4. Security Risks

| Risk | Mitigation |
|------|------------|
| Scanning arbitrary internet hosts | Configurable allowlist with default lab scope |
| DNS rebinding | Resolve IPs pre-scan and validate against allowlist |
| Shell injection via target input | subprocess with argument list, no shell=True |
| Unbounded process resources | Subprocess timeout + concurrent scan limit |
| Info exposure via error messages | Sanitized error responses, no stack traces |
| Wildcard CORS | Restrict to configured CORS_ORIGINS |
| Secrets in source | All config via environment variables |

---

## 5. Implementation Status

| Phase | Status | Notes |
|-------|--------|-------|
| 1 — Audit | Complete | Problem audit and architectural risk analysis documented |
| 2 — Backend restructure | Complete | Modular app package, Pydantic v2 schemas, async SQLAlchemy ORM |
| 3 — Diagnostics | Complete | dnspython DNS lookups, socket TCP checks, route trace parser |
| 4 — Persistence | Complete | SQLite storage with scans and findings tables, pagination/filters |
| 5 — Comparison and findings | Complete | Drift detection engine with new/closed ports & CVE differences |
| 6 — Frontend dashboard | Complete | Next.js 16 + React 19 single-page dashboard with 4 functional tabs |
| 7 — Tests and security | Complete | 54 automated unit & integration tests passing 100%, allowlist guard |
| 8 — Docker and docs | Complete | Non-root Dockerfile, updated docker-compose, full documentation suite |
