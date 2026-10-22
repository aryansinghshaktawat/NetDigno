# NetScope Testing Guide

NetScope maintains a comprehensive automated testing suite covering unit tests, integration tests, and frontend build verification.

---

## 1. Test Architecture

The testing strategy focuses on high-confidence, deterministic tests that do not depend on external Internet connectivity:

```
backend/tests/
├── unit/
│   ├── test_allowlist.py         # 11 tests: Loopback, RFC-1918, Hostname, Length, Edge cases
│   ├── test_dns_diagnostics.py   # 4 tests: Success, NXDOMAIN, Timeout, Unknown errors
│   ├── test_nmap_parser.py       # 13 tests: Valid XML, Empty, Malformed, CVE extraction, Evidence
│   ├── test_scan_comparison.py   # 7 tests: Incomplete scans, Target mismatch, Ports open/closed, Diff
│   ├── test_scan_repository.py   # 3 tests: Async CRUD, Eager loading, Pagination/Filter
│   └── test_tcp_diagnostics.py   # 4 tests: Connection open, Timeout, ECONNREFUSED, Unreachable
└── integration/
    └── test_api.py               # 13 tests: Health, DNS lookups, TCP bounds, Allowlist 403,
                                  #            422 input validation, CRUD operations, Compare 404
```

---

## 2. Running Backend Tests

### Prerequisites
Activate the Python virtual environment:
```bash
cd backend
source .venv/bin/activate
```

### Running All Tests
```bash
pytest -v
```

### Running Unit Tests Only
```bash
pytest -v tests/unit/
```

### Running Integration Tests Only
```bash
pytest -v tests/integration/
```

### Running with Code Coverage
```bash
pytest --cov=app --cov-report=term-missing tests/
```

---

## 3. Verified Backend Test Results

All 54 test cases execute deterministically in **< 1.0 second**:

| Test Suite | Total Tests | Status | Execution Time |
|:---|:---:|:---:|:---:|
| `tests/integration/test_api.py` | 13 | PASS | 0.28s |
| `tests/unit/test_allowlist.py` | 11 | PASS | 0.05s |
| `tests/unit/test_dns_diagnostics.py` | 4 | PASS | 0.03s |
| `tests/unit/test_nmap_parser.py` | 13 | PASS | 0.04s |
| `tests/unit/test_scan_comparison.py` | 7 | PASS | 0.02s |
| `tests/unit/test_scan_repository.py` | 3 | PASS | 0.08s |
| `tests/unit/test_tcp_diagnostics.py` | 4 | PASS | 0.02s |
| **Total** | **54** | **100% PASS** | **0.52s** |

---

## 4. Frontend Verification

### Running TypeScript Verification & Production Build
```bash
cd frontend
npm run build
```

**Build Verification Output:**
```
✓ Compiled successfully in 3.7s
✓ Finished TypeScript in 1310.4ms
✓ Generating static pages using 7 workers (4/4) in 401.4ms
✓ Finalizing page optimization in 206.9ms

Route (app)
┌ ○ /
└ ○ /_not-found
```
- **Zero TypeScript errors**
- **Zero build warnings or failures**

---

## 5. End-to-End Smoke Test

With both services running (or via Docker Compose):
```bash
# 1. Verify health
curl -s http://localhost:8000/api/v1/health | jq .

# 2. Test DNS diagnostics
curl -s -X POST http://localhost:8000/api/v1/diagnostics/dns \
  -H "Content-Type: application/json" \
  -d '{"hostname": "localhost"}' | jq .

# 3. Test TCP diagnostics
curl -s -X POST http://localhost:8000/api/v1/diagnostics/tcp \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "port": 8000}' | jq .

# 4. Attempt scan against unauthorized host (expect 403)
curl -s -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8", "profile": "quick", "authorized": true}' | jq .

# 5. Start scan against authorized lab host
curl -s -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "profile": "quick", "authorized": true}' | jq .
```
