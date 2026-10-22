# NetDigno API Reference (v1)

Base URL: `/api/v1`

Interactive OpenAPI Documentation: `http://localhost:8000/docs` or `http://localhost:8000/redoc`

---

## 1. Standard Error Responses

All error responses return a JSON object adhering to RFC 7807 problem details:

```json
{
  "detail": "Description of the error condition."
}
```

| HTTP Status | Meaning | Typical Trigger |
|:---|:---|:---|
| `400 Bad Request` | Client request syntax invalid | Missing required parameters |
| `403 Forbidden` | Target not permitted | Target not matching configured allowlist |
| `404 Not Found` | Resource does not exist | Invalid scan ID or comparison baseline |
| `422 Unprocessable Entity` | Validation failure | Invalid port range, target length, or profile |
| `429 Too Many Requests` | Rate limit exceeded | Exceeded per-minute request quota |
| `500 Internal Error` | Server execution error | Subprocess crash or database exception |
| `503 Service Unavailable` | Subsystem offline | Nmap scanner binary not installed |

---

## 2. Health & System Status

### `GET /api/v1/health`

Returns application operational readiness and Nmap binary availability.

**Response (200 OK):**
```json
{
  "status": "ok",
  "app_name": "NetDigno",
  "version": "1.0.0",
  "nmap_available": true,
  "nmap_version": "Nmap version 7.95"
}
```

---

## 3. Network Infrastructure Diagnostics

### `POST /api/v1/diagnostics/dns`

Performs DNS A and AAAA record resolution with latency tracking and error classification.

**Request Body:**
```json
{
  "hostname": "scanme.nmap.org"
}
```

**Response (200 OK):**
```json
{
  "hostname": "scanme.nmap.org",
  "ipv4_addresses": ["45.33.32.156"],
  "ipv6_addresses": ["2600:3c01::f03c:91ff:fe18:bb2f"],
  "resolution_success": true,
  "resolution_duration_ms": 14.8,
  "error_category": null,
  "error_detail": null,
  "note": "DNS resolution confirms the hostname maps to the listed addresses at the time of the query. It does not confirm that a service is reachable or that the host is online."
}
```

**Error Categories:**
- `NXDOMAIN`: Domain name does not exist.
- `NO_ANSWER`: No record of the requested type exists.
- `NO_NAMESERVERS`: Upstream DNS nameservers unreachable.
- `TIMEOUT`: DNS lookup timed out.
- `INVALID_HOSTNAME`: Malformed domain name.

---

### `POST /api/v1/diagnostics/tcp`

Performs a bounded TCP connection check to a specific target and port.

**Request Body:**
```json
{
  "target": "127.0.0.1",
  "port": 80,
  "timeout_seconds": 3.0
}
```

**Response (200 OK):**
```json
{
  "target": "127.0.0.1",
  "port": 80,
  "success": true,
  "connection_duration_ms": 1.2,
  "timed_out": false,
  "error_detail": null,
  "note": "A successful TCP connection confirms a connection was established at this moment on this port. A failure may result from filtering, routing, service availability, or network conditions — it does not necessarily mean the entire host is offline."
}
```

---

### `POST /api/v1/diagnostics/route`

Executes route path discovery (`traceroute` or `tracepath`).

**Request Body:**
```json
{
  "target": "scanme.nmap.org",
  "max_hops": 20
}
```

**Response (200 OK):**
```json
{
  "target": "scanme.nmap.org",
  "success": true,
  "hops": [
    {
      "hop": 1,
      "host": "192.168.1.1",
      "ip": "192.168.1.1",
      "rtt_ms": [1.4, 1.2, 1.1]
    }
  ],
  "tool_used": "traceroute",
  "error_detail": null,
  "note": "Route traces may show asterisks (*) for hops where ICMP time-exceeded messages are filtered by intermediate routers."
}
```

---

## 4. Security Assessment & Port Scanning

### `POST /api/v1/scans`

Initiates an asynchronous Nmap port and service scan. Target must match the configured allowlist.

**Request Body:**
```json
{
  "target": "scanme.nmap.org",
  "profile": "service",
  "authorized": true
}
```

**Parameters:**
- `target`: Target hostname or IP address.
- `profile`: Scan profile (`quick`, `service`, `vuln`).
- `authorized`: Operator confirmation acknowledging target authorization. Must be `true`.

**Response (201 Created):**
```json
{
  "id": "e4b9d09e-71fb-4395-8ee0-0bcaebae4691",
  "target": "scanme.nmap.org",
  "profile": "service",
  "status": "running",
  "started_at": "2026-10-22T23:00:00Z",
  "completed_at": null,
  "duration_seconds": null,
  "error_message": null,
  "exit_code": null,
  "findings": []
}
```

---

### `GET /api/v1/scans`

Retrieves a paginated list of historical scans with optional filtering.

**Query Parameters:**
- `target`: Filter by target string (case-insensitive substring).
- `profile`: Filter by profile (`quick`, `service`, `vuln`).
- `scan_status`: Filter by status (`pending`, `running`, `completed`, `failed`, `timeout`).
- `page`: Page number (default: 1).
- `page_size`: Items per page (default: 20, max: 100).

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "e4b9d09e-71fb-4395-8ee0-0bcaebae4691",
      "target": "scanme.nmap.org",
      "profile": "service",
      "status": "completed",
      "started_at": "2026-10-22T23:00:00Z",
      "completed_at": "2026-10-22T23:00:15Z",
      "duration_seconds": 15.2,
      "finding_count": 3
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

---

### `GET /api/v1/scans/{scan_id}`

Retrieves complete scan details and all associated findings.

**Response (200 OK):**
```json
{
  "id": "e4b9d09e-71fb-4395-8ee0-0bcaebae4691",
  "target": "scanme.nmap.org",
  "profile": "service",
  "status": "completed",
  "started_at": "2026-10-22T23:00:00Z",
  "completed_at": "2026-10-22T23:00:15Z",
  "duration_seconds": 15.2,
  "error_message": null,
  "exit_code": 0,
  "findings": [
    {
      "id": "764b8a1c-3bcf-4f9c-9c71-2c0ff52f864e",
      "scan_id": "e4b9d09e-71fb-4395-8ee0-0bcaebae4691",
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.7",
      "cpe": "cpe:/a:apache:http_server:2.4.7",
      "nse_output": null,
      "cve_refs": [],
      "evidence": "80/tcp open http Apache httpd 2.4.7",
      "recorded_at": "2026-10-22T23:00:15Z"
    }
  ]
}
```

---

### `GET /api/v1/scans/compare`

Compares two completed scans against the same target to detect network drift.

**Query Parameters:**
- `baseline_id`: ID of the earlier reference scan.
- `current_id`: ID of the subsequent scan.

**Response (200 OK):**
```json
{
  "baseline_id": "scan-1",
  "current_id": "scan-2",
  "target": "scanme.nmap.org",
  "comparable": true,
  "reason": null,
  "new_open_ports": [
    {
      "port": 3306,
      "protocol": "tcp",
      "service": "mysql",
      "version": "MySQL 8.0.28"
    }
  ],
  "closed_ports": [
    {
      "port": 8080,
      "protocol": "tcp",
      "service": "http-proxy"
    }
  ],
  "service_changes": [
    {
      "port": 22,
      "protocol": "tcp",
      "old_version": "OpenSSH 7.4",
      "new_version": "OpenSSH 8.9"
    }
  ],
  "new_cves": ["CVE-2023-38408"]
}
```
