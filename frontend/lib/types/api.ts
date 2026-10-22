// NetDigno — TypeScript type definitions for all API responses

// ── Health ────────────────────────────────────────────────────────────────
export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  nmap_available: boolean;
}

// ── DNS Diagnostics ───────────────────────────────────────────────────────
export interface DnsResult {
  hostname: string;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  resolution_success: boolean;
  resolution_duration_ms: number;
  error_category?: string;
  error_detail?: string;
  note: string;
}

// ── TCP Diagnostics ───────────────────────────────────────────────────────
export interface TcpResult {
  target: string;
  port: number;
  success: boolean;
  connection_duration_ms?: number;
  timed_out: boolean;
  error_detail?: string;
  note: string;
}

// ── Route Diagnostics ─────────────────────────────────────────────────────
export interface RouteHop {
  hop: number;
  address?: string;
  rtt_ms?: number;
}

export interface RouteResult {
  target: string;
  supported: boolean;
  hops: RouteHop[];
  raw_output?: string;
  error_detail?: string;
  note: string;
}

// ── Scans ─────────────────────────────────────────────────────────────────
export type ScanProfile = 'quick' | 'service' | 'vuln';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'timeout';

export interface Finding {
  id: string;
  scan_id: string;
  port?: number;
  protocol?: string;
  state?: string;
  service?: string;
  version?: string;
  cpe?: string;
  nse_output?: string;
  cve_refs?: string[];
  evidence?: string;
  recorded_at: string;
}

export interface ScanOut {
  id: string;
  target: string;
  profile: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  error_message?: string;
  exit_code?: number;
  findings: Finding[];
}

export interface ScanSummary {
  id: string;
  target: string;
  profile: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  finding_count: number;
}

export interface PaginatedScans {
  total: number;
  page: number;
  page_size: number;
  items: ScanSummary[];
}

// ── Comparison ────────────────────────────────────────────────────────────
export interface PortChange {
  port: number;
  protocol: string;
  change_type: 'new_open' | 'now_closed' | 'version_changed';
  baseline_value?: string;
  current_value?: string;
}

export interface ComparisonResult {
  baseline_scan_id: string;
  current_scan_id: string;
  target: string;
  comparable: boolean;
  reason?: string;
  new_open_ports: PortChange[];
  closed_ports: PortChange[];
  version_changes: PortChange[];
  new_cves?: string[];
  note: string;
}

// ── Error ─────────────────────────────────────────────────────────────────
export interface ApiError {
  detail: string;
}
