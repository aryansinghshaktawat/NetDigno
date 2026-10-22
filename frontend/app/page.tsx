"use client";

import { useState, useEffect, useCallback } from "react";
import type {
  HealthResponse,
  DnsResult,
  TcpResult,
  RouteResult,
  ScanOut,
  ScanSummary,
  PaginatedScans,
  ComparisonResult,
  Finding,
  ScanProfile,
} from "../lib/types/api";
import {
  getHealth,
  checkDns,
  checkTcp,
  checkRoute,
} from "../lib/api/diagnostics";
import {
  startScan,
  listScans,
  getScan,
  compareScans,
} from "../lib/api/scans";

// ── Icons (inline SVGs to avoid external dependencies) ───────────────────
const Icon = {
  Network: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/>
      <rect x="9" y="16" width="6" height="6" rx="1"/>
      <path d="M5 8v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8"/><line x1="12" y1="12" x2="12" y2="16"/>
    </svg>
  ),
  Radar: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2a10 10 0 0 1 10 10"/><path d="M12 6a6 6 0 0 1 6 6"/>
      <path d="M12 10a2 2 0 0 1 2 2"/><circle cx="12" cy="12" r="1"/>
    </svg>
  ),
  History: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/>
      <path d="M12 7v5l4 2"/>
    </svg>
  ),
  Shield: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Globe: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  Zap: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
    </svg>
  ),
  Check: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  ),
  X: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  ),
  AlertTriangle: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  Info: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
    </svg>
  ),
  Activity: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  Compare: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 6H3m18 6H3m18 6H3"/><path d="M8 3L4 6l4 3"/><path d="M16 15l4 3-4 3"/>
    </svg>
  ),
};

// ── Utility Components ────────────────────────────────────────────────────
const Spinner = () => <span className="spinner" />;

const StatusBadge = ({ status }: { status: string }) => (
  <span className={`badge badge-${status}`}>{status}</span>
);

const ProfileBadge = ({ profile }: { profile: string }) => (
  <span className={`badge badge-${profile}`}>{profile}</span>
);

const Alert = ({
  type,
  children,
}: {
  type: "error" | "success" | "info" | "warning";
  children: React.ReactNode;
}) => {
  const icons = { error: Icon.X, success: Icon.Check, info: Icon.Info, warning: Icon.AlertTriangle };
  const Ico = icons[type];
  return (
    <div className={`alert alert-${type}`}>
      <Ico />
      <div>{children}</div>
    </div>
  );
};

// ── Tab navigation ────────────────────────────────────────────────────────
type Tab = "overview" | "diagnostics" | "scanner" | "history";
const TABS: { id: Tab; label: string; Icon: React.FC }[] = [
  { id: "overview", label: "Overview", Icon: Icon.Activity },
  { id: "diagnostics", label: "Diagnostics", Icon: Icon.Network },
  { id: "scanner", label: "Scanner", Icon: Icon.Radar },
  { id: "history", label: "History", Icon: Icon.History },
];

// ── Overview Tab ──────────────────────────────────────────────────────────
function OverviewTab({
  health,
  scans,
  onNavigate,
}: {
  health: HealthResponse | null;
  scans: ScanSummary[];
  onNavigate: (tab: Tab) => void;
}) {
  const completed = scans.filter((s) => s.status === "completed").length;
  const failed = scans.filter((s) => s.status === "failed" || s.status === "timeout").length;
  const recentChanges = scans.filter((s) => s.finding_count > 0).length;

  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Health Banner */}
      <div className="card" style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <span className={`pulse-dot ${health?.status === "ok" ? "" : "offline"}`} />
        <div>
          <p style={{ fontWeight: 600 }}>
            {health?.status === "ok" ? "NetScope Backend Online" : "Backend Unavailable"}
          </p>
          <p style={{ fontSize: "0.8125rem", color: "var(--color-text-dim)" }}>
            Version {health?.version ?? "—"} &nbsp;·&nbsp;
            Nmap: {health?.nmap_available ? "Available" : "Not found"}
          </p>
        </div>
        {health && !health.nmap_available && (
          <Alert type="warning">
            Nmap is not installed. Port scanning features are disabled.
          </Alert>
        )}
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "1rem" }}>
        <div className="stat-card">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{scans.length}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Completed</span>
          <span className="stat-value" style={{ color: "var(--color-success)" }}>{completed}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Failed / Timeout</span>
          <span className="stat-value" style={{ color: failed > 0 ? "var(--color-danger)" : undefined }}>{failed}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Scans with Findings</span>
          <span className="stat-value" style={{ color: "var(--color-accent-2)" }}>{recentChanges}</span>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Scans</span>
          <button className="btn btn-secondary" onClick={() => onNavigate("history")} style={{ padding: "0.375rem 0.875rem" }}>
            View All
          </button>
        </div>
        {scans.length === 0 ? (
          <div style={{ textAlign: "center", padding: "2rem", color: "var(--color-text-dim)" }}>
            <p>No scans yet. Start your first scan in the Scanner tab.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Profile</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((scan) => (
                  <tr key={scan.id}>
                    <td className="text-mono">{scan.target}</td>
                    <td><ProfileBadge profile={scan.profile} /></td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td style={{ color: scan.finding_count > 0 ? "var(--color-accent)" : "var(--color-muted)" }}>
                      {scan.finding_count}
                    </td>
                    <td style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>
                      {scan.duration_seconds != null ? `${scan.duration_seconds.toFixed(1)}s` : "—"}
                    </td>
                    <td style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>
                      {new Date(scan.started_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick links */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
        {[
          { label: "Run DNS Lookup", tab: "diagnostics" as Tab, desc: "Resolve hostname to IP addresses" },
          { label: "TCP Port Check", tab: "diagnostics" as Tab, desc: "Test TCP connectivity to a port" },
          { label: "Start Port Scan", tab: "scanner" as Tab, desc: "Discover open ports with Nmap" },
        ].map((link) => (
          <button
            key={link.label}
            className="card btn-secondary"
            onClick={() => onNavigate(link.tab)}
            style={{ textAlign: "left", border: "1px solid var(--color-border)", cursor: "pointer", transition: "all 0.15s" }}
          >
            <p style={{ fontWeight: 600, marginBottom: "0.25rem" }}>{link.label}</p>
            <p style={{ fontSize: "0.8125rem", color: "var(--color-text-dim)" }}>{link.desc}</p>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Diagnostics Tab ───────────────────────────────────────────────────────
function DiagnosticsTab() {
  const [dnsHost, setDnsHost] = useState("");
  const [dnsResult, setDnsResult] = useState<DnsResult | null>(null);
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsError, setDnsError] = useState<string | null>(null);

  const [tcpTarget, setTcpTarget] = useState("");
  const [tcpPort, setTcpPort] = useState("80");
  const [tcpResult, setTcpResult] = useState<TcpResult | null>(null);
  const [tcpLoading, setTcpLoading] = useState(false);
  const [tcpError, setTcpError] = useState<string | null>(null);

  const [routeTarget, setRouteTarget] = useState("");
  const [routeResult, setRouteResult] = useState<RouteResult | null>(null);
  const [routeLoading, setRouteLoading] = useState(false);
  const [routeError, setRouteError] = useState<string | null>(null);

  const runDns = async () => {
    if (!dnsHost.trim()) return;
    setDnsLoading(true);
    setDnsError(null);
    setDnsResult(null);
    try {
      setDnsResult(await checkDns(dnsHost.trim()));
    } catch (e: unknown) {
      setDnsError(e instanceof Error ? e.message : "DNS lookup failed");
    } finally {
      setDnsLoading(false);
    }
  };

  const runTcp = async () => {
    const port = parseInt(tcpPort, 10);
    if (!tcpTarget.trim() || isNaN(port)) return;
    setTcpLoading(true);
    setTcpError(null);
    setTcpResult(null);
    try {
      setTcpResult(await checkTcp(tcpTarget.trim(), port));
    } catch (e: unknown) {
      setTcpError(e instanceof Error ? e.message : "TCP check failed");
    } finally {
      setTcpLoading(false);
    }
  };

  const runRoute = async () => {
    if (!routeTarget.trim()) return;
    setRouteLoading(true);
    setRouteError(null);
    setRouteResult(null);
    try {
      setRouteResult(await checkRoute(routeTarget.trim()));
    } catch (e: unknown) {
      setRouteError(e instanceof Error ? e.message : "Route diagnostics failed");
    } finally {
      setRouteLoading(false);
    }
  };

  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* DNS */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">DNS Resolution</span>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem" }}>
          <input
            value={dnsHost}
            onChange={(e) => setDnsHost(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !dnsLoading && runDns()}
            placeholder="hostname (e.g. scanme.nmap.org)"
            id="dns-hostname"
            disabled={dnsLoading}
          />
          <button className="btn btn-primary" onClick={runDns} disabled={dnsLoading || !dnsHost.trim()} style={{ whiteSpace: "nowrap" }}>
            {dnsLoading ? <Spinner /> : "Resolve"}
          </button>
        </div>
        {dnsError && <Alert type="error">{dnsError}</Alert>}
        {dnsResult && (
          <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
              {dnsResult.resolution_success ? (
                <Alert type="success">
                  Resolved in <strong>{dnsResult.resolution_duration_ms.toFixed(1)} ms</strong>
                </Alert>
              ) : (
                <Alert type="error">
                  {dnsResult.error_category}: {dnsResult.error_detail}
                </Alert>
              )}
            </div>
            {dnsResult.ipv4_addresses.length > 0 && (
              <div>
                <p className="form-label">IPv4 Addresses</p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                  {dnsResult.ipv4_addresses.map((ip) => (
                    <code key={ip} className="text-mono" style={{ background: "var(--color-surface-2)", padding: "0.25rem 0.625rem", borderRadius: "0.375rem", color: "var(--color-accent-2)" }}>{ip}</code>
                  ))}
                </div>
              </div>
            )}
            {dnsResult.ipv6_addresses.length > 0 && (
              <div>
                <p className="form-label">IPv6 Addresses</p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                  {dnsResult.ipv6_addresses.map((ip) => (
                    <code key={ip} className="text-mono" style={{ background: "var(--color-surface-2)", padding: "0.25rem 0.625rem", borderRadius: "0.375rem", color: "var(--color-text-dim)" }}>{ip}</code>
                  ))}
                </div>
              </div>
            )}
            <p className="note-box">{dnsResult.note}</p>
          </div>
        )}
      </div>

      {/* TCP */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">TCP Connectivity</span>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem" }}>
          <div style={{ flex: 3 }}>
            <input
              value={tcpTarget}
              onChange={(e) => setTcpTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !tcpLoading && runTcp()}
              placeholder="IP or hostname (e.g. 127.0.0.1)"
              id="tcp-target"
              disabled={tcpLoading}
            />
          </div>
          <div style={{ flex: 1 }}>
            <input
              value={tcpPort}
              onChange={(e) => setTcpPort(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !tcpLoading && runTcp()}
              placeholder="Port"
              type="number"
              min="1"
              max="65535"
              id="tcp-port"
              disabled={tcpLoading}
            />
          </div>
          <button className="btn btn-primary" onClick={runTcp} disabled={tcpLoading || !tcpTarget.trim()} style={{ whiteSpace: "nowrap" }}>
            {tcpLoading ? <Spinner /> : "Check"}
          </button>
        </div>
        {tcpError && <Alert type="error">{tcpError}</Alert>}
        {tcpResult && (
          <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {tcpResult.success ? (
              <Alert type="success">
                Connection established to {tcpResult.target}:{tcpResult.port} in{" "}
                <strong>{tcpResult.connection_duration_ms?.toFixed(1)} ms</strong>
              </Alert>
            ) : tcpResult.timed_out ? (
              <Alert type="warning">{tcpResult.error_detail}</Alert>
            ) : (
              <Alert type="error">{tcpResult.error_detail ?? "Connection failed"}</Alert>
            )}
            <p className="note-box">{tcpResult.note}</p>
          </div>
        )}
      </div>

      {/* Route */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Route Diagnostics</span>
          <span className="badge badge-pending">Optional</span>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem" }}>
          <input
            value={routeTarget}
            onChange={(e) => setRouteTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !routeLoading && runRoute()}
            placeholder="IP or hostname"
            id="route-target"
            disabled={routeLoading}
          />
          <button className="btn btn-primary" onClick={runRoute} disabled={routeLoading || !routeTarget.trim()} style={{ whiteSpace: "nowrap" }}>
            {routeLoading ? <Spinner /> : "Trace"}
          </button>
        </div>
        {routeError && <Alert type="error">{routeError}</Alert>}
        {routeResult && (
          <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {!routeResult.supported && (
              <Alert type="warning">
                {routeResult.error_detail ?? "Route diagnostics not supported on this platform."}
              </Alert>
            )}
            {routeResult.supported && routeResult.hops.length > 0 && (
              <div className="table-container">
                <table>
                  <thead>
                    <tr><th>Hop</th><th>Address</th><th>RTT</th></tr>
                  </thead>
                  <tbody>
                    {routeResult.hops.map((hop) => (
                      <tr key={hop.hop}>
                        <td style={{ color: "var(--color-text-dim)" }}>{hop.hop}</td>
                        <td className="text-mono">{hop.address ?? "*"}</td>
                        <td style={{ color: hop.rtt_ms != null ? "var(--color-accent-2)" : "var(--color-muted)" }}>
                          {hop.rtt_ms != null ? `${hop.rtt_ms.toFixed(2)} ms` : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {routeResult.supported && routeResult.hops.length === 0 && !routeResult.error_detail && (
              <Alert type="info">Route trace completed but no hops were parsed from the output.</Alert>
            )}
            <p className="note-box">{routeResult.note}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Scanner Tab ───────────────────────────────────────────────────────────
function ScannerTab() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<ScanProfile>("quick");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanOut | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;
    if (loading) {
      timer = setInterval(() => setElapsed((e) => e + 1), 1000);
    } else {
      setElapsed(0);
    }
    return () => clearInterval(timer);
  }, [loading]);

  const PROFILE_TIMEOUTS: Record<ScanProfile, number> = {
    quick: 150_000,
    service: 360_000,
    vuln: 720_000,
  };

  const runScan = async () => {
    if (!target.trim() || !authorized) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await startScan(
        { target: target.trim(), profile, authorized },
        PROFILE_TIMEOUTS[profile]
      );
      setResult(res);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const openFindings = result?.findings.filter((f) => f.state === "open") ?? [];
  const otherFindings = result?.findings.filter((f) => f.state !== "open") ?? [];

  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Configure Scan</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "0.75rem", marginBottom: "1rem" }}>
          <div className="form-group">
            <label className="form-label" htmlFor="scan-target">Target</label>
            <input
              id="scan-target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="IP or hostname (e.g. 127.0.0.1)"
              disabled={loading}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="scan-profile">Profile</label>
            <select id="scan-profile" value={profile} onChange={(e) => setProfile(e.target.value as ScanProfile)} disabled={loading}>
              <option value="quick">Quick (top 100 ports, ~2min)</option>
              <option value="service">Service (top 1000 + versions, ~5min)</option>
              <option value="vuln">Vulnerability (NSE vuln scripts, ~10min)</option>
            </select>
          </div>
        </div>

        <div style={{ marginBottom: "1.25rem", padding: "0.875rem 1rem", background: "var(--color-surface-2)", borderRadius: "0.5rem", border: "1px solid var(--color-border)" }}>
          <label style={{ display: "flex", alignItems: "flex-start", gap: "0.75rem", cursor: loading ? "not-allowed" : "pointer" }}>
            <input
              type="checkbox"
              id="scan-authorized"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              disabled={loading}
              style={{ width: "auto", marginTop: "0.125rem", accentColor: "var(--color-accent)" }}
            />
            <span style={{ fontSize: "0.875rem" }}>
              <strong>I confirm</strong> that I am authorised to scan this target and that it is
              within the configured allowed scope. Unauthorised scanning is illegal and unethical.
            </span>
          </label>
        </div>

        <button
          id="scan-submit"
          className="btn btn-primary"
          onClick={runScan}
          disabled={loading || !target.trim() || !authorized}
          style={{ width: "100%", justifyContent: "center", padding: "0.75rem" }}
        >
          {loading ? (
            <>
              <Spinner />
              Scanning — {Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, "0")} elapsed
            </>
          ) : (
            "Start Scan"
          )}
        </button>

        {loading && (
          <div className="alert alert-info" style={{ marginTop: "1rem" }}>
            <Icon.Info />
            <div>
              Nmap is running. This may take several minutes depending on the profile.
              Do not navigate away.
            </div>
          </div>
        )}
      </div>

      {error && <Alert type="error">{error}</Alert>}

      {result && (
        <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Scan Complete</span>
              <StatusBadge status={result.status} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "1rem" }}>
              <div className="stat-card">
                <span className="stat-label">Target</span>
                <span className="text-mono" style={{ fontSize: "0.875rem", paddingTop: "0.25rem" }}>{result.target}</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Open Ports</span>
                <span className="stat-value" style={{ color: openFindings.length > 0 ? "var(--color-accent)" : undefined }}>
                  {openFindings.length}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Duration</span>
                <span className="stat-value" style={{ fontSize: "1.25rem" }}>
                  {result.duration_seconds != null ? `${result.duration_seconds.toFixed(1)}s` : "—"}
                </span>
              </div>
              <div className="stat-card">
                <span className="stat-label">CVE Refs</span>
                <span className="stat-value" style={{ fontSize: "1.25rem", color: result.findings.some((f) => f.cve_refs?.length) ? "var(--color-danger)" : undefined }}>
                  {result.findings.reduce((acc, f) => acc + (f.cve_refs?.length ?? 0), 0)}
                </span>
              </div>
            </div>
            {result.error_message && (
              <div style={{ marginTop: "1rem" }}>
                <Alert type="warning">{result.error_message}</Alert>
              </div>
            )}
          </div>

          {openFindings.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">Open Ports</span>
                <span className="badge badge-open">{openFindings.length} found</span>
              </div>
              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Proto</th>
                      <th>State</th>
                      <th>Service</th>
                      <th>Version</th>
                      <th>CVE Refs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {openFindings.map((f) => (
                      <tr key={f.id}>
                        <td className="text-mono" style={{ color: "var(--color-accent)" }}>{f.port}</td>
                        <td className="text-mono">{f.protocol}</td>
                        <td><StatusBadge status={f.state ?? "unknown"} /></td>
                        <td>{f.service}</td>
                        <td className="text-mono" style={{ fontSize: "0.75rem", color: "var(--color-text-dim)" }}>{f.version || "—"}</td>
                        <td>
                          {f.cve_refs?.map((cve) => (
                            <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" style={{ display: "block", fontSize: "0.75rem", color: "var(--color-danger)" }}>
                              {cve}
                            </a>
                          )) ?? <span style={{ color: "var(--color-muted)" }}>—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {openFindings.some((f) => f.evidence) && (
            <div className="card">
              <div className="card-header"><span className="card-title">Evidence Notes</span></div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {openFindings.filter((f) => f.evidence).map((f) => (
                  <div key={f.id} style={{ display: "flex", gap: "0.75rem", alignItems: "flex-start" }}>
                    <code className="text-mono" style={{ minWidth: "5rem", color: "var(--color-accent)" }}>{f.port}/{f.protocol}</code>
                    <p className="note-box" style={{ flex: 1 }}>{f.evidence}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.status === "completed" && openFindings.length === 0 && (
            <Alert type="info">
              No open ports were detected in the scanned port range. The target may be filtering connections or the relevant ports are not in the scanned range.
            </Alert>
          )}
        </div>
      )}
    </div>
  );
}

// ── History Tab ───────────────────────────────────────────────────────────
function HistoryTab() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedScan, setSelectedScan] = useState<ScanOut | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [compareMode, setCompareMode] = useState(false);
  const [baselineId, setBaselineId] = useState("");
  const [currentId, setCurrentId] = useState("");
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  const PAGE_SIZE = 15;

  const fetchScans = useCallback(async (p: number) => {
    setLoading(true);
    setError(null);
    try {
      const data = await listScans({ page: p, page_size: PAGE_SIZE });
      setScans(data.items);
      setTotal(data.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load scan history");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans(page);
  }, [page, fetchScans]);

  const viewDetail = async (scanId: string) => {
    setDetailLoading(true);
    setSelectedScan(null);
    try {
      setSelectedScan(await getScan(scanId));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load scan details");
    } finally {
      setDetailLoading(false);
    }
  };

  const runComparison = async () => {
    if (!baselineId.trim() || !currentId.trim()) return;
    setCompareLoading(true);
    setCompareError(null);
    setComparison(null);
    try {
      setComparison(await compareScans(baselineId.trim(), currentId.trim()));
    } catch (e: unknown) {
      setCompareError(e instanceof Error ? e.message : "Comparison failed");
    } finally {
      setCompareLoading(false);
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Scan History</span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn btn-secondary" onClick={() => fetchScans(page)} style={{ padding: "0.375rem 0.875rem" }}>
              Refresh
            </button>
            <button
              className={`btn ${compareMode ? "btn-danger" : "btn-secondary"}`}
              onClick={() => { setCompareMode(!compareMode); setComparison(null); setCompareError(null); }}
              style={{ padding: "0.375rem 0.875rem" }}
            >
              <Icon.Compare /> Compare
            </button>
          </div>
        </div>

        {error && <Alert type="error">{error}</Alert>}
        {loading ? (
          <div style={{ textAlign: "center", padding: "2rem" }}><Spinner /></div>
        ) : scans.length === 0 ? (
          <div style={{ textAlign: "center", padding: "2rem", color: "var(--color-text-dim)" }}>
            No scan history yet. Run scans from the Scanner tab.
          </div>
        ) : (
          <>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Duration</th>
                    <th>Started</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr key={scan.id} style={{ cursor: "pointer" }} onClick={() => viewDetail(scan.id)}>
                      <td className="text-mono" style={{ color: "var(--color-text-dim)", fontSize: "0.7rem" }}>{scan.id.slice(0, 8)}…</td>
                      <td className="text-mono">{scan.target}</td>
                      <td><ProfileBadge profile={scan.profile} /></td>
                      <td><StatusBadge status={scan.status} /></td>
                      <td style={{ color: scan.finding_count > 0 ? "var(--color-accent)" : "var(--color-muted)" }}>
                        {scan.finding_count}
                      </td>
                      <td style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>
                        {scan.duration_seconds != null ? `${scan.duration_seconds.toFixed(1)}s` : "—"}
                      </td>
                      <td style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>
                        {new Date(scan.started_at).toLocaleString()}
                      </td>
                      <td>
                        {compareMode && (
                          <div style={{ display: "flex", gap: "0.375rem" }} onClick={(e) => e.stopPropagation()}>
                            <button className="btn btn-secondary" onClick={() => setBaselineId(scan.id)} style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}>
                              Baseline
                            </button>
                            <button className="btn btn-secondary" onClick={() => setCurrentId(scan.id)} style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}>
                              Current
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div style={{ display: "flex", justifyContent: "center", gap: "0.5rem", paddingTop: "1rem" }}>
                <button className="btn btn-secondary" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
                  ‹ Prev
                </button>
                <span style={{ padding: "0.625rem 0.875rem", color: "var(--color-text-dim)", fontSize: "0.875rem" }}>
                  {page} / {totalPages}
                </span>
                <button className="btn btn-secondary" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
                  Next ›
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Compare panel */}
      {compareMode && (
        <div className="card fade-in">
          <div className="card-header"><span className="card-title">Snapshot Comparison</span></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: "0.75rem", marginBottom: "1rem" }}>
            <div>
              <label className="form-label">Baseline Scan ID</label>
              <input value={baselineId} onChange={(e) => setBaselineId(e.target.value)} placeholder="Baseline scan ID" id="compare-baseline" />
            </div>
            <div>
              <label className="form-label">Current Scan ID</label>
              <input value={currentId} onChange={(e) => setCurrentId(e.target.value)} placeholder="Current scan ID" id="compare-current" />
            </div>
            <div style={{ display: "flex", alignItems: "flex-end" }}>
              <button className="btn btn-primary" onClick={runComparison} disabled={compareLoading || !baselineId.trim() || !currentId.trim()}>
                {compareLoading ? <Spinner /> : "Compare"}
              </button>
            </div>
          </div>
          {compareError && <Alert type="error">{compareError}</Alert>}
          {comparison && (
            <div className="fade-in" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              {!comparison.comparable ? (
                <Alert type="warning">{comparison.reason}</Alert>
              ) : (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem" }}>
                    <div className="stat-card">
                      <span className="stat-label">New Open Ports</span>
                      <span className="stat-value" style={{ color: comparison.new_open_ports.length > 0 ? "var(--color-danger)" : undefined }}>
                        {comparison.new_open_ports.length}
                      </span>
                    </div>
                    <div className="stat-card">
                      <span className="stat-label">Closed Ports</span>
                      <span className="stat-value" style={{ color: comparison.closed_ports.length > 0 ? "var(--color-warning)" : undefined }}>
                        {comparison.closed_ports.length}
                      </span>
                    </div>
                    <div className="stat-card">
                      <span className="stat-label">Version Changes</span>
                      <span className="stat-value" style={{ color: comparison.version_changes.length > 0 ? "var(--color-accent)" : undefined }}>
                        {comparison.version_changes.length}
                      </span>
                    </div>
                  </div>
                  {comparison.new_open_ports.length > 0 && (
                    <div>
                      <p className="form-label" style={{ marginBottom: "0.5rem" }}>Newly Open Ports</p>
                      {comparison.new_open_ports.map((c) => (
                        <div key={`${c.port}-${c.protocol}`} style={{ display: "flex", alignItems: "center", gap: "0.75rem", padding: "0.5rem 0", borderBottom: "1px solid var(--color-border)" }}>
                          <code className="text-mono" style={{ color: "var(--color-danger)" }}>{c.port}/{c.protocol}</code>
                          <span style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>{c.baseline_value} → {c.current_value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {comparison.closed_ports.length > 0 && (
                    <div>
                      <p className="form-label" style={{ marginBottom: "0.5rem" }}>No Longer Open</p>
                      {comparison.closed_ports.map((c) => (
                        <div key={`${c.port}-${c.protocol}`} style={{ display: "flex", alignItems: "center", gap: "0.75rem", padding: "0.5rem 0", borderBottom: "1px solid var(--color-border)" }}>
                          <code className="text-mono" style={{ color: "var(--color-warning)" }}>{c.port}/{c.protocol}</code>
                          <span style={{ color: "var(--color-text-dim)", fontSize: "0.8125rem" }}>was open → {c.current_value}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {comparison.new_open_ports.length === 0 && comparison.closed_ports.length === 0 && comparison.version_changes.length === 0 && (
                    <Alert type="success">No observable changes between these two scans.</Alert>
                  )}
                  <p className="note-box">{comparison.note}</p>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* Detail panel */}
      {(detailLoading || selectedScan) && (
        <div className="card fade-in">
          <div className="card-header">
            <span className="card-title">Scan Detail</span>
            <button className="btn btn-secondary" onClick={() => setSelectedScan(null)} style={{ padding: "0.375rem 0.75rem" }}>
              Close
            </button>
          </div>
          {detailLoading ? (
            <div style={{ textAlign: "center", padding: "1rem" }}><Spinner /></div>
          ) : selectedScan ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "0.75rem" }}>
                <div>
                  <p className="form-label">Target</p>
                  <code className="text-mono">{selectedScan.target}</code>
                </div>
                <div>
                  <p className="form-label">Profile</p>
                  <ProfileBadge profile={selectedScan.profile} />
                </div>
                <div>
                  <p className="form-label">Status</p>
                  <StatusBadge status={selectedScan.status} />
                </div>
                <div>
                  <p className="form-label">Duration</p>
                  <span style={{ fontSize: "0.875rem" }}>
                    {selectedScan.duration_seconds != null ? `${selectedScan.duration_seconds.toFixed(2)}s` : "—"}
                  </span>
                </div>
              </div>
              {selectedScan.error_message && <Alert type="warning">{selectedScan.error_message}</Alert>}
              {selectedScan.findings.length > 0 ? (
                <div className="table-container">
                  <table>
                    <thead>
                      <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>CVEs</th></tr>
                    </thead>
                    <tbody>
                      {selectedScan.findings.map((f) => (
                        <tr key={f.id}>
                          <td className="text-mono" style={{ color: "var(--color-accent)" }}>{f.port}</td>
                          <td className="text-mono">{f.protocol}</td>
                          <td><StatusBadge status={f.state ?? "unknown"} /></td>
                          <td>{f.service}</td>
                          <td className="text-mono" style={{ fontSize: "0.75rem", color: "var(--color-text-dim)" }}>{f.version || "—"}</td>
                          <td style={{ fontSize: "0.75rem" }}>
                            {f.cve_refs?.join(", ") || <span style={{ color: "var(--color-muted)" }}>—</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p style={{ color: "var(--color-text-dim)", fontSize: "0.875rem" }}>No findings recorded for this scan.</p>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────
export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([]);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => {});
    listScans({ page: 1, page_size: 10 }).then((d) => setRecentScans(d.items)).catch(() => {});
  }, []);

  const handleNavigate = (tab: Tab) => setActiveTab(tab);

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      {/* Sidebar */}
      <aside style={{
        width: "240px",
        flexShrink: 0,
        background: "var(--color-surface)",
        borderRight: "1px solid var(--color-border)",
        display: "flex",
        flexDirection: "column",
        padding: "1.25rem 1rem",
      }}>
        {/* Logo */}
        <div style={{ padding: "0.5rem 0.875rem 1.5rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.625rem" }}>
            <div style={{
              width: "32px", height: "32px", borderRadius: "8px",
              background: "linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%)",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Icon.Shield />
            </div>
            <div>
              <p style={{ fontWeight: 700, fontSize: "1rem", letterSpacing: "-0.01em" }}>NetScope</p>
              <p style={{ fontSize: "0.7rem", color: "var(--color-text-dim)", marginTop: "-0.125rem" }}>v1.0.0</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="sidebar-nav" style={{ display: "flex", flexDirection: "column", gap: "0.25rem", flex: 1 }}>
          {TABS.map(({ id, label, Icon: TabIcon }) => (
            <a
              key={id}
              href="#"
              className={activeTab === id ? "active" : ""}
              onClick={(e) => { e.preventDefault(); setActiveTab(id); }}
            >
              <TabIcon />
              {label}
            </a>
          ))}
        </nav>

        {/* Status indicator */}
        <div style={{ padding: "0.875rem", background: "var(--color-surface-2)", borderRadius: "0.5rem", border: "1px solid var(--color-border)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem" }}>
            <span className={`pulse-dot ${health?.status === "ok" ? "" : "offline"}`} />
            <span style={{ fontSize: "0.8125rem", fontWeight: 500 }}>
              {health ? (health.status === "ok" ? "Backend Online" : "Backend Error") : "Connecting…"}
            </span>
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--color-text-dim)" }}>
            Nmap: {health == null ? "…" : health.nmap_available ? "✓ Available" : "✗ Not found"}
          </p>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflow: "auto", padding: "1.75rem 2rem" }}>
        {/* Page header */}
        <div style={{ marginBottom: "1.75rem" }}>
          <h1 style={{ fontSize: "1.375rem", fontWeight: 700, letterSpacing: "-0.02em" }}>
            {TABS.find((t) => t.id === activeTab)?.label}
          </h1>
          <p style={{ fontSize: "0.875rem", color: "var(--color-text-dim)", marginTop: "0.25rem" }}>
            {activeTab === "overview" && "Platform status, recent scans, and quick access to diagnostic workflows."}
            {activeTab === "diagnostics" && "DNS resolution, TCP connectivity, and route diagnostics."}
            {activeTab === "scanner" && "Nmap-based port and service discovery against authorised targets."}
            {activeTab === "history" && "Persistent scan history with snapshot comparison."}
          </p>
        </div>

        {activeTab === "overview" && (
          <OverviewTab health={health} scans={recentScans} onNavigate={handleNavigate} />
        )}
        {activeTab === "diagnostics" && <DiagnosticsTab />}
        {activeTab === "scanner" && <ScannerTab />}
        {activeTab === "history" && <HistoryTab />}
      </main>
    </div>
  );
}
