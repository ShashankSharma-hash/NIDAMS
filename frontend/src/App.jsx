
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronRight,
  Clock3,
  LayoutDashboard,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  X,
  XCircle,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./App.css";
import evaluationData from "./data/eval_results.json";
const API = "http://127.0.0.1:8000";

const severityColors = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
};

const threatLabels = {
  anomaly: "Anomaly",
  path_scan: "Path scan",
  port_scan: "Port scan",
  brute_force: "Brute force",
  flood_dos: "Flood / DoS",
  traffic_spike: "Traffic spike",
  injection: "Injection",
  replay: "Replay",
};

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const seenAlertIdsRef = useRef(null);
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatingId, setUpdatingId] = useState("");
  const [showNotifications, setShowNotifications] = useState(false);  
  

const loadDashboard = useCallback(async () => {
  try {
    setError("");

    const [statsResponse, alertsResponse] = await Promise.all([
      fetch(`${API}/stats`),
      fetch(`${API}/alerts?limit=100`),
    ]);

    if (!statsResponse.ok || !alertsResponse.ok) {
      throw new Error("The backend returned an error.");
    }

    const [statsData, alertsData] = await Promise.all([
      statsResponse.json(),
      alertsResponse.json(),
    ]);

    setStats(statsData);
    setAlerts(alertsData);

    const currentIds = new Set(
      alertsData.map((alert) => alert.alert_id)
    );

    // First load: remember existing alerts without pop-ups.
    if (seenAlertIdsRef.current === null) {
      seenAlertIdsRef.current = currentIds;
    } else {
      const newHighPriorityAlerts = alertsData.filter(
        (alert) =>
          !seenAlertIdsRef.current.has(alert.alert_id) &&
          ["High", "Critical"].includes(alert.severity)
      );

      if (newHighPriorityAlerts.length > 0) {
        setNotifications((previous) =>
          [
            ...newHighPriorityAlerts.map((alert) => ({
              id: alert.alert_id,
              severity: alert.severity,
              threat: alert.threat_type,
              src_ip: alert.src_ip,
            })),
            ...previous,
          ].slice(0, 5)
        );
      }

      seenAlertIdsRef.current = new Set([
        ...seenAlertIdsRef.current,
        ...currentIds,
      ]);
    }
  } catch {
    setError(
      "Cannot reach the backend. Check that FastAPI is running at 127.0.0.1:8000."
    );
  } finally {
    setLoading(false);
  }
}, []);

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(loadDashboard, 10000);
    return () => clearInterval(timer);
  }, [loadDashboard]);

  async function updateStatus(alertId, status) {
    try {
      setUpdatingId(alertId);

      const response = await fetch(
        `${API}/alerts/${encodeURIComponent(alertId)}?status=${status}`,
        { method: "PATCH" }
      );

      if (!response.ok) {
        throw new Error("Could not update alert status.");
      }

      await loadDashboard();
    } catch (err) {
      setError(err.message || "Could not update alert status.");
    } finally {
      setUpdatingId("");
    }
  }

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSeverity =
      severityFilter === "All" || alert.severity === severityFilter;
    const matchesStatus =
      statusFilter === "All" || alert.status === statusFilter;

    const query = search.trim().toLowerCase();
    const matchesSearch =
      !query ||
      [
        alert.alert_id,
        alert.src_ip,
        alert.dst_ip,
        alert.site_id,
        alert.owner,
        alert.threat_type,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));

    return matchesSeverity && matchesStatus && matchesSearch;
  });

  const severityData = Object.entries(stats?.by_severity || {}).map(
    ([name, value]) => ({ name, value })
  );

  const threatData = Object.entries(stats?.by_threat_type || {}).map(
    ([name, count]) => ({
      name: threatLabels[name] || name.replaceAll("_", " "),
      count,
    })
  );

  const highPriority = alerts.filter(
    (alert) =>
      ["Critical", "High"].includes(alert.severity) &&
      alert.status === "new"
  ).length;

function dismissNotification(id) {
  setNotifications((previous) =>
    previous.filter((notification) => notification.id !== id)
  );
}

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Shield size={23} /></div>
          <div>
            <strong>NIDAMS</strong>
            <span>SECURITY CENTER</span>
          </div>
        </div>

        <div className="nav-caption">WORKSPACE</div>
        <div className="nav-item active">
          <LayoutDashboard size={18} /> Overview
        </div>
        <a className="nav-item" href="#alerts">
          <ShieldAlert size={18} /> Security alerts
          <span className="nav-count">{alerts.length}</span>
        </a>
        <a className="nav-item" href="#analytics">
          <Activity size={18} /> Threat analytics
        </a>
        <a className="nav-item" href="#evaluation">
          <CheckCircle2 size={18} /> Evaluation
        </a>

        <div className="sidebar-bottom">
          <div className="system-indicator">
            <span className="live-dot" />
            <div>
              <strong>Monitoring system</strong>
              <span>{error ? "Connection issue" : "API connection active"}</span>
            </div>
          </div>
          <p>NIDAMS · Development environment</p>
        </div>
      </aside>

      <div className="toast-stack" aria-live="polite">
        {notifications.map((notification) => (
          <div
            className={`alert-toast ${notification.severity.toLowerCase()}`}
            key={notification.id}
            role="alert"
          >
            <div className="toast-icon">
              <Siren size={20} />
            </div>

            <div className="toast-copy">
              <strong>
                {notification.severity} Security Alert
              </strong>
              <span>
                {threatLabels[notification.threat] || notification.threat}
              </span>
              <small>
                Source IP: {notification.src_ip || "Unknown"}
              </small>
            </div>

            <button
              className="toast-dismiss"
              aria-label="Dismiss notification"
              onClick={() => dismissNotification(notification.id)}
            >
              <X size={17} />
            </button>
          </div>
        ))}
      </div>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="breadcrumb">Workspace <ChevronRight size={14} /> Overview</div>
            <h1>Security overview</h1>
            <p className="subtitle">Monitor network threats and security incidents.</p>
          </div>
          <div className="top-actions">
            <div className="connection-pill">
              <span className={error ? "status-dot offline" : "status-dot"} />
              {error ? "Disconnected" : "Connected"}
            </div>
            <button className="icon-button" onClick={loadDashboard} title="Refresh">
              <RefreshCw size={17} />
            </button>
            
            <div className="notification-wrapper">
              <button
                type="button"
                className="notification-icon"
                title={`${highPriority} new high-priority alerts`}
                aria-label={`Notifications: ${highPriority} new high-priority alerts`}
                aria-expanded={showNotifications}
                onClick={() =>
                  setShowNotifications((previous) => !previous)
                }
              >
                <Bell size={19} />
                {highPriority > 0 && (
                  <span className="notification-count">
                    {highPriority}
                  </span>
                )}
              </button>

              {showNotifications && (
                <div className="notification-dropdown">
                  <div className="notification-dropdown-header">
                    <div>
                      <strong>Notifications</strong>
                      <p>{highPriority} new high-priority alerts</p>
                    </div>
                    <button
                      type="button"
                      className="notification-close"
                      aria-label="Close notifications"
                      onClick={() => setShowNotifications(false)}
                    >
                      <X size={16} />
                    </button>
                  </div>

                  <div className="notification-list">
                    {alerts
                      .filter(
                        (alert) =>
                          ["Critical", "High"].includes(alert.severity) &&
                          alert.status === "new"
                      )
                      .slice(0, 8)
                      .map((alert) => (
                        <a
                          href="#alerts"
                          className="notification-item"
                          key={alert.alert_id}
                          onClick={() => setShowNotifications(false)}
                        >
                          <span
                            className={`notification-severity-dot ${alert.severity.toLowerCase()}`}
                          />

                          <span className="notification-item-copy">
                            <strong>{alert.severity} alert</strong>
                            <span>
                              {threatLabels[alert.threat_type] ||
                                alert.threat_type}
                            </span>
                            <small>
                              Source: {alert.src_ip || "Unknown"}
                            </small>
                          </span>

                          <ChevronRight size={16} />
                        </a>
                      ))}

                    {highPriority === 0 && (
                      <div className="notification-empty">
                        <ShieldCheck size={22} />
                        <strong>All clear!</strong>
                        <span>No new High or Critical alerts.</span>
                      </div>
                    )}
                  </div>

                  <a
                    href="#alerts"
                    className="notification-footer"
                    onClick={() => setShowNotifications(false)}
                  >
                    View all security alerts
                    <ChevronRight size={15} />
                  </a>
                </div>
              )}
            </div>

          </div>
        </header>

        {error && (
          <div className="error-banner">
            <AlertTriangle size={18} />
            {error}
          </div>
        )}

        <section className="welcome-row">
          <div>
            <h2>Network monitoring dashboard</h2>
            <p>Security events from your detector and alert database.</p>
          </div>
          <div className="last-updated">
            <Clock3 size={15} /> Auto-refreshes every 10 seconds
          </div>
        </section>

        <section className="stats-grid">
          <StatCard
            label="Total alerts"
            value={stats?.total_alerts ?? "—"}
            detail="All stored incidents"
            icon={<Activity />}
            accent="blue"
          />
          <StatCard
            label="Critical severity"
            value={stats?.by_severity?.Critical ?? 0}
            detail="Requires urgent review"
            icon={<Siren />}
            accent="red"
          />
          <StatCard
            label="High severity"
            value={stats?.by_severity?.High ?? 0}
            detail="Priority investigation"
            icon={<AlertTriangle />}
            accent="orange"
          />
          <StatCard
            label="Unresolved alerts"
            value={alerts.filter((a) => a.status !== "resolved").length}
            detail={`${highPriority} new high-priority`}
            icon={<ShieldAlert />}
            accent="purple"
          />
        </section>

        <section className="chart-grid" id="analytics">
          <div className="panel">
            <div className="panel-heading">
              <div>
                <h3>Threat distribution</h3>
                <p>Alerts grouped by detected threat type</p>
              </div>
              <span className="panel-tag">ALL TIME</span>
            </div>
            <div className="chart-area">
              {threatData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={threatData} margin={{ top: 10, right: 8, left: -16, bottom: 42 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#293142" />
                    <XAxis dataKey="name" angle={-30} textAnchor="end" interval={0} tick={{ fill: "#929caf", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fill: "#929caf", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: "#171d29", border: "1px solid #30394b", borderRadius: 8, color: "#f3f5fa" }} />
                    <Bar dataKey="count" fill="#8b78f6" radius={[5, 5, 0, 0]} maxBarSize={40} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <EmptyChart loading={loading} />}
            </div>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <div>
                <h3>Severity breakdown</h3>
                <p>Distribution across all alerts</p>
              </div>
              <span className="panel-tag">SEVERITY</span>
            </div>
            <div className="severity-chart">
              {severityData.length ? (
                <>
                  <ResponsiveContainer width="100%" height={190}>
                    <PieChart>
                      <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={54} outerRadius={78} paddingAngle={4} stroke="none">
                        {severityData.map((entry) => (
                          <Cell key={entry.name} fill={severityColors[entry.name] || "#64748b"} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ background: "#171d29", border: "1px solid #30394b", borderRadius: 8, color: "#f3f5fa" }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="severity-legend">
                    {["Critical", "High", "Medium", "Low"].map((name) => (
                      <div key={name}>
                        <span><i style={{ background: severityColors[name] }} />{name}</span>
                        <strong>{stats?.by_severity?.[name] ?? 0}</strong>
                      </div>
                    ))}
                  </div>
                </>
              ) : <EmptyChart loading={loading} />}
            </div>
          </div>
        </section>

        <section className="panel alerts-panel" id="alerts">
          <div className="panel-heading alerts-heading">
            <div>
              <h3>Recent security alerts</h3>
              <p>Investigate incidents and update their status.</p>
            </div>
            <span className="panel-tag">{filteredAlerts.length} RESULTS</span>
          </div>

          <div className="filters">
            <input
              aria-label="Search alerts"
              placeholder="Search IP, site, threat, or ID..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="All">All severities</option>
              {["Critical", "High", "Medium", "Low"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
              <option value="All">All statuses</option>
              {["new", "acknowledged", "resolved"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>THREAT</th>
                  <th>SOURCE IP</th>
                  <th>SITE</th>
                  <th>SEVERITY</th>
                  <th>DETECTED AT</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td>
                      <div className="threat-cell">
                        <span className="threat-icon"><ShieldAlert size={16} /></span>
                        <div>
                          <strong>{threatLabels[alert.threat_type] || alert.threat_type}</strong>
                          <small>{alert.detected_by || "Unknown method"}</small>
                        </div>
                      </div>
                    </td>
                    <td className="ip-cell">{alert.src_ip}</td>
                    <td>{alert.site_id || "—"}</td>
                    <td><span className={`severity-badge ${String(alert.severity).toLowerCase()}`}>{alert.severity}</span></td>
                    <td className="date-cell">{formatDate(alert.timestamp)}</td>
                    <td><span className={`status-badge ${alert.status}`}>{alert.status}</span></td>
                    <td>
                      <div className="action-buttons">
                        {alert.status === "new" && (
                          <button disabled={updatingId === alert.alert_id} title="Acknowledge" onClick={() => updateStatus(alert.alert_id, "acknowledged")}>
                            <CheckCircle2 size={16} />
                          </button>
                        )}
                        {alert.status !== "resolved" && (
                          <button disabled={updatingId === alert.alert_id} title="Resolve" onClick={() => updateStatus(alert.alert_id, "resolved")}>
                            <ShieldCheck size={16} />
                          </button>
                        )}
                        {alert.status === "resolved" && <span className="resolved-icon"><XCircle size={16} /></span>}
                      </div>
                    </td>
                  </tr>
                ))}
                {!filteredAlerts.length && (
                  <tr><td colSpan="7" className="empty-table">{loading ? "Loading alerts..." : "No alerts match your filters."}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        
        <section className="evaluation-panel" id="evaluation">
          <div className="evaluation-icon">
            <CheckCircle2 size={21} />
          </div>

          <div>
            <h3>Detection Evaluation</h3>
            <p>
              Performance comparison of rule-based, machine-learning,
              and hybrid intrusion detection.
            </p>
          </div>

          <span className="panel-tag">EVALUATION RESULTS</span>

          <div className="evaluation-results">
            {Object.entries(evaluationData.overall).map(
              ([method, metrics]) => (
                <div className="evaluation-card" key={method}>
                  <h4>{method}</h4>

                  <div className="evaluation-metric">
                    <span>Precision</span>
                    <strong>
                      {(metrics.precision * 100).toFixed(1)}%
                    </strong>
                  </div>

                  <div className="evaluation-metric">
                    <span>Recall</span>
                    <strong>
                      {(metrics.recall * 100).toFixed(1)}%
                    </strong>
                  </div>

                  <div className="evaluation-metric">
                    <span>F1-score</span>
                    <strong>
                      {(metrics.f1 * 100).toFixed(1)}%
                    </strong>
                  </div>

                  <div className="evaluation-metric">
                    <span>False-positive rate (reported)</span>
                    <strong>
                      {(metrics.fpr * 100).toFixed(1)}%
                    </strong>
                  </div>
                </div>
              )
            )}
          </div>

          <div className="attack-recall">
            <h3>Detection Recall by Attack Type</h3>
            <p>
              Percentage of attack windows detected for each attack category.
            </p>

            <div className="attack-recall-table">
              <div className="attack-recall-row attack-recall-header">
                <span>Attack type</span>
                <span>Rules</span>
                <span>ML</span>
                <span>Hybrid</span>
              </div>

              {Object.entries(evaluationData.recall_per_attack).map(
                ([attack, scores]) => (
                  <div className="attack-recall-row" key={attack}>
                    <span>{attack.replaceAll("_", " ")}</span>
                    <span>{(scores.rules * 100).toFixed(1)}%</span>
                    <span>{(scores.ml * 100).toFixed(1)}%</span>
                    <span>{(scores.hybrid * 100).toFixed(1)}%</span>
                  </div>
                )
              )}
            </div>
          </div>

          {/* <p className="evaluation-note">
            Evaluation results are from a simulated, held-out test set.
            Verify the reported Hybrid false-positive rate against its
            false-positive count before final reporting.
          </p> */}
        </section>


        <footer>
          <span><Shield size={14} /> NIDAMS · Network Intrusion Detection and Monitoring System</span>
          <span><span className="live-dot" /> Dashboard data refreshes every 10 seconds</span>
        </footer>
      </main>
    </div>
  );
}

function StatCard({ label, value, detail, icon, accent }) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span>{label}</span>
        <span className={`stat-icon ${accent}`}>{icon}</span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-detail">{detail}</div>
    </div>
  );
}

function EmptyChart({ loading }) {
  return <div className="empty-chart">{loading ? "Loading chart..." : "No chart data available"}</div>;
}

export default App;
