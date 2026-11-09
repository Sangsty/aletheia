import { useEffect, useState } from "react";
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { api } from "../api";
import DataSourceBanner from "../DataSourceBanner";

const SEVERITY_COLORS = {
  critical: "#e5484d",
  high: "#f5a524",
  medium: "#f5d90a",
  low: "#4cc38a",
  unknown: "#888888",
};

const PIE_COLORS = ["#4cc9f0", "#7209b7", "#f72585", "#4361ee", "#4cc38a", "#f5a524"];

export default function Overview() {
  const [summary, setSummary] = useState(null);
  const [attackTypes, setAttackTypes] = useState(null);
  const [corroboration, setCorroboration] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([api.statsSummary(), api.statsAttackTypes(), api.statsCorroboration()])
      .then(([s, a, c]) => {
        setSummary(s);
        setAttackTypes(a);
        setCorroboration(c);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">Could not reach the API: {error}</div>;
  if (!summary || !attackTypes || !corroboration) return <div className="loading">Loading…</div>;

  const severityData = Object.entries(summary.by_severity).map(([name, value]) => ({ name, value }));
  const byNodeData = Object.entries(summary.by_node).map(([name, value]) => ({ name, value }));
  const attackTypeData = Object.entries(attackTypes.overall).map(([name, value]) => ({ name, value }));

  return (
    <div className="page">
      <DataSourceBanner dataSource={summary.data_source} />

      <div className="stat-cards">
        <div className="stat-card">
          <div className="stat-value">{summary.total_sessions}</div>
          <div className="stat-label">Total sessions</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{summary.unclassified_pct}%</div>
          <div className="stat-label">Unclassified</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{corroboration.records_submitted_onchain}</div>
          <div className="stat-label">Submitted on-chain</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{corroboration.total_corroborations}</div>
          <div className="stat-label">Total corroborations</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-panel">
          <h3>Sessions by severity</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis dataKey="name" stroke="#aaa" />
              <YAxis stroke="#aaa" allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#1e1e2a", border: "1px solid #444" }} />
              <Bar dataKey="value">
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#888"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-panel">
          <h3>Sessions by node</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={byNodeData} dataKey="value" nameKey="name" outerRadius={90} label>
                {byNodeData.map((entry, i) => (
                  <Cell key={entry.name} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#1e1e2a", border: "1px solid #444" }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-panel wide">
          <h3>Attack types (overall)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={attackTypeData} layout="vertical" margin={{ left: 140 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis type="number" stroke="#aaa" allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#aaa" width={140} />
              <Tooltip contentStyle={{ background: "#1e1e2a", border: "1px solid #444" }} />
              <Bar dataKey="value" fill="#4cc9f0" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <p className="corroboration-note">{corroboration.note}</p>
    </div>
  );
}
