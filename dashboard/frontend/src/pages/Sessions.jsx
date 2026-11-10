import { useEffect, useState } from "react";
import { api } from "../api";
import DataSourceBanner from "../DataSourceBanner";

export default function Sessions() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ attack_type: "", severity: "" });
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const params = {};
    if (filters.attack_type) params.attack_type = filters.attack_type;
    if (filters.severity) params.severity = filters.severity;
    api.sessions(params).then(setResult).catch((e) => setError(e.message));
  }, [filters]);

  async function handleExport() {
    const params = {};
    if (filters.attack_type) params.attack_type = filters.attack_type;
    if (filters.severity) params.severity = filters.severity;
    setExporting(true);
    try {
      const { skipped } = await api.exportStix(params);
      if (skipped) {
        alert(`Exported, but ${skipped} record(s) couldn't be converted and were skipped — check the backend log.`);
      }
    } catch (e) {
      alert(`STIX export failed: ${e.message}`);
    } finally {
      setExporting(false);
    }
  }

  if (error) return <div className="error">Could not reach the API: {error}</div>;
  if (!result) return <div className="loading">Loading…</div>;

  return (
    <div className="page">
      <DataSourceBanner dataSource={result.data_source} />

      <div className="filters">
        <select
          value={filters.severity}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="filter-count">{result.count} sessions</span>
        <button className="export-button export-button-small" onClick={handleExport} disabled={exporting}>
          {exporting ? "Exporting…" : "Export filtered as STIX 2.1 ⬇"}
        </button>
      </div>

      <table className="sessions-table">
        <thead>
          <tr>
            <th>Session</th>
            <th className="nowrap">Node</th>
            <th>Protocol</th>
            <th>Src IP</th>
            <th>Attack type</th>
            <th>Severity</th>
            <th>ATT&amp;CK</th>
            <th>On-chain</th>
          </tr>
        </thead>
        <tbody>
          {result.sessions.map((s) => (
            <tr key={s.session_id}>
              <td className="mono">{s.session_id}</td>
              <td className="nowrap">{s.node_label}</td>
              <td>{s.protocol}</td>
              <td className="mono">{s.src_ip}</td>
              <td>{s.attack_type}</td>
              <td>
                <span className={`severity-pill severity-${s.severity}`}>{s.severity}</span>
              </td>
              <td className="mono small">{(s.attck_technique_ids || []).join(", ")}</td>
              <td>{s.tx_hash ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
