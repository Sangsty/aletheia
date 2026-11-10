import { useEffect, useState } from "react";
import { api } from "../api";
import DataSourceBanner from "../DataSourceBanner";

export default function Nodes() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.nodes().then(setResult).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">Could not reach the API: {error}</div>;
  if (!result) return <div className="loading">Loading…</div>;

  return (
    <div className="page">
      <DataSourceBanner dataSource={result.data_source} />
      <div className="node-cards">
        {result.nodes.map((n) => (
          <div className="node-card" key={n.node_id}>
            <div className="node-label">{n.node_label}</div>
            <div className="node-id mono">{n.node_id}</div>
            <div className="node-count">{n.session_count} sessions</div>
            {n.provider ? (
              <div className="node-geo">
                <div className="node-provider">{n.provider}</div>
                <div className="node-region">{n.region}</div>
              </div>
            ) : (
              <div className="node-geo node-geo-pending">Deployment details pending</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
