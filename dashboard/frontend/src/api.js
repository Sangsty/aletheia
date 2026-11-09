const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

async function getJson(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${path} failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => getJson("/api/health"),
  sessions: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return getJson(`/api/sessions${qs ? `?${qs}` : ""}`);
  },
  statsSummary: () => getJson("/api/stats/summary"),
  statsAttackTypes: () => getJson("/api/stats/attack-types"),
  nodes: () => getJson("/api/nodes"),
  statsCorroboration: () => getJson("/api/stats/corroboration"),
};
