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
  exportStixUrl: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return `${API_BASE}/api/export/stix${qs ? `?${qs}` : ""}`;
  },
  // Uses fetch() + a blob download instead of a bare <a href> so the
  // caller gets real feedback: a loading state while the (potentially
  // 15-60s, at full-corpus scale) export builds, and a real error
  // message instead of the request silently going nowhere if the
  // backend 404s/500s.
  exportStix: async (params = {}) => {
    const res = await fetch(api.exportStixUrl(params));
    if (!res.ok) {
      let message = res.statusText;
      try {
        const body = await res.json();
        if (body.error) message = body.error;
      } catch {
        // response wasn't JSON — keep statusText
      }
      throw new Error(message);
    }
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const match = cd.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : "aletheia_stix_export.json";

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    const skipped = res.headers.get("X-Aletheia-Skipped-Records");
    return { filename, skipped: skipped ? parseInt(skipped, 10) : 0 };
  },
};
