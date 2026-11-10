import { useEffect, useState } from "react";
import { api } from "../api";

const PIPELINE_STAGES = [
  {
    pillar: "Pillar 1 — The Trap",
    title: "Honeypot capture",
    body:
      "Cowrie SSH/Telnet honeypots run on real cloud nodes, each exposed to the open " +
      "internet so real attackers (not simulated traffic) find and interact with them. " +
      "Every connection, login attempt, shell command, and file transfer an attacker " +
      "makes is logged by Cowrie as raw JSON event lines.",
  },
  {
    pillar: "Pillar 2 — The Brain, stage 1",
    title: "Ingestion & session reconstruction",
    body:
      "Raw Cowrie event logs are pulled from each node and reassembled into one " +
      "SessionRecord per attacker session (grouping connect → login attempts → " +
      "commands → disconnect). An automated incremental-ingest job tracks a byte " +
      "offset per node so re-runs only process new log data, and dedupes by session ID.",
  },
  {
    pillar: "Pillar 2 — The Brain, stage 2",
    title: "Rule-based classification",
    body:
      "Each session is run through a rule-based classifier that pattern-matches its " +
      "command sequence against signatures for 13 attack types (credential brute force, " +
      "reconnaissance, malware deployment, cryptomining, botnet recruitment, reverse " +
      "shells, data exfiltration, privilege escalation, persistence, defense evasion, " +
      "and a few probe/scan patterns), each mapped to one or more real MITRE ATT&CK " +
      "technique IDs. See the Learn page for the full mapping.",
  },
  {
    pillar: "Pillar 2 — The Brain, stage 3",
    title: "Threat-intel enrichment",
    body:
      "Each session's source IP is looked up against AbuseIPDB (abuse confidence score, " +
      "report history) and GreyNoise (mass-scanner noise vs. targeted-actor signal). " +
      "Every enrichment result is tagged as real (live API) or mock, with a per-IP " +
      "database cache so an IP already resolved for real is never re-queried and " +
      "quota isn't wasted on repeats.",
  },
  {
    pillar: "Pillar 3 — The Ledger",
    title: "Blockchain anchoring & federation",
    body:
      "A cryptographic hash of each enriched threat record is submitted on-chain " +
      "(Polygon Amoy testnet), and independent federation nodes can corroborate a " +
      "record they've also observed — giving tamper-evidence and multi-node agreement " +
      "without any single node having to be trusted outright.",
  },
  {
    pillar: "Output",
    title: "STIX 2.1 export",
    body:
      "Every record can be exported as a standards-compliant STIX 2.1 Bundle " +
      "(Indicator + Malware + Attack Pattern objects, cross-referenced to MITRE ATT&CK), " +
      "the interchange format used by MISP, OpenCTI, and most enterprise SIEM/SOAR " +
      "platforms — so this corpus is usable by real-world security tooling, not just " +
      "this dashboard. Use the export buttons on the Overview and Sessions pages.",
  },
];

export default function About() {
  const [nodes, setNodes] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.nodes().then((r) => setNodes(r.nodes)).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="page">
      <div className="about-hero">
        <h2>About Aletheia</h2>
        <p>
          Aletheia is a federated, blockchain-anchored honeypot threat-intelligence
          pipeline. Real attackers hitting real honeypot nodes on three continents feed
          a pipeline that classifies their behavior against MITRE ATT&amp;CK, enriches
          it with external threat-intel context, cryptographically anchors it on-chain,
          and exports it in an industry-standard interchange format.
        </p>
      </div>

      <h3 className="section-heading">Pipeline</h3>
      <div className="about-pipeline">
        {PIPELINE_STAGES.map((stage) => (
          <div className="pipeline-stage" key={stage.title}>
            <div className="pipeline-pillar">{stage.pillar}</div>
            <div className="pipeline-title">{stage.title}</div>
            <div className="pipeline-body">{stage.body}</div>
          </div>
        ))}
      </div>

      <h3 className="section-heading">Node deployment</h3>
      {error && <div className="error">Could not reach the API: {error}</div>}
      <div className="geo-cards">
        {(nodes || [])
          // Nodes with no metadata yet (not A/B/C, e.g. leftover sample
          // data) still get a "pending" card instead of being hidden,
          // so an unmapped node_id is visible, not silently dropped.
          .map((n) => (
            <div className={`geo-card${n.provider ? "" : " geo-card-pending"}`} key={n.node_id}>
              <div className="geo-card-label">{n.node_label}</div>
              {n.provider ? (
                <>
                  <div className="geo-card-provider">{n.provider}</div>
                  <div className="geo-card-region">{n.region}</div>
                  <div className="geo-card-coords mono small">
                    {n.lat.toFixed(2)}°, {n.lon.toFixed(2)}°
                  </div>
                  <div className="geo-card-count">{n.session_count} sessions captured</div>
                </>
              ) : (
                <div className="geo-card-count">Deployment details pending finalization</div>
              )}
            </div>
          ))}
      </div>
    </div>
  );
}
