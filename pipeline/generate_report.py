"""
Aletheia — Visual Report Generator
Produces a styled, standalone HTML page for an EnrichedThreatRecord,
so the pipeline's output can be shown as a clean visual artifact
instead of raw terminal JSON.

Usage:
    python generate_report.py                        # default sample
    python generate_report.py <path-to-log.json>      # specific log
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_pipeline import run_pipeline

SEVERITY_COLORS = {
    "low": "#4caf50",
    "medium": "#ff9800",
    "high": "#f44336",
    "critical": "#8e24aa",
}

ATTACK_TYPE_LABELS = {
    "credential_brute_force": "Credential Brute Force",
    "reconnaissance": "Reconnaissance",
    "malware_deployment": "Malware Deployment",
    "cryptominer_installation": "Cryptominer Installation",
    "botnet_recruitment": "Botnet Recruitment",
    "unclassified": "Unclassified",
}


def build_html(record, record_hash: str) -> str:
    session = record.session
    classification = record.classification
    enrichment = record.enrichment

    severity = classification.severity.value
    severity_color = SEVERITY_COLORS.get(severity, "#999")
    attack_label = ATTACK_TYPE_LABELS.get(classification.attack_type.value, classification.attack_type.value)

    attck_tags = "".join(
        f'<span class="tag attck-tag">{tid}</span>' for tid in classification.attck_technique_ids
    )
    commands_html = "".join(
        f'<div class="command-line">$ {cmd}</div>' for cmd in session.command_sequence
    ) or '<div class="command-line muted">No commands executed</div>'

    abuse = enrichment.abuseipdb
    greynoise = enrichment.greynoise

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Aletheia — Threat Record {session.session_id}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f1117;
    color: #e6e6e6;
    margin: 0;
    padding: 40px 20px;
  }}
  .card {{
    max-width: 780px;
    margin: 0 auto;
    background: #161925;
    border-radius: 14px;
    padding: 32px;
    box-shadow: 0 8px 30px rgba(0,0,0,0.4);
    border: 1px solid #262a3a;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid #262a3a;
    padding-bottom: 20px;
    margin-bottom: 24px;
  }}
  .header h1 {{
    font-size: 20px;
    margin: 0 0 4px 0;
    color: #ffffff;
  }}
  .header .subtitle {{
    color: #8a8fa3;
    font-size: 13px;
  }}
  .severity-badge {{
    background: {severity_color};
    color: white;
    padding: 6px 16px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }}
  .section {{ margin-bottom: 24px; }}
  .section-title {{
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #6b7086;
    margin-bottom: 10px;
    font-weight: 600;
  }}
  .attack-type {{
    font-size: 24px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 12px;
  }}
  .tag {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-family: 'Consolas', monospace;
    margin-right: 6px;
    margin-bottom: 6px;
  }}
  .attck-tag {{
    background: #262a3a;
    color: #7cb9ff;
    border: 1px solid #33395a;
  }}
  .grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }}
  .stat-box {{
    background: #1c2032;
    border-radius: 8px;
    padding: 14px 16px;
    border: 1px solid #262a3a;
  }}
  .stat-label {{ font-size: 11px; color: #6b7086; margin-bottom: 4px; }}
  .stat-value {{ font-size: 16px; color: #ffffff; font-weight: 600; }}
  .command-line {{
    font-family: 'Consolas', monospace;
    font-size: 13px;
    color: #a8ffb0;
    background: #0d0f16;
    padding: 6px 12px;
    border-radius: 4px;
    margin-bottom: 4px;
  }}
  .command-line.muted {{ color: #6b7086; }}
  .hash-box {{
    font-family: 'Consolas', monospace;
    font-size: 12px;
    color: #ffd479;
    background: #1c2032;
    padding: 14px 16px;
    border-radius: 8px;
    word-break: break-all;
    border: 1px solid #33395a;
  }}
  .footer-note {{
    font-size: 11px;
    color: #6b7086;
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid #262a3a;
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div>
        <h1>Threat Record</h1>
        <div class="subtitle">Session {session.session_id} &middot; Node {session.node_id} &middot; {session.protocol.value.upper()}</div>
      </div>
      <div class="severity-badge">{severity}</div>
    </div>

    <div class="section">
      <div class="section-title">Classification</div>
      <div class="attack-type">{attack_label}</div>
      {attck_tags}
    </div>

    <div class="section">
      <div class="section-title">Session Overview</div>
      <div class="grid">
        <div class="stat-box">
          <div class="stat-label">Source IP</div>
          <div class="stat-value">{session.src_ip}</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Duration</div>
          <div class="stat-value">{session.duration_seconds:.1f}s</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Credential Attempts</div>
          <div class="stat-value">{len(session.credential_attempts)} ({sum(1 for c in session.credential_attempts if c.success)} successful)</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Files Downloaded</div>
          <div class="stat-value">{len(session.file_artifacts)}</div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Command Sequence</div>
      {commands_html}
    </div>

    <div class="section">
      <div class="section-title">External Enrichment</div>
      <div class="grid">
        <div class="stat-box">
          <div class="stat-label">AbuseIPDB Confidence</div>
          <div class="stat-value">{abuse.confidence_score}/100</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">GreyNoise Classification</div>
          <div class="stat-value">{greynoise.classification.value}</div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Blockchain-Ready Hash (SHA-256)</div>
      <div class="hash-box">{record_hash}</div>
    </div>

    <div class="footer-note">
      Aletheia &mdash; Federated Threat Intelligence Verification &middot; Enrichment values are simulated (mock AbuseIPDB/GreyNoise); classification and hashing are real, tested pipeline logic.
    </div>
  </div>
</body>
</html>
"""


if __name__ == "__main__":
    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])
    else:
        log_path = Path(__file__).parent / "ingestion" / "sample_cowrie_session.json"

    record, record_hash = run_pipeline(log_path)
    html = build_html(record, record_hash)

    output_path = Path(__file__).parent / f"report_{record.session.session_id}.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"\nHTML report written to: {output_path}")
