import csv
from datetime import datetime, timezone
from db import fetch_all_records

# Per-node cutoff: the UTC time each node's Cowrie container was restarted
# with the de-fingerprinted config (hostname + SSH banner change).
# Anything with session_start before this is "pre-hardening" baseline data.
HARDENING_CUTOFFS = {
    "node-A": datetime(2026, 10, 12, 8, 40, 0, tzinfo=timezone.utc),
    "node-B": datetime(2026, 10, 12, 9, 5, 0, tzinfo=timezone.utc),
    "node-C": datetime(2026, 10, 12, 9, 20, 0, tzinfo=timezone.utc),
}

records = fetch_all_records()

baseline = [
    r for r in records
    if r["node_id"] in HARDENING_CUTOFFS
    and r["session_start"] is not None
    and r["session_start"].replace(tzinfo=timezone.utc) < HARDENING_CUTOFFS[r["node_id"]]
]

print(f"Total records: {len(records)}")
print(f"Pre-hardening baseline: {len(baseline)}")

if baseline:
    fieldnames = list(baseline[0].keys())
    out_path = "baseline_pre_hardening_2026-10-12.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in baseline:
            writer.writerow(row)
    print(f"Written to {out_path}")
else:
    print("No records matched the baseline window — check session_start format.")