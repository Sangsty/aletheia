from db import fetch_all_records, get_connection
from collections import Counter

records = fetch_all_records()
empty_unclassified_c = [
    r for r in records
    if r['node_id'] == 'node-C'
    and r['attack_type'] == 'unclassified'
    and r['command_sequence'] == []
]

print(f"Empty-command unclassified sessions on Node C: {len(empty_unclassified_c)}")

conn = get_connection()
try:
    attempt_counts = []
    for r in empty_unclassified_c:
        rows = conn.run(
            "SELECT COUNT(*) FROM credential_attempts WHERE session_id = :sid",
            sid=r["session_uuid"],
        )
        attempt_counts.append(rows[0][0])
finally:
    conn.close()

dist = Counter(attempt_counts)
print("Distribution of credential_attempts count per session:")
for count, freq in sorted(dist.items()):
    print(f"  {count} attempts: {freq} sessions")

at_or_above_3 = sum(freq for count, freq in dist.items() if count >= 3)
print(f"\nSessions with >=3 credential attempts (should have been classified): {at_or_above_3}")