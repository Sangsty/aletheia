from db import fetch_all_records
from collections import Counter

records = fetch_all_records()
unclassified = [r for r in records if r['attack_type'] == 'unclassified']
print(f"Total records: {len(records)}")
print(f"Total unclassified: {len(unclassified)}")

empty_cmds = [r for r in unclassified if len(r['command_sequence']) == 0]
print(f"Unclassified with ZERO commands: {len(empty_cmds)}")
print(f"Unclassified with 1+ commands: {len(unclassified) - len(empty_cmds)}")

print("\nAbuseIPDB categories for unclassified sessions:")
cats = Counter()
for r in unclassified:
    for c in (r['abuseipdb_categories'] or []):
        cats[c] += 1
for c, n in cats.most_common():
    print(f"  {c}: {n}")

print("\nSample unclassified sessions WITH commands (if any):")
for r in unclassified:
    if len(r['command_sequence']) > 0:
        print(f"  session={r['session_id']} commands={r['command_sequence']}")