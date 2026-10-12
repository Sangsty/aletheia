from db import fetch_all_records
from collections import Counter

records = fetch_all_records()
node_a = [r for r in records if r['node_id'] == 'node-A']
node_b = [r for r in records if r['node_id'] == 'node-B']
node_c = [r for r in records if r['node_id'] == 'node-C']

print(f"Node A total: {len(node_a)}")
print(Counter(r['attack_type'] for r in node_a))
print()
print(f"Node B total: {len(node_b)}")
print(Counter(r['attack_type'] for r in node_b))
print()
print(f"Node C total: {len(node_c)}")
print(Counter(r['attack_type'] for r in node_c))
print()
print(f"Combined total: {len(node_a) + len(node_b) + len(node_c)}")
print(Counter(r['attack_type'] for r in records))