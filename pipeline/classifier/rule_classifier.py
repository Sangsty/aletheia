"""
Aletheia — Rule-Based Classifier
Pipeline: Pillar 2 (The Brain), Stage 2 → Stage 3
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from session_record import SessionRecord, ClassificationResult, AttackType, Severity

RECON_COMMANDS = {"whoami", "uname", "ifconfig", "ip", "cat", "ls", "id", "pwd", "hostname", "ps", "netstat"}

CRYPTOMINER_SIGNATURES = [
    r"\bxmrig\b", r"\bminerd\b", r"\bstratum\+tcp\b", r"\bcpuminer\b",
    r"\bxmr-stak\b", r"\bcryptonight\b", r"\bmoneroocean\b",
]

BOTNET_SIGNATURES = [
    r"\birc\b", r"\bmirai\b", r"\bgafgyt\b", r"\bqbot\b",
    r"/bin/busybox", r"\bddos\b",
]

REVERSE_SHELL_SIGNATURES = [
    r"/bin/(ba)?sh\s+-i", r"\bnc\s+-e\b", r"\bncat\s+.*-e\b",
    r"/dev/tcp/\d", r"\bsocat\b.*exec", r"\bmkfifo\b",
    r"python[23]?\s+-c\s+.*socket", r"perl\s+-e\s+.*socket",
]

EXFILTRATION_SIGNATURES = [
    r"\bcurl\s+.*(-F|--upload-file|-T)\b", r"\bcurl\s+.*-X\s*POST",
    r"\bwget\s+.*--post-", r"\bscp\s+\S+\s+\S+@", r"\brsync\s+.*@",
    r"base64\s+\S+\s*\|\s*(nc|curl)", r"\btar\s+.*\|\s*(nc|ssh|curl)",
]

PRIVESC_SIGNATURES = [
    r"\bsudo\s+-l\b", r"\bsudo\s+su\b", r"\bchmod\s+(u\+s|4[0-7]{3})\b",
    r"find\s+/\s+.*-perm\s+-4000", r"/etc/sudoers\b", r"\bvisudo\b",
    r"\bpkexec\b", r"\bsu\s+root\b",
]

PERSISTENCE_SIGNATURES = [
    r"\bcrontab\s+-[el]\b", r">>\s*/etc/crontab", r">>\s*/etc/rc\.local",
    r"\bsystemctl\s+enable\b", r">>\s*~?/?\.bashrc", r">>\s*~?/?\.profile",
    r"authorized_keys", r"\buseradd\b", r"\badduser\b",
]

DEFENSE_EVASION_SIGNATURES = [
    r"\bhistory\s+-c\b", r"\bunset\s+HISTFILE\b", r"export\s+HISTSIZE=0",
    r"rm\s+.*\.bash_history", r">\s*~?/?\.bash_history", r"\bshred\b",
    r"rm\s+-rf\s+/var/log", r">\s*/var/log/\S+",
]


def _matches_brute_force(session: SessionRecord) -> bool:
    return len(session.credential_attempts) >= 3


def _matches_reconnaissance(session: SessionRecord) -> bool:
    for cmd in session.command_sequence:
        first_token = cmd.strip().split(" ")[0] if cmd.strip() else ""
        if first_token in RECON_COMMANDS:
            return True
    return False


def _matches_malware_deployment(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    has_download = bool(re.search(r"\b(wget|curl)\b", joined))
    has_chmod = bool(re.search(r"\bchmod\s+\+?x\b", joined))
    has_execute = bool(re.search(r"\./\S+", joined))
    return (has_download and (has_chmod or has_execute)) or len(session.file_artifacts) > 0


def _matches_cryptominer(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in CRYPTOMINER_SIGNATURES)


def _matches_botnet_recruitment(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in BOTNET_SIGNATURES)


def _matches_reverse_shell(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in REVERSE_SHELL_SIGNATURES)


def _matches_exfiltration(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in EXFILTRATION_SIGNATURES)


def _matches_privilege_escalation(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in PRIVESC_SIGNATURES)


def _matches_persistence(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in PERSISTENCE_SIGNATURES)


def _matches_defense_evasion(session: SessionRecord) -> bool:
    joined = " ".join(session.command_sequence).lower()
    return any(re.search(pattern, joined) for pattern in DEFENSE_EVASION_SIGNATURES)


RULES = [
    {
        "name": "cryptominer_signature_match",
        "matcher": _matches_cryptominer,
        "attack_type": AttackType.cryptominer_installation,
        "severity": Severity.critical,
        "attck_ids": ["T1496"],
    },
    {
        "name": "reverse_shell_pattern",
        "matcher": _matches_reverse_shell,
        "attack_type": AttackType.reverse_shell,
        "severity": Severity.critical,
        "attck_ids": ["T1059", "T1071"],
    },
    {
        "name": "exfiltration_pattern",
        "matcher": _matches_exfiltration,
        "attack_type": AttackType.data_exfiltration,
        "severity": Severity.critical,
        "attck_ids": ["T1041", "T1048"],
    },
    {
        "name": "botnet_signature_match",
        "matcher": _matches_botnet_recruitment,
        "attack_type": AttackType.botnet_recruitment,
        "severity": Severity.critical,
        "attck_ids": ["T1071", "T1584"],
    },
    {
        "name": "privilege_escalation_pattern",
        "matcher": _matches_privilege_escalation,
        "attack_type": AttackType.privilege_escalation,
        "severity": Severity.critical,
        "attck_ids": ["T1548", "T1068"],
    },
    {
        "name": "download_chmod_execute_pattern",
        "matcher": _matches_malware_deployment,
        "attack_type": AttackType.malware_deployment,
        "severity": Severity.high,
        "attck_ids": ["T1059.004", "T1105"],
    },
    {
        "name": "persistence_pattern",
        "matcher": _matches_persistence,
        "attack_type": AttackType.persistence_mechanism,
        "severity": Severity.high,
        "attck_ids": ["T1053"],
    },
    {
        "name": "defense_evasion_pattern",
        "matcher": _matches_defense_evasion,
        "attack_type": AttackType.defense_evasion,
        "severity": Severity.high,
        "attck_ids": ["T1070"],
    },
    {
        "name": "recon_command_pattern",
        "matcher": _matches_reconnaissance,
        "attack_type": AttackType.reconnaissance,
        "severity": Severity.medium,
        "attck_ids": ["T1082"],
    },
    {
        "name": "repeated_credential_attempts",
        "matcher": _matches_brute_force,
        "attack_type": AttackType.credential_brute_force,
        "severity": Severity.low,
        "attck_ids": ["T1110"],
    },
]


def classify_session(session: SessionRecord) -> ClassificationResult:
    matched_rules = []
    all_attck_ids: list[str] = []
    primary_attack_type = None
    primary_severity = None

    for rule in RULES:
        if rule["matcher"](session):
            matched_rules.append(rule["name"])
            for tid in rule["attck_ids"]:
                if tid not in all_attck_ids:
                    all_attck_ids.append(tid)
            if primary_attack_type is None:
                primary_attack_type = rule["attack_type"]
                primary_severity = rule["severity"]

    if primary_attack_type is None:
        return ClassificationResult(
            attack_type=AttackType.unclassified,
            severity=Severity.low,
            attck_technique_ids=[],
            matched_rules=[],
        )

    return ClassificationResult(
        attack_type=primary_attack_type,
        severity=primary_severity,
        attck_technique_ids=all_attck_ids,
        matched_rules=matched_rules,
    )


if __name__ == "__main__":
    import json

    sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))
    from session_reconstructor import reconstruct_session

    sample_path = Path(__file__).parent.parent / "ingestion" / "sample_cowrie_session.json"

    events = []
    with open(sample_path) as f:
        for line in f:
            events.append(json.loads(line))

    session = reconstruct_session(events, node_id="node-blr-01")
    classification = classify_session(session)

    print("SessionRecord → ClassificationResult")
    print("=" * 50)
    print(f"Session ID:      {session.session_id}")
    print(f"Source IP:       {session.src_ip}")
    print(f"Attack type:     {classification.attack_type.value}")
    print(f"Severity:        {classification.severity.value}")
    print(f"ATT&CK IDs:      {classification.attck_technique_ids}")
    print(f"Matched rules:   {classification.matched_rules}")