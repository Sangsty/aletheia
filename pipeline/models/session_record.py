"""
Aletheia — Session Record Models
Pipeline: Pillar 2 (The Brain)

This module defines the structured data contract for a single honeypot
attack session, from raw Cowrie capture through classification,
enrichment, and blockchain submission.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class Protocol(str, Enum):
    ssh = "ssh"
    telnet = "telnet"


class AttackType(str, Enum):
    credential_brute_force = "credential_brute_force"
    reconnaissance = "reconnaissance"
    malware_deployment = "malware_deployment"
    cryptominer_installation = "cryptominer_installation"
    botnet_recruitment = "botnet_recruitment"
    reverse_shell = "reverse_shell"
    data_exfiltration = "data_exfiltration"
    privilege_escalation = "privilege_escalation"
    persistence_mechanism = "persistence_mechanism"
    defense_evasion = "defense_evasion"
    unclassified = "unclassified"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class GreyNoiseClassification(str, Enum):
    noise = "noise"
    targeted = "targeted"
    unknown = "unknown"


class RawCowrieEvent(BaseModel):
    eventid: str
    session: str
    timestamp: datetime
    src_ip: IPvAnyAddress
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[Protocol] = None
    username: Optional[str] = None
    password: Optional[str] = None
    input: Optional[str] = None
    url: Optional[str] = None
    shasum: Optional[str] = None

    class Config:
        extra = "allow"


class CredentialAttempt(BaseModel):
    username: str
    password: str
    success: bool


class FileArtifact(BaseModel):
    url: Optional[str] = None
    sha256: str
    file_size_bytes: Optional[int] = None


class SessionRecord(BaseModel):
    session_id: str
    node_id: str
    protocol: Protocol
    src_ip: IPvAnyAddress
    src_port: Optional[int] = None
    session_start: datetime
    session_end: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    credential_attempts: list[CredentialAttempt] = Field(default_factory=list)
    command_sequence: list[str] = Field(default_factory=list)
    file_artifacts: list[FileArtifact] = Field(default_factory=list)
    behavioral_fingerprint: Optional[str] = None


class ClassificationResult(BaseModel):
    attack_type: AttackType
    severity: Severity
    attck_technique_ids: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)


class AbuseIPDBResult(BaseModel):
    confidence_score: int = Field(..., ge=0, le=100)
    abuse_categories: list[str] = Field(default_factory=list)
    total_reports: int = 0
    isp: Optional[str] = None
    country_code: Optional[str] = None


class GreyNoiseResult(BaseModel):
    classification: GreyNoiseClassification = GreyNoiseClassification.unknown
    actor: Optional[str] = None
    last_seen: Optional[datetime] = None


class EnrichmentResult(BaseModel):
    abuseipdb: Optional[AbuseIPDBResult] = None
    greynoise: Optional[GreyNoiseResult] = None
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChainReference(BaseModel):
    record_hash: str
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    submitted_at: Optional[datetime] = None
    submitting_node: str
    corroboration_count: int = 0


class EnrichedThreatRecord(BaseModel):
    session: SessionRecord
    classification: ClassificationResult
    enrichment: EnrichmentResult
    chain_reference: Optional[ChainReference] = None

    def canonical_dict(self) -> dict:
        return {
            "session_id": self.session.session_id,
            "node_id": self.session.node_id,
            "src_ip": str(self.session.src_ip),
            "session_start": self.session.session_start.isoformat(),
            "attack_type": self.classification.attack_type.value,
            "severity": self.classification.severity.value,
            "attck_technique_ids": self.classification.attck_technique_ids,
            "abuseipdb_score": (
                self.enrichment.abuseipdb.confidence_score
                if self.enrichment.abuseipdb else None
            ),
        }