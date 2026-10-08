"""
Aletheia — Blockchain Bridge (Pillar 2 -> Pillar 3)
Connects the Python pipeline's output (an EnrichedThreatRecord + its
SHA-256 hash) to the deployed AletheiaRegistry smart contract.

This is the missing link flagged in the blockchain/README.md — until
now, run_pipeline.py computed a hash and stopped. This module actually
submits that hash on-chain, and lets other nodes corroborate it.

Expects the contract artifact (ABI) at:
    blockchain/artifacts_exported/AletheiaRegistry.json
(exported via `node export_artifact.js` or Hardhat's own compile step
 — see blockchain/README.md)

Usage:
    from chain_bridge import ChainBridge

    bridge = ChainBridge(
        rpc_url="http://127.0.0.1:8545",
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        private_key="0x...",   # the submitting node's account key
    )

    tx_hash = bridge.submit_record(record_hash, attack_type, severity, attck_tags, enrichment_score)
    bridge.corroborate(record_hash)                 # from a DIFFERENT node's bridge instance
    exists, submitter, ts, atype, sev, corrob = bridge.verify(record_hash)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from web3 import Web3


SEVERITY_MAP = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_REVERSE = {v: k for k, v in SEVERITY_MAP.items()}

DEFAULT_ARTIFACT_PATH = (
    Path(__file__).parent.parent.parent / "blockchain" / "artifacts" / "contracts"
    / "AletheiaRegistry.sol" / "AletheiaRegistry.json"
)


class ChainBridge:
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        private_key: Optional[str] = None,
        artifact_path: Optional[Path] = None,
    ):
        self.rpc_url = rpc_url or os.environ.get("ALETHEIA_RPC_URL", "http://127.0.0.1:8545")
        self.contract_address = contract_address or os.environ.get("ALETHEIA_CONTRACT_ADDRESS")
        self.private_key = private_key or os.environ.get("ALETHEIA_PRIVATE_KEY")

        if not self.contract_address:
            raise ValueError(
                "No contract address provided. Pass contract_address=, or set "
                "ALETHEIA_CONTRACT_ADDRESS, after deploying with scripts/deploy.js."
            )

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Could not connect to RPC endpoint: {self.rpc_url}")

        artifact_path = artifact_path or DEFAULT_ARTIFACT_PATH
        with open(artifact_path) as f:
            artifact = json.load(f)
        self.abi = artifact["abi"]

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.contract_address), abi=self.abi
        )

        if self.private_key:
            self.account = self.w3.eth.account.from_key(self.private_key)
        else:
            # Fall back to the node's first unlocked account (fine for local
            # Hardhat/Ganache dev chains; a real PoA deployment should always
            # pass an explicit private_key for the submitting node's identity).
            self.account = None

    @property
    def address(self) -> str:
        if self.account:
            return self.account.address
        return self.w3.eth.accounts[0]

    def _send(self, fn):
        """Builds, signs (if a key was given), sends, and waits for a contract call."""
        if self.account:
            tx = fn.build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address),
                }
            )
            signed = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            tx_hash = fn.transact({"from": self.address})

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt

    @staticmethod
    def _to_bytes32(record_hash: str) -> bytes:
        """Accepts a 64-char hex SHA-256 string (with or without 0x) and returns bytes32."""
        h = record_hash[2:] if record_hash.startswith("0x") else record_hash
        if len(h) != 64:
            raise ValueError(f"record_hash must be a 64-char hex SHA-256 digest, got {len(h)} chars")
        return bytes.fromhex(h)

    def submit_record(
        self,
        record_hash: str,
        attack_type: str,
        severity: str,
        attck_tags: list[str],
        enrichment_score: int,
    ) -> str:
        """
        Submits a new threat record on-chain. Returns the transaction hash (hex string).
        `severity` must be one of: low, medium, high, critical.
        """
        if severity not in SEVERITY_MAP:
            raise ValueError(f"severity must be one of {list(SEVERITY_MAP)}, got {severity!r}")

        hash_bytes = self._to_bytes32(record_hash)
        fn = self.contract.functions.submitRecord(
            hash_bytes, attack_type, SEVERITY_MAP[severity], attck_tags, int(enrichment_score)
        )
        receipt = self._send(fn)
        return receipt.transactionHash.hex()

    def corroborate(self, record_hash: str) -> str:
        """Corroborates an existing record as an independent node. Returns the tx hash."""
        hash_bytes = self._to_bytes32(record_hash)
        fn = self.contract.functions.corroborate(hash_bytes)
        receipt = self._send(fn)
        return receipt.transactionHash.hex()

    def verify(self, record_hash: str) -> dict:
        """Read-only: checks whether a hash exists on-chain and returns its metadata."""
        hash_bytes = self._to_bytes32(record_hash)
        exists, submitter, timestamp, attack_type, severity, corroboration_count = (
            self.contract.functions.verify(hash_bytes).call()
        )
        return {
            "exists": exists,
            "submitting_node": submitter,
            "timestamp": timestamp,
            "attack_type": attack_type,
            "severity": SEVERITY_REVERSE.get(severity, severity),
            "corroboration_count": corroboration_count,
        }

    def get_record_details(self, record_hash: str) -> dict:
        hash_bytes = self._to_bytes32(record_hash)
        attck_tags, enrichment_score = self.contract.functions.getRecordDetails(hash_bytes).call()
        return {"attck_tags": list(attck_tags), "enrichment_score": enrichment_score}

    def has_corroborated(self, record_hash: str, node_address: Optional[str] = None) -> bool:
        """Checks whether a given node has already corroborated this record."""
        hash_bytes = self._to_bytes32(record_hash)
        addr = Web3.to_checksum_address(node_address or self.address)
        return self.contract.functions.hasNodeCorroborated(hash_bytes, addr).call()

    def get_reputation(self, node_address: Optional[str] = None) -> dict:
        addr = Web3.to_checksum_address(node_address or self.address)
        score, total_submissions, total_corroborations_given = (
            self.contract.functions.getReputation(addr).call()
        )
        return {
            "score": score,
            "total_submissions": total_submissions,
            "total_corroborations_given": total_corroborations_given,
        }
