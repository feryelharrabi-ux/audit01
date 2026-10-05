import csv
from pathlib import Path

from crypto.hash_chain import LogRecord, build_chain, verify_chain
from crypto.merkle import build_merkle_tree, generate_inclusion_proof, verify_inclusion_proof


ROOT = Path(__file__).resolve().parents[2]


def test_sample_logs_pass_chain_and_merkle_proof():
    path = ROOT / "data" / "processed" / "sample_logs.csv"
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))[:10]
    records = [LogRecord(
        source_id=row["source_id"], seq_no=int(row["seq_no"]), timestamp=row["timestamp"],
        event_id=row["event_id"], event_template=row["event_template"], raw_log=row["raw_log"],
    ) for row in rows]
    chain = build_chain(records)
    assert verify_chain(chain)
    tree = build_merkle_tree([entry.leaf for entry in chain])
    proof = generate_inclusion_proof(tree, 0, "integration-test")
    assert verify_inclusion_proof(proof)