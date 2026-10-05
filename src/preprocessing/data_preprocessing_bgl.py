#!/usr/bin/env python3
"""Parse BGL raw log file and produce a structured CSV.

Usage:
  py -3 data_preprocessing-BGL.py --input BGL_100000.log --output structured_output/bgl_100000_structured.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List

LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUM_RE = re.compile(r"\b\d+\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")


def normalize_template(msg: str) -> str:
    s = IP_RE.sub("<IP>", msg)
    s = HEX_RE.sub("<HEX>", s)
    s = NUM_RE.sub("<NUM>", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def event_id_from_template(template: str) -> str:
    return hashlib.md5(template.encode("utf-8")).hexdigest()[:12]


def parse_timestamp_from_line(line: str) -> str:
    # Try to find detailed timestamp like 2005-06-03-15.42.50.363779
    m = re.search(r"(\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+)", line)
    if m:
        t = m.group(1)
        try:
            dt = datetime.strptime(t, "%Y-%m-%d-%H.%M.%S.%f")
            return dt.isoformat(sep=" ")
        except Exception:
            pass
    # fallback: any ISO-like timestamp
    m2 = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
    if m2:
        return m2.group(1)
    # last resort: unix timestamp
    m3 = re.search(r"\b(1\d{9,})\b", line)
    if m3:
        try:
            return datetime.utcfromtimestamp(int(m3.group(1))).isoformat(sep=" ")
        except Exception:
            pass
    return ""


def infer_source(line: str) -> str:
    # node id patterns like R02-M1-N0-C:J12-U11 or hex hostnames
    m = re.search(r"([A-Z0-9\-]+(?:[:\/]?J?\d+)*)", line)
    return m.group(1) if m else ""


def infer_severity(line: str) -> str:
    m = LEVEL_RE.search(line)
    return m.group(1) if m else ""


def extract_parameters(msg: str, template: str) -> str:
    # crude: parameters are tokens in msg that are not in template after splitting
    tset = set(template.split())
    params = [tok for tok in msg.split() if tok not in tset]
    return json.dumps(params, ensure_ascii=False)


def floor_minute_iso(ts_iso: str) -> str:
    if not ts_iso:
        return ""
    try:
        dt = datetime.fromisoformat(ts_iso)
    except Exception:
        try:
            dt = datetime.strptime(ts_iso, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""
    dt = dt.replace(second=0, microsecond=0)
    return dt.isoformat(sep=" ")


def process_file(input_path: Path, output_path: Path) -> None:
    rows = []
    seq_counters: Dict[str, int] = defaultdict(int)

    with input_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            raw = line.strip()
            if not raw:
                continue

            timestamp = parse_timestamp_from_line(raw)
            source = infer_source(raw)
            severity = infer_severity(raw)
            template = normalize_template(raw)
            eid = event_id_from_template(template)
            params = extract_parameters(raw, template)

            seq_counters[source] += 1
            seq_no = seq_counters[source]

            session_id = floor_minute_iso(timestamp)
            # block id: combine minute session and source/node (or component if available)
            source_for_block = source or ''
            block_id = f"{session_id}|{source_for_block}" if session_id else source_for_block

            row = {
                "log_id": f"log_{idx}",
                "source_id": source,
                "timestamp": timestamp,
                "seq_no": str(seq_no),
                "raw_log": raw,
                "event_id": eid,
                "event_template": template,
                "parameters": params,
                "session_id": session_id,
                "block_id": block_id,
                "severity": severity,
            }
            rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "log_id", "source_id", "timestamp", "seq_no", "raw_log",
        "event_id", "event_template", "parameters", "session_id", "severity",
    ]
    # include block_id column
    if 'block_id' not in fieldnames:
        fieldnames.insert(fieldnames.index('session_id')+1, 'block_id')
    with output_path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(description="BGL preprocessing to structured CSV")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    process_file(args.input, args.output)


if __name__ == "__main__":
    main()
