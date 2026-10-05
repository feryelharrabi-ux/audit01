#!/usr/bin/env python3
"""Controlled tampering generator with dual-level truth.

This module takes an intact log CSV and generates tampered variants for the
required scenarios:

1. Suppression
2. Injection
3. Modification
4. Reordering
5. Replay
6. Rollback

It produces three CSV files per attack/rate:

- tampered_<attack>_<rate>.csv
- ground_truth_logs_<attack>_<rate>.csv
- ground_truth_blocks_<attack>_<rate>.csv

The log-level truth contains:
log_id, batch_id, attack_type, tampered

The block-level truth contains:
batch_id, attack_type, tampered, original_row_count, tampered_row_count,
tampered_log_count, tampered_log_ids

The default block size is 20 logs.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


CRITICAL_KEYWORDS = (
    "error",
    "warn",
    "warning",
    "fail",
    "failed",
    "exception",
    "critical",
    "panic",
    "abort",
    "terminate",
    "fatal",
)

LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b")
TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
]
IGNORE_COMPARE_FIELDS = {"batch_id", "attack_type", "tampered", "origin_log_id"}
CANONICAL_FIELDS = (
    "log_id", "source_id", "timestamp", "seq_no", "raw_log", "event_id",
    "event_template", "parameters", "session_id", "block_id", "label",
)


@dataclass
class AttackResult:
    tampered_rows: List[Dict[str, str]]
    tampered_ids: set[str]
    extra_truth_rows: List[Dict[str, str]]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def write_csv(rows: Sequence[Dict[str, str]], path: Path, fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def to_float_rate(rate: float) -> float:
    return rate / 100.0 if rate > 1 else rate


def safe_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_timestamp(value: Optional[datetime]) -> str:
    return value.isoformat(sep=" ") if value else ""


def is_critical(row: Dict[str, str]) -> bool:
    haystack = " ".join(
        [
            row.get("raw_log", ""),
            row.get("event_template", ""),
            row.get("source_id", ""),
            row.get("label", ""),
        ]
    ).lower()
    if any(keyword in haystack for keyword in CRITICAL_KEYWORDS):
        return True
    level_match = LEVEL_RE.search(haystack.upper())
    return bool(level_match and level_match.group(1) in {"WARN", "WARNING", "ERROR", "FATAL", "TRACE"})


def make_log_id(index: int, row: Dict[str, str]) -> str:
    value = str(row.get("log_id", "")).strip()
    return value if value else str(index)


def block_id_for_index(index: int, block_size: int) -> str:
    return f"block_{((index - 1) // block_size) + 1:04d}"


def annotate_blocks(rows: List[Dict[str, str]], block_size: int) -> List[Dict[str, str]]:
    annotated: List[Dict[str, str]] = []
    for index, row in enumerate(rows, start=1):
        current = deepcopy(row)
        current.setdefault("log_id", make_log_id(index, current))
        current["batch_id"] = block_id_for_index(index, block_size)
        current.setdefault("attack_type", "clean")
        current.setdefault("tampered", "False")
        current.setdefault("origin_log_id", current.get("log_id", ""))
        annotated.append(current)
    return annotated


def row_signature(row: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted((key, str(value)) for key, value in row.items() if key not in IGNORE_COMPARE_FIELDS))


def chunk_rows(rows: Sequence[Dict[str, str]], block_size: int) -> List[List[Dict[str, str]]]:
    return [list(rows[i : i + block_size]) for i in range(0, len(rows), block_size)]


def group_by_batch(rows: Sequence[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    grouped: Dict[str, List[Dict[str, str]]] = {}
    for row in rows:
        batch_id = str(row.get("batch_id", ""))
        grouped.setdefault(batch_id, []).append(row)
    return grouped


def clone_row(row: Dict[str, str], *, new_log_id: str) -> Dict[str, str]:
    clone = deepcopy(row)
    clone["origin_log_id"] = row.get("origin_log_id", row.get("log_id", ""))
    clone["log_id"] = new_log_id
    clone["tampered"] = "True"
    return clone


def mutate_content(row: Dict[str, str], suffix: str) -> Tuple[str, str, str]:
    raw_log = row.get("raw_log", "")
    event_template = row.get("event_template", "")
    parameters = row.get("parameters", "")
    if raw_log:
        raw_log = f"{raw_log} {suffix}".strip()
    if event_template:
        event_template = f"{event_template} {suffix}".strip()
    if parameters:
        parameters = f"{parameters} | {suffix}"
    return raw_log, event_template, parameters


def mutate_level(level: str) -> str:
    level = level.upper()
    mapping = {
        "DEBUG": "INFO",
        "INFO": "WARN",
        "WARN": "ERROR",
        "WARNING": "ERROR",
        "ERROR": "FATAL",
        "FATAL": "FATAL",
        "TRACE": "WARN",
    }
    return mapping.get(level, "WARN")


def mutate_timestamp(row: Dict[str, str], offset_seconds: int) -> str:
    ts = safe_timestamp(row.get("timestamp", ""))
    if not ts:
        return row.get("timestamp", "")
    return format_timestamp(ts + timedelta(seconds=offset_seconds))


def pick_rows(
    rng: random.Random,
    rows: Sequence[Dict[str, str]],
    count: int,
    predicate=None,
) -> List[Dict[str, str]]:
    candidates = [row for row in rows if predicate(row)] if predicate else list(rows)
    if not candidates or count <= 0:
        return []
    count = min(count, len(candidates))
    return rng.sample(candidates, count)


def make_extra_truth_row(log_id: str, batch_id: str, attack_type: str) -> Dict[str, str]:
    return {
        "log_id": log_id,
        "batch_id": batch_id,
        "attack_type": attack_type,
        "tampered": "True",
    }


def attack_delete_isolated(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows = [row for row in rows if str(row.get("log_id", "")) not in selected_ids]
    return AttackResult(tampered_rows, selected_ids, [])


def attack_delete_contiguous(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    if count >= len(rows):
        selected = list(rows)
    else:
        start = rng.randint(0, len(rows) - count)
        selected = list(rows[start : start + count])
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows = [row for row in rows if str(row.get("log_id", "")) not in selected_ids]
    return AttackResult(tampered_rows, selected_ids, [])


def attack_delete_critical(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    critical_rows = [row for row in rows if is_critical(row)] or list(rows)
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, critical_rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows = [row for row in rows if str(row.get("log_id", "")) not in selected_ids]
    return AttackResult(tampered_rows, selected_ids, [])


def attack_inject_normal(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    base_pool = [row for row in rows if not is_critical(row)] or list(rows)
    tampered_rows = list(rows)
    extra_truth_rows: List[Dict[str, str]] = []
    for index in range(count):
        template = rng.choice(base_pool)
        new_log_id = f"inj_normal_{index + 1}"
        clone = clone_row(template, new_log_id=new_log_id)
        clone["attack_type"] = "inject_normal"
        clone["source_id"] = template.get("source_id", "")
        clone["timestamp"] = template.get("timestamp", "")
        insert_at = rng.randint(0, len(tampered_rows))
        tampered_rows.insert(insert_at, clone)
        extra_truth_rows.append(make_extra_truth_row(new_log_id, template.get("batch_id", ""), "inject_normal"))
    return AttackResult(tampered_rows, set(), extra_truth_rows)


def attack_inject_anomalous(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    base_pool = [row for row in rows if is_critical(row)] or list(rows)
    tampered_rows = list(rows)
    extra_truth_rows: List[Dict[str, str]] = []
    for index in range(count):
        template = rng.choice(base_pool)
        new_log_id = f"inj_anom_{index + 1}"
        clone = clone_row(template, new_log_id=new_log_id)
        clone["attack_type"] = "inject_anomalous"
        clone["label"] = "Anomaly"
        raw_log, event_template, parameters = mutate_content(clone, "[INJECTED_ANOMALY]")
        clone["raw_log"] = raw_log
        clone["event_template"] = event_template
        clone["parameters"] = parameters
        clone["timestamp"] = template.get("timestamp", "")
        tampered_rows.insert(rng.randint(0, len(tampered_rows)), clone)
        extra_truth_rows.append(make_extra_truth_row(new_log_id, template.get("batch_id", ""), "inject_anomalous"))
    return AttackResult(tampered_rows, set(), extra_truth_rows)


def attack_inject_plausible_timestamp(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    tampered_rows = list(rows)
    extra_truth_rows: List[Dict[str, str]] = []
    for index in range(count):
        template = rng.choice(rows)
        new_log_id = f"inj_ts_{index + 1}"
        clone = clone_row(template, new_log_id=new_log_id)
        clone["attack_type"] = "inject_plausible_timestamp"
        ts = safe_timestamp(template.get("timestamp", ""))
        if ts:
            clone["timestamp"] = format_timestamp(ts + timedelta(seconds=rng.randint(1, 120)))
        tampered_rows.insert(rng.randint(0, len(tampered_rows)), clone)
        extra_truth_rows.append(make_extra_truth_row(new_log_id, template.get("batch_id", ""), "inject_plausible_timestamp"))
    return AttackResult(tampered_rows, set(), extra_truth_rows)


def attack_modify_content(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows: List[Dict[str, str]] = []
    for row in rows:
        if str(row.get("log_id", "")) in selected_ids:
            mutated = deepcopy(row)
            raw_log, event_template, parameters = mutate_content(mutated, "[CONTENT_MODIFIED]")
            mutated["raw_log"] = raw_log
            mutated["event_template"] = event_template
            mutated["parameters"] = parameters
            mutated["attack_type"] = "modify_content"
            mutated["tampered"] = "True"
            tampered_rows.append(mutated)
        else:
            tampered_rows.append(row)
    return AttackResult(tampered_rows, selected_ids, [])


def attack_modify_level(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows: List[Dict[str, str]] = []
    for row in rows:
        if str(row.get("log_id", "")) in selected_ids:
            mutated = deepcopy(row)
            level_match = LEVEL_RE.search((mutated.get("raw_log", "") + " " + mutated.get("event_template", "")).upper())
            current_level = level_match.group(1) if level_match else "INFO"
            new_level = mutate_level(current_level)
            mutated["raw_log"] = re.sub(LEVEL_RE, new_level, mutated.get("raw_log", ""), count=1)
            mutated["event_template"] = re.sub(LEVEL_RE, new_level, mutated.get("event_template", ""), count=1)
            mutated["attack_type"] = "modify_level"
            mutated["tampered"] = "True"
            tampered_rows.append(mutated)
        else:
            tampered_rows.append(row)
    return AttackResult(tampered_rows, selected_ids, [])


def attack_modify_timestamp(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count, predicate=lambda row: bool(safe_timestamp(row.get("timestamp", ""))))
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows: List[Dict[str, str]] = []
    for row in rows:
        if str(row.get("log_id", "")) in selected_ids:
            mutated = deepcopy(row)
            mutated["timestamp"] = mutate_timestamp(mutated, rng.randint(-300, 300))
            mutated["attack_type"] = "modify_timestamp"
            mutated["tampered"] = "True"
            tampered_rows.append(mutated)
        else:
            tampered_rows.append(row)
    return AttackResult(tampered_rows, selected_ids, [])


def attack_modify_source(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    source_pool = [row.get("source_id", "") for row in rows if row.get("source_id", "")]
    tampered_rows: List[Dict[str, str]] = []
    for row in rows:
        if str(row.get("log_id", "")) in selected_ids:
            mutated = deepcopy(row)
            choices = [source for source in source_pool if source != mutated.get("source_id", "")]
            mutated["source_id"] = rng.choice(choices) if choices else f"{mutated.get('source_id', 'source')}_alt"
            mutated["attack_type"] = "modify_source_id"
            mutated["tampered"] = "True"
            tampered_rows.append(mutated)
        else:
            tampered_rows.append(row)
    return AttackResult(tampered_rows, selected_ids, [])


def attack_modify_event_id(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    count = max(1, int(len(rows) * rate))
    selected = pick_rows(rng, rows, count)
    selected_ids = {str(row.get("log_id", "")) for row in selected}
    tampered_rows = []
    for row in rows:
        if str(row.get("log_id", "")) in selected_ids:
            mutated = deepcopy(row)
            mutated["event_id"] = f"modified_{mutated.get('event_id', '')}"
            mutated["attack_type"] = "modify_event_id"
            mutated["tampered"] = "True"
            tampered_rows.append(mutated)
        else:
            tampered_rows.append(row)
    return AttackResult(tampered_rows, selected_ids, [])


def attack_permute_two(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    selected = pick_rows(rng, rows, 2)
    if len(selected) < 2:
        return AttackResult(list(rows), set(), [])
    ids = [str(row.get("log_id", "")) for row in selected]
    idx1 = next(i for i, row in enumerate(rows) if str(row.get("log_id", "")) == ids[0])
    idx2 = next(i for i, row in enumerate(rows) if str(row.get("log_id", "")) == ids[1])
    tampered_rows = list(rows)
    tampered_rows[idx1], tampered_rows[idx2] = tampered_rows[idx2], tampered_rows[idx1]
    for row in tampered_rows:
        if str(row.get("log_id", "")) in ids:
            row["attack_type"] = "permute_two_logs"
            row["tampered"] = "True"
    return AttackResult(tampered_rows, set(ids), [])


def attack_reverse_window(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    if len(rows) < 3:
        return AttackResult(list(rows), set(), [])
    window_len = max(2, min(len(rows), int(len(rows) * max(rate, 0.1))))
    start = rng.randint(0, len(rows) - window_len)
    window = list(rows[start : start + window_len])
    reversed_window = list(reversed(window))
    tampered_rows = list(rows)
    tampered_rows[start : start + window_len] = reversed_window
    selected_ids = {str(row.get("log_id", "")) for row in window}
    for row in tampered_rows[start : start + window_len]:
        row["attack_type"] = "reverse_window"
        row["tampered"] = "True"
    return AttackResult(tampered_rows, selected_ids, [])


def attack_move_critical(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    critical_rows = [row for row in rows if is_critical(row)] or list(rows)
    selected = pick_rows(rng, critical_rows, 1)
    if not selected:
        return AttackResult(list(rows), set(), [])
    target = selected[0]
    selected_id = str(target.get("log_id", ""))
    tampered_rows = [row for row in rows if str(row.get("log_id", "")) != selected_id]
    moved = deepcopy(target)
    moved["attack_type"] = "move_critical_event"
    moved["tampered"] = "True"
    tampered_rows.insert(rng.randint(0, len(tampered_rows)), moved)
    return AttackResult(tampered_rows, {selected_id}, [])


def attack_replay(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    if not rows:
        return AttackResult([], set(), [])
    window_len = max(1, min(len(rows), int(len(rows) * max(rate, 0.01))))
    start = rng.randint(0, len(rows) - window_len)
    replay_slice = list(rows[start : start + window_len])
    tampered_rows = list(rows)
    extra_truth_rows: List[Dict[str, str]] = []
    for index, row in enumerate(replay_slice, start=1):
        new_log_id = f"replay_{start + 1}_{index}"
        clone = clone_row(row, new_log_id=new_log_id)
        clone["attack_type"] = "replay"
        tampered_rows.insert(rng.randint(0, len(tampered_rows)), clone)
        extra_truth_rows.append(make_extra_truth_row(new_log_id, row.get("batch_id", ""), "replay"))
    return AttackResult(tampered_rows, set(), extra_truth_rows)


def attack_rollback(rows: List[Dict[str, str]], rate: float, rng: random.Random) -> AttackResult:
    grouped = group_by_batch(rows)
    batches = [item for item in grouped.items() if item[1]]
    if len(batches) < 2:
        return AttackResult(list(rows), set(), [])
    old_batch_id, old_rows = rng.choice(batches)
    recent_candidates = [item for item in batches if item[0] != old_batch_id]
    recent_batch_id, recent_rows = rng.choice(recent_candidates)
    count = max(1, min(len(recent_rows), int(len(rows) * max(rate, 0.01))))
    replace_targets = recent_rows[:count]
    replacement_source = old_rows[:count] if len(old_rows) >= count else old_rows
    tampered_rows = list(rows)
    tampered_ids: set[str] = set()
    extra_truth_rows: List[Dict[str, str]] = []
    for target, source in zip(replace_targets, replacement_source):
        target_id = str(target.get("log_id", ""))
        tampered_ids.add(target_id)
        idx = next(i for i, row in enumerate(tampered_rows) if str(row.get("log_id", "")) == target_id)
        replacement = deepcopy(source)
        replacement["log_id"] = f"rollback_{target_id}"
        replacement["origin_log_id"] = source.get("origin_log_id", source.get("log_id", ""))
        replacement["attack_type"] = "rollback"
        replacement["tampered"] = "True"
        tampered_rows[idx] = replacement
        extra_truth_rows.append(make_extra_truth_row(replacement["log_id"], recent_batch_id, "rollback"))
    return AttackResult(tampered_rows, tampered_ids, extra_truth_rows)


ATTACKS = {
    "delete_isolated": attack_delete_isolated,
    "delete_contiguous": attack_delete_contiguous,
    "delete_critical": attack_delete_critical,
    "inject_normal": attack_inject_normal,
    "inject_anomalous": attack_inject_anomalous,
    "inject_plausible_timestamp": attack_inject_plausible_timestamp,
    "modify_content": attack_modify_content,
    "modify_level": attack_modify_level,
    "modify_timestamp": attack_modify_timestamp,
    "modify_source_id": attack_modify_source,
    "modify_event_id": attack_modify_event_id,
    "permute_two_logs": attack_permute_two,
    "reverse_window": attack_reverse_window,
    "move_critical_event": attack_move_critical,
    "replay": attack_replay,
    "rollback": attack_rollback,
}


def run_attack(rows: List[Dict[str, str]], attack_name: str, rate: float, seed: int, block_size: int) -> AttackResult:
    if attack_name not in ATTACKS:
        raise ValueError(f"Unknown attack: {attack_name}")
    rng = random.Random(seed)
    normalized_rows = annotate_blocks(rows, block_size)
    return ATTACKS[attack_name](normalized_rows, rate, rng)


def build_log_truth(
    original_rows: Sequence[Dict[str, str]],
    tampered_rows: Sequence[Dict[str, str]],
    attack_name: str,
    tampered_ids: Iterable[str],
    extra_truth_rows: Sequence[Dict[str, str]],
    block_size: int,
) -> List[Dict[str, str]]:
    tampered_set = {str(log_id) for log_id in tampered_ids}
    truth: List[Dict[str, str]] = []
    original_by_id = {str(row.get("log_id", "")): row for row in original_rows}
    after_by_id = {str(row.get("log_id", "")): index for index, row in enumerate(tampered_rows, start=1)}
    changed_ids = tampered_set | {
        str(row.get("log_id", "")) for row in extra_truth_rows
    }
    for index, row in enumerate(original_rows, start=1):
        log_id = str(row.get("log_id", ""))
        after_index = after_by_id.get(log_id)
        after_row = tampered_rows[after_index - 1] if after_index else None
        changed_fields = [
            field for field in CANONICAL_FIELDS
            if after_row is not None and str(row.get(field, "")) != str(after_row.get(field, ""))
        ]
        deleted = after_index is None
        truth.append(
            {
                "log_id": log_id,
                "batch_id": block_id_for_index(index, block_size),
                "original_position": str(index),
                "position_after": str(after_index or ""),
                "attack_type": attack_name if log_id in changed_ids or deleted else "clean",
                "intensity": "",
                "modified_fields": ",".join(changed_fields),
                "is_deleted": "True" if deleted else "False",
                "tampered": "True" if log_id in changed_ids or deleted else "False",
            }
        )
    for extra in extra_truth_rows:
        log_id = str(extra.get("log_id", ""))
        after_index = after_by_id.get(log_id)
        truth.append({
            "log_id": log_id,
            "batch_id": extra.get("batch_id", ""),
            "original_position": "",
            "position_after": str(after_index or ""),
            "attack_type": attack_name,
            "intensity": "",
            "modified_fields": "injected",
            "is_deleted": "False",
            "tampered": "True",
        })
    return truth


def block_equivalent(original_block: Sequence[Dict[str, str]], tampered_block: Sequence[Dict[str, str]]) -> bool:
    if len(original_block) != len(tampered_block):
        return False
    original_signatures = [row_signature(row) for row in original_block]
    tampered_signatures = [row_signature(row) for row in tampered_block]
    return original_signatures == tampered_signatures


def build_block_truth(
    original_rows: Sequence[Dict[str, str]],
    tampered_rows: Sequence[Dict[str, str]],
    attack_name: str,
    block_size: int,
) -> List[Dict[str, str]]:
    original_blocks = chunk_rows(original_rows, block_size)
    original_positions = {
        str(row.get("log_id", "")): index
        for index, row in enumerate(original_rows, start=1)
    }
    tampered_positions = {
        str(row.get("log_id", "")): index
        for index, row in enumerate(tampered_rows, start=1)
    }
    tampered_ids = {str(row.get("log_id", "")) for row in tampered_rows}
    total_blocks = len(original_blocks)
    truth: List[Dict[str, str]] = []
    for index in range(total_blocks):
        block_id = f"block_{index + 1:04d}"
        original_block = original_blocks[index] if index < len(original_blocks) else []
        tampered_block = tampered_blocks[index] if index < len(tampered_blocks) else []
        original_ids = {str(row.get("log_id", "")) for row in original_block}
        surviving_originals = original_ids & tampered_ids
        deleted_ids = original_ids - surviving_originals
        changed_ids = {
            log_id for log_id in surviving_originals
            if original_positions[log_id] != tampered_positions[log_id]
            or row_signature(original_rows[original_positions[log_id] - 1]) != row_signature(
                next(row for row in tampered_rows if str(row.get("log_id", "")) == log_id))
        }
        injected_ids = {
            str(row.get("log_id", "")) for row in tampered_block
            if str(row.get("log_id", "")) not in original_ids
        }
        affected_ids = deleted_ids | changed_ids | injected_ids
        tampered = bool(affected_ids)
        truth.append(
            {
                "batch_id": block_id,
                "attack_type": attack_name if tampered else "clean",
                "tampered": "True" if tampered else "False",
                "original_row_count": str(len(original_block)),
                "tampered_row_count": str(len(tampered_block)),
                "tampered_log_count": str(len(affected_ids)),
                "tampered_log_ids": ",".join(sorted(affected_ids)),
                "deleted_log_ids": ",".join(sorted(deleted_ids)),
            }
        )
    return truth


def build_output_paths(output_dir: Path, attack_name: str, rate: float) -> Tuple[Path, Path, Path]:
    rate_tag = str(rate).replace(".", "p")
    tampered_path = output_dir / f"tampered_{attack_name}_{rate_tag}.csv"
    log_truth_path = output_dir / f"ground_truth_logs_{attack_name}_{rate_tag}.csv"
    block_truth_path = output_dir / f"ground_truth_blocks_{attack_name}_{rate_tag}.csv"
    return tampered_path, log_truth_path, block_truth_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Controlled tampering generator with log and block truth.")
    parser.add_argument("--input", type=Path, required=True, help="Structured input CSV, for example merged_logs.csv")
    parser.add_argument(
        "--attack",
        nargs="+",
        default=["all"],
        help=(
            "Attack name(s) or 'all'. Supported: delete_isolated, delete_contiguous, delete_critical, "
            "inject_normal, inject_anomalous, inject_plausible_timestamp, modify_content, modify_level, "
            "modify_timestamp, modify_source_id, modify_event_id, permute_two_logs, reverse_window, move_critical_event, replay, rollback"
        ),
    )
    parser.add_argument("--rates", nargs="+", type=float, default=[0.1, 0.5, 1, 5, 10], help="Attack intensities in percent or ratio")
    parser.add_argument("--block-size", type=int, default=20, help="Number of logs per block")
    parser.add_argument("--output-dir", type=Path, default=Path("tampering_dual_output"), help="Directory for generated files")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--preview-rows", type=int, default=5, help="Number of example rows to print")
    args = parser.parse_args()

    rows = read_csv(args.input)
    if not rows:
        raise SystemExit(f"No rows found in {args.input}")

    attacks = list(ATTACKS.keys()) if any(name.lower() == "all" for name in args.attack) else args.attack
    for attack_name in attacks:
        if attack_name not in ATTACKS:
            raise SystemExit(f"Unsupported attack: {attack_name}")

    base_fieldnames = list(rows[0].keys())
    if "source_id" not in base_fieldnames:
        raise SystemExit("Input must contain source_id; refusing unverifiable source-id attacks")
    tampered_fieldnames = list(dict.fromkeys(base_fieldnames + ["batch_id", "attack_type", "tampered", "origin_log_id"]))
    log_truth_fieldnames = [
        "log_id", "batch_id", "original_position", "position_after", "attack_type",
        "intensity", "modified_fields", "is_deleted", "tampered",
    ]
    block_truth_fieldnames = [
        "batch_id",
        "attack_type",
        "tampered",
        "original_row_count",
        "tampered_row_count",
        "tampered_log_count",
        "tampered_log_ids",
        "deleted_log_ids",
    ]

    for attack_index, attack_name in enumerate(attacks):
        for rate_index, rate in enumerate(args.rates):
            normalized_rate = to_float_rate(rate)
            result = run_attack(rows, attack_name, normalized_rate, args.seed + attack_index * 1000 + rate_index, args.block_size)

            tampered_rows = annotate_blocks(result.tampered_rows, args.block_size)
            log_truth = build_log_truth(rows, tampered_rows, attack_name, result.tampered_ids, result.extra_truth_rows, args.block_size)
            for truth_row in log_truth:
                truth_row["intensity"] = str(rate)
            block_truth = build_block_truth(rows, tampered_rows, attack_name, args.block_size)

            tampered_path, log_truth_path, block_truth_path = build_output_paths(args.output_dir, attack_name, rate)
            write_csv(tampered_rows, tampered_path, tampered_fieldnames)
            write_csv(log_truth, log_truth_path, log_truth_fieldnames)
            write_csv(block_truth, block_truth_path, block_truth_fieldnames)

            print(f"Saved tampered data: {tampered_path}")
            print(f"Saved log truth: {log_truth_path}")
            print(f"Saved block truth: {block_truth_path}")
            print(f"Rows before: {len(rows)} | Rows after: {len(tampered_rows)} | Attack: {attack_name} | Rate: {rate}")
            for row in tampered_rows[: args.preview_rows]:
                print(
                    f"  preview log_id={row.get('log_id')} batch_id={row.get('batch_id')} "
                    f"tampered={row.get('tampered')} attack={row.get('attack_type')}"
                )


if __name__ == "__main__":
    main()