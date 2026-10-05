from pathlib import Path
import csv


ROOT = Path(__file__).resolve().parents[2]


def test_hdfs_attack_export_has_rows_and_columns():
    path = ROOT / "data" / "attacks" / "Falsification_HDFS.csv"
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        first_row = next(reader, None)
    assert header
    assert first_row


def test_bgl_attack_workbook_is_delivered():
    path = ROOT / "data" / "attacks" / "falsification_BGL.xlsx"
    assert path.is_file()
    assert path.stat().st_size > 0