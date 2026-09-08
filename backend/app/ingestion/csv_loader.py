"""Phase 1 traffic ingestion: load flow CSVs into Flow-compatible dicts.

Reads netflow-style CSVs (backend/data/*.csv) and returns plain dicts whose
keys/values match the Flow ORM model (app/models/flow.py).
No DB writes, no feature extraction, no detection here.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# Canonical Flow field -> accepted CSV header names (after normalization:
# lowercase, spaces/dashes -> underscores). First alias is preferred.
COLUMN_ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "time", "ts", "start_time", "starttime"],
    "source_ip": ["source_ip", "src_ip", "srcip", "sip", "source"],
    "destination_ip": [
        "destination_ip", "dst_ip", "dest_ip", "dstip", "dip", "destination",
    ],
    "source_port": ["source_port", "src_port", "srcport", "sport"],
    "destination_port": ["destination_port", "dst_port", "dstport", "dport"],
    "protocol": ["protocol", "proto"],
    "packet_count": ["packet_count", "packets", "pkt_count", "total_packets"],
    "byte_count": ["byte_count", "bytes", "total_bytes", "octets"],
    "duration": ["duration", "dur", "flow_duration"],
}

TEXT_FIELDS = {"source_ip", "destination_ip", "protocol"}
INT_FIELDS = {"source_port", "destination_port", "packet_count"}
FLOAT_FIELDS = {"duration"}
# byte_count is intentionally a plain Python int (64-bit BigInteger column).

# Netflow convention: ICMP flows often leave ports as "-" instead of 0.
PORT_SENTINEL = "-"
PORT_FIELDS = {"source_port", "destination_port"}


class CSVLoaderError(ValueError):
    """Raised when a flow CSV cannot be converted into Flow records."""


def _normalize(name: object) -> str:
    return str(name).strip().lower().replace(" ", "_").replace("-", "_")


def _resolve_columns(headers) -> dict[str, str]:
    """Map canonical Flow fields to the actual CSV column names."""
    normalized = {_normalize(h): h for h in headers}
    resolved: dict[str, str] = {}
    for field, aliases in COLUMN_ALIASES.items():
        found = [normalized[a] for a in aliases if a in normalized]
        if len(found) > 1:
            raise CSVLoaderError(
                f"Ambiguous columns for '{field}': {found}. "
                f"Keep only one of: {aliases}"
            )
        if found:
            resolved[field] = found[0]
    return resolved


def _parse_timestamps(series: pd.Series) -> pd.Series:
    """Parse a timestamp column to timezone-aware UTC datetimes.

    Handles both ISO-ish strings and numeric epoch columns.
    """
    sample = series.dropna().astype(str).str.strip()
    is_epoch = len(sample) > 0 and sample.str.fullmatch(
        r"[+-]?\d+(\.\d+)?", na=False
    ).all()
    if is_epoch:
        magnitude = abs(float(sample.iloc[0]))
        unit = "s" if magnitude < 1e11 else "ms" if magnitude < 1e14 else "us" if magnitude < 1e17 else "ns"
        return pd.to_datetime(series.astype("float"), unit=unit, utc=True)
    # utc=True: naive values are assumed UTC, aware values converted to UTC.
    return pd.to_datetime(series, utc=True)


def _clean_value(value: object, field: str) -> int | float | str:
    """Convert one raw cell to the Python type expected by the Flow model."""
    if field in PORT_FIELDS and value == PORT_SENTINEL:
        value = 0
    if value == "" or pd.isna(value):
        raise ValueError(f"missing value for '{field}'")

    if field in TEXT_FIELDS:
        return str(value).strip()
    if field in INT_FIELDS or field == "byte_count":
        if isinstance(value, float) and not value.is_integer():
            raise ValueError(f"'{field}' must be an integer, got {value!r}")
        return int(value)
    if field in FLOAT_FIELDS:
        return float(value)
    raise ValueError(f"unsupported field: {field}")


def load_flows_from_csv(path: str | Path, *, encoding: str = "utf-8-sig") -> list[dict]:
    """Load a flow CSV into a list of dicts ready for Flow insertion.

    Raises:
        FileNotFoundError: if the CSV file does not exist.
        CSVLoaderError: if the file is empty, required columns are missing,
            or any value cannot be converted / is missing.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    try:
        df = pd.read_csv(csv_path, encoding=encoding)
    except pd.errors.EmptyDataError as exc:
        raise CSVLoaderError(f"CSV file is empty or has no header: {csv_path}") from exc
    except pd.errors.ParserError as exc:
        raise CSVLoaderError(f"Could not parse CSV {csv_path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise CSVLoaderError(
            f"Could not decode {csv_path} with encoding '{encoding}'; "
            f"pass a different encoding (e.g. 'latin-1') if needed"
        ) from exc

    resolved = _resolve_columns(df.columns)
    missing = [f for f in COLUMN_ALIASES if f not in resolved]
    if missing:
        raise CSVLoaderError(
            f"CSV {csv_path} is missing required column(s): {missing}. "
            f"Found columns: {list(df.columns)}"
        )

    if df.empty:  # header present, no data rows -> valid empty dataset
        return []

    try:
        timestamps = _parse_timestamps(df[resolved["timestamp"]])
    except (ValueError, TypeError) as exc:
        raise CSVLoaderError(
            f"Column '{resolved['timestamp']}' has invalid timestamps: {exc}"
        ) from exc

    flows: list[dict] = []
    for idx, row in df.iterrows():
        line_no = idx + 2  # +1 for header, +1 for zero-based index
        try:
            ts = timestamps.loc[idx]
            if pd.isna(ts):
                raise ValueError("missing value for 'timestamp'")
            record: dict = {"timestamp": ts.to_pydatetime()}
            for field, col in resolved.items():
                if field != "timestamp":
                    record[field] = _clean_value(row[col], field)
            flows.append(record)
        except (ValueError, TypeError) as exc:
            raise CSVLoaderError(f"{csv_path}: line {line_no}: {exc}") from exc

    return flows


__all__ = ["load_flows_from_csv", "CSVLoaderError"]
