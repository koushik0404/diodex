"""DIODEx synthetic flow-dataset generator (Phase 1 helper).

Generates 7 balanced CSV files (normal, ddos, c2, dga, tls, scan, exfil),
each with 1000 realistic network-flow records matching the Flow ORM model
and the headers expected by app/ingestion/csv_loader.py:

    timestamp, source_ip, destination_ip, source_port, destination_port,
    protocol, packet_count, byte_count, duration

Flow-level signatures (Random Forest learns per-row stats, not cross-row
patterns, so each class gets a distinct band in packet/byte/duration/port/
protocol space; bytes = packets * sampled bytes-per-packet):

  * normal -> ordinary mixed services (web, DNS, SSH, mail, LAN), modest
              volumes, mostly internal client -> external server.
  * ddos   -> short flows with very high packet counts aimed at a few
              internal victims. No 1-packet "SYN" rows: those are
              statistically identical to scan flows at the row level.
  * c2     -> short, low-volume beacons to uncommon ports at regular
              cadence (20-90 s inter-arrival) from a few infected hosts.
  * dga    -> DNS-channel proxy: sustained port-53 flows with many small
              packets toward many distinct resolvers. True domain-name
              entropy cannot be represented in flow columns, so this is
              the honest, learnable proxy for DGA/DNS-tunnel behavior.
  * tls    -> long-lived, large encrypted sessions (443/8443/4433) with
              high bytes-per-packet.
  * scan   -> 1-2 packet probes across many hosts/ports (TCP/UDP/ICMP),
              tiny byte counts, sub-second durations.
  * exfil  -> very long-lived flows with extreme outbound byte volume to
              a handful of drop destinations.

Deterministic: every class draws from its own random.Random(seed + offset).
No DB writes, no ML, no feature extraction -- data generation only.
"""

from __future__ import annotations

import argparse
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parent
START = datetime(2024, 6, 3, tzinfo=timezone.utc)  # Monday 00:00 UTC

FLOW_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
]

SEED_BASE = 42
CLASS_SEED_OFFSETS = {
    "normal": 1,
    "ddos": 2,
    "c2": 3,
    "dga": 4,
    "tls": 5,
    "scan": 6,
    "exfil": 7,
}

# ---------------------------------------------------------------------------
# Small IP helpers (deterministic, class-agnostic pools)
# ---------------------------------------------------------------------------

EXTERNAL_PREFIXES = [
    (8, 8, 8), (1, 1, 1), (104, 16, 0), (104, 18, 0), (151, 101, 0),
    (172, 217, 0), (140, 82, 0), (185, 199, 0), (20, 99, 0), (13, 107, 0),
    (91, 189, 0), (198, 41, 0), (157, 240, 0),
]


def _external_ip(rng: random.Random) -> str:
    a, b, c = rng.choice(EXTERNAL_PREFIXES)
    return f"{a}.{b}.{c}.{rng.randint(1, 254)}"


def _internal_client(rng: random.Random) -> str:
    return f"10.0.0.{rng.randint(2, 99)}"


def _internal_server(rng: random.Random) -> str:
    return f"10.0.1.{rng.randint(1, 20)}"


def _internal_host(rng: random.Random, lo: int, hi: int) -> str:
    return f"10.0.0.{rng.randint(lo, hi)}"


# ---------------------------------------------------------------------------
# Sampling helpers
# ---------------------------------------------------------------------------


def _log_uniform(rng: random.Random, lo: float, hi: float) -> float:
    """Sample uniformly in log10 space between lo and hi (inclusive)."""
    if lo >= hi:
        return float(lo)
    return 10.0 ** rng.uniform(math.log10(lo), math.log10(hi))


def _pick_weighted(rng: random.Random, entries: list[tuple]):
    """Pick an entry by its weight (index 2)."""
    total = sum(e[2] for e in entries)
    r = rng.uniform(0.0, total)
    upto = 0.0
    for entry in entries:
        upto += entry[2]
        if r <= upto:
            return entry
    return entries[-1]


def _resolve_dport(rng: random.Random, spec) -> int:
    """Accept either a literal port or a ('rand', lo, hi) tuple."""
    if isinstance(spec, int):
        return spec
    return rng.randint(spec[1], spec[2])


def _make_row(ts, src_ip, dst_ip, src_port, dst_port, proto,
              packets, duration, bpp) -> dict:
    """Assemble one Flow-compatible record with physically consistent bytes."""
    if proto == "ICMP":
        src_port = 0
        dst_port = 0
    packets = max(1, int(round(packets)))
    duration = max(0.000001, round(duration, 6))
    return {
        "timestamp": ts,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": proto,
        "packet_count": packets,
        "byte_count": int(round(packets * bpp)),
        "duration": duration,
    }


def _sport(rng: random.Random, proto: str) -> int:
    return 0 if proto == "ICMP" else rng.randint(1024, 65535)


# ---------------------------------------------------------------------------
# Per-class generators
# ---------------------------------------------------------------------------

# (proto, dst_port, weight, pkt_lo, pkt_hi, dur_lo, dur_hi, bpp_lo, bpp_hi, lan_only)
NORMAL_ENTRIES = [
    ("TCP", 443, 0.31, 1, 300, 0.1, 120, 300, 1460, False),   # HTTPS
    ("TCP", 80, 0.18, 1, 200, 0.1, 60, 300, 1460, False),     # HTTP
    ("UDP", 53, 0.10, 1, 3, 0.005, 0.3, 40, 180, False),      # DNS (light)
    ("TCP", 22, 0.06, 2, 150, 1, 300, 100, 1000, False),      # SSH
    ("UDP", 123, 0.04, 1, 2, 0.005, 0.2, 40, 90, False),      # NTP
    ("TCP", 25, 0.02, 2, 100, 0.5, 60, 100, 1000, False),     # SMTP
    ("TCP", 445, 0.03, 2, 100, 0.5, 60, 100, 1400, True),     # SMB (LAN)
    ("TCP", 139, 0.02, 2, 100, 0.5, 60, 100, 1400, True),     # NetBIOS (LAN)
    ("UDP", 5353, 0.03, 1, 3, 0.005, 0.2, 40, 200, True),     # mDNS (LAN)
    ("UDP", 137, 0.02, 1, 3, 0.005, 0.2, 40, 200, True),      # NetBIOS (LAN)
    ("TCP", 3389, 0.03, 2, 400, 5, 300, 100, 1400, False),    # RDP
    ("TCP", 8080, 0.04, 1, 120, 0.1, 30, 300, 1460, False),   # alt web
    ("TCP", ("rand", 8000, 65535), 0.05, 1, 120, 0.1, 60, 100, 1460, False),
    ("UDP", ("rand", 8000, 65535), 0.04, 1, 20, 0.01, 30, 40, 500, False),
    ("ICMP", 0, 0.03, 1, 2, 0.001, 0.1, 60, 84, True),        # ping (LAN)
]


def _gen_normal(rng: random.Random, n: int) -> list[dict]:
    rows = []
    window_s = 8 * 3600  # one business day
    for _ in range(n):
        ts = START + timedelta(seconds=rng.uniform(0, window_s))
        proto, dport_spec, _, p_lo, p_hi, d_lo, d_hi, b_lo, b_hi, lan = (
            _pick_weighted(rng, NORMAL_ENTRIES)
        )
        dport = _resolve_dport(rng, dport_spec)
        if lan or rng.random() < 0.10:
            src, dst = _internal_client(rng), _internal_server(rng)
        else:
            src, dst = _internal_client(rng), _external_ip(rng)
        rows.append(_make_row(
            ts, src, dst, _sport(rng, proto), dport, proto,
            _log_uniform(rng, p_lo, p_hi),
            _log_uniform(rng, d_lo, d_hi),
            _log_uniform(rng, b_lo, b_hi),
        ))
    return rows


# (proto, dst_port, weight, pkt_lo, pkt_hi, dur_lo, dur_hi, bpp_lo, bpp_hi)
DDOS_ENTRIES = [
    ("TCP", 80, 0.25, 250, 6000, 0.05, 2.0, 60, 1460),
    ("TCP", 443, 0.30, 250, 6000, 0.05, 2.0, 100, 1460),
    ("UDP", 53, 0.20, 250, 6000, 0.05, 2.0, 100, 1400),
    ("UDP", 443, 0.15, 250, 6000, 0.05, 2.0, 100, 1400),   # QUIC flood
    ("UDP", 123, 0.10, 250, 6000, 0.05, 2.0, 40, 300),      # NTP amplification
]


def _gen_ddos(rng: random.Random, n: int) -> list[dict]:
    rows = []
    victims = [f"10.0.1.{i}" for i in range(11, 17)]
    t = START + timedelta(seconds=rng.uniform(0, 300))
    for _ in range(n):
        t += timedelta(seconds=rng.expovariate(1 / 0.6))  # ~10 min attack
        proto, dport, _, p_lo, p_hi, d_lo, d_hi, b_lo, b_hi = (
            _pick_weighted(rng, DDOS_ENTRIES)
        )
        victim = rng.choice(victims)
        src = _external_ip(rng) if rng.random() < 0.75 else _internal_host(rng, 2, 99)
        rows.append(_make_row(
            t, src, victim, _sport(rng, proto), dport, proto,
            _log_uniform(rng, p_lo, p_hi),
            _log_uniform(rng, d_lo, d_hi),
            _log_uniform(rng, b_lo, b_hi),
        ))
    return rows


C2_PORTS = [4444, 5555, 6667, 1337, 31337, 9001, 10000, 1234, 2323, 8081]
C2_SERVERS = [
    "185.220.101.4", "45.155.205.233", "91.189.91.7",
    "198.41.0.4", "104.16.132.229",
]


def _gen_c2(rng: random.Random, n: int) -> list[dict]:
    rows = []
    t = START
    for _ in range(n):
        t += timedelta(seconds=rng.uniform(20, 90))  # periodic beacon
        proto = "TCP" if rng.random() < 0.85 else "UDP"
        dport = rng.choice(C2_PORTS)
        src = _internal_host(rng, 41, 50)
        dst = rng.choice(C2_SERVERS)
        rows.append(_make_row(
            t, src, dst, _sport(rng, proto), dport, proto,
            _log_uniform(rng, 1, 20),
            _log_uniform(rng, 0.2, 5.0),
            _log_uniform(rng, 40, 400),
        ))
    return rows


def _gen_dga(rng: random.Random, n: int) -> list[dict]:
    rows = []
    t = START
    for _ in range(n):
        t += timedelta(seconds=rng.expovariate(1 / 1.0))  # rapid lookups
        proto = "UDP" if rng.random() < 0.85 else "TCP"
        src = _internal_host(rng, 31, 40)
        dst = _external_ip(rng)  # many distinct resolvers
        rows.append(_make_row(
            t, src, dst, _sport(rng, proto), 53, proto,
            _log_uniform(rng, 5, 80),
            _log_uniform(rng, 0.05, 2.0),
            _log_uniform(rng, 60, 220),
        ))
    return rows


def _gen_tls(rng: random.Random, n: int) -> list[dict]:
    rows = []
    window_s = 6 * 3600
    ports = [443, 8443, 4433, 993]
    weights = [0.65, 0.20, 0.10, 0.05]
    for _ in range(n):
        ts = START + timedelta(seconds=rng.uniform(0, window_s))
        dport = rng.choices(ports, weights)[0]
        src, dst = _internal_client(rng), _external_ip(rng)
        rows.append(_make_row(
            ts, src, dst, _sport(rng, "TCP"), dport, "TCP",
            _log_uniform(rng, 500, 20000),
            _log_uniform(rng, 10, 900),
            _log_uniform(rng, 500, 1460),
        ))
    return rows


SCAN_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]


def _gen_scan(rng: random.Random, n: int) -> list[dict]:
    rows = []
    scanners = [f"10.0.0.{i}" for i in (10, 11, 12)]
    t = START
    for _ in range(n):
        t += timedelta(seconds=rng.expovariate(1 / 0.3))  # fast probing
        src = rng.choice(scanners)
        dst = f"10.0.{rng.randint(0, 1)}.{rng.randint(1, 99)}"
        r = rng.random()
        if r < 0.85:
            proto, b_lo, b_hi = "TCP", 40, 100
        elif r < 0.95:
            proto, b_lo, b_hi = "UDP", 40, 90
        else:
            proto, b_lo, b_hi = "ICMP", 60, 84
        dport = (
            rng.choice(SCAN_COMMON_PORTS)
            if rng.random() < 0.5
            else rng.randint(1, 65535)
        )
        rows.append(_make_row(
            t, src, dst, _sport(rng, proto), dport, proto,
            rng.randint(1, 2),  # handshake probe, no payload
            _log_uniform(rng, 0.001, 0.2),
            _log_uniform(rng, b_lo, b_hi),
        ))
    return rows


EXFIL_DROPS = [
    "185.220.101.7", "45.155.205.244", "103.86.99.100", "91.189.91.12",
]


def _gen_exfil(rng: random.Random, n: int) -> list[dict]:
    rows = []
    window_s = 12 * 3600
    ports = [443, 80, 22, 21, 8080]
    weights = [0.40, 0.15, 0.15, 0.10, 0.20]
    for _ in range(n):
        ts = START + timedelta(seconds=rng.uniform(0, window_s))
        dport = rng.choices(ports, weights)[0]
        src = _internal_host(rng, 101, 110)
        dst = rng.choice(EXFIL_DROPS)
        rows.append(_make_row(
            ts, src, dst, _sport(rng, "TCP"), dport, "TCP",
            _log_uniform(rng, 30000, 600000),
            _log_uniform(rng, 300, 3600),
            _log_uniform(rng, 700, 1460),
        ))
    return rows


GENERATORS = {
    "normal": _gen_normal,
    "ddos": _gen_ddos,
    "c2": _gen_c2,
    "dga": _gen_dga,
    "tls": _gen_tls,
    "scan": _gen_scan,
    "exfil": _gen_exfil,
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _write_csv(rows: list[dict], path: Path) -> pd.DataFrame:
    """Write rows to CSV with canonical headers and ISO-8601 UTC timestamps."""
    df = pd.DataFrame(rows, columns=FLOW_COLUMNS)
    df["timestamp"] = (
        pd.to_datetime(df["timestamp"], utc=True)
        .dt.tz_convert("UTC")
        .dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )
    df.to_csv(path, index=False)
    return df


def generate_all(
    rows: int = 1000,
    out_dir: str | Path = DATA_DIR,
    seed: int = SEED_BASE,
) -> dict[str, Path]:
    """Generate every class CSV into out_dir. Returns {class_name: path}."""
    if rows < 1:
        raise ValueError("rows must be >= 1")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    written = {}
    header = (f"{'file':<12}{'rows':>6}{'mean_pkts':>12}"
              f"{'mean_bytes':>16}{'mean_dur_s':>14}")
    print(header)
    print("-" * len(header))
    for name, gen in GENERATORS.items():
        rng = random.Random(seed + CLASS_SEED_OFFSETS[name])
        data = gen(rng, rows)
        path = out_dir / f"{name}.csv"
        df = _write_csv(data, path)
        written[name] = path
        print(f"{name + '.csv':<12}{len(df):>6}"
              f"{df['packet_count'].mean():>12.1f}"
              f"{df['byte_count'].mean():>16.0f}"
              f"{df['duration'].mean():>14.3f}")
    return written


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate DIODEx synthetic flow CSVs into backend/data."
    )
    parser.add_argument("--rows", type=int, default=1000,
                        help="records per class (default: 1000)")
    parser.add_argument("--seed", type=int, default=SEED_BASE,
                        help="base random seed (default: 42)")
    parser.add_argument("--output-dir", type=Path, default=DATA_DIR,
                        help="directory to write CSVs (default: this file's dir)")
    args = parser.parse_args()

    generate_all(rows=args.rows, out_dir=args.output_dir, seed=args.seed)


if __name__ == "__main__":
    main()
