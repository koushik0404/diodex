"""Tests for app/explanation/evidence.py (deterministic, no LLM/DB)."""

import pytest

from app.explanation.evidence import build_evidence


def _flow(**overrides):
    base = {
        "timestamp": "2024-06-03T00:00:00+00:00",
        "source_ip": "10.0.0.5",
        "destination_ip": "93.184.216.34",
        "source_port": 51234,
        "destination_port": 443,
        "protocol": "tcp",
        "packet_count": 10,
        "byte_count": 2000,
        "duration": 2.0,
    }
    base.update(overrides)
    return base


def _signal_names(evidence: dict) -> list[str]:
    return [s["name"] for s in evidence["signals"]]


def test_ddos_like_flow_reports_high_packet_rate():
    flow = _flow(packet_count=5000, byte_count=2_000_000, duration=1.0)
    detection = {"threat_name": "ddos", "confidence": 0.99, "anomaly_score": 0.2}

    evidence = build_evidence(flow, detection)

    names = _signal_names(evidence)
    assert "high_packet_rate" in names
    # A known threat is reported factually, not as an anomaly signal.
    assert "known_threat_classification" in names
    assert "high_anomaly_score" not in names


def test_unknown_anomaly_reports_anomaly_score_signal():
    flow = _flow()
    detection = {"threat_name": "unknown", "anomaly_score": 0.93}

    evidence = build_evidence(flow, detection)

    names = _signal_names(evidence)
    assert "high_anomaly_score" in names
    assert "known_threat_classification" not in names


def test_missing_baseline_does_not_fabricate_deviation():
    flow = _flow(packet_count=500, byte_count=500_000, duration=0.1)
    detection = {"threat_name": "unknown", "anomaly_score": 0.8}

    for baseline in (None, {}):
        evidence = build_evidence(flow, detection, baseline=baseline)
        assert not any(
            name.startswith("baseline_deviation")
            for name in _signal_names(evidence)
        )


def test_baseline_deviation_reported_only_when_supplied():
    flow = _flow(packet_count=9000, byte_count=1_000_000, duration=10.0)
    detection = {"threat_name": "normal", "anomaly_score": 0.1}

    # Deviation: 900 pps is ~8 std above a 10 +/- 10 baseline.
    baseline = {"packets_per_second": {"mean": 10.0, "std": 10.0}}
    evidence = build_evidence(flow, detection, baseline=baseline)
    assert "baseline_deviation_packets_per_second" in _signal_names(evidence)

    # Within range: same baseline, benign packet rate -> no deviation.
    quiet = _flow(packet_count=20, byte_count=2000, duration=10.0)
    evidence_quiet = build_evidence(quiet, detection, baseline=baseline)
    assert not any(
        name.startswith("baseline_deviation")
        for name in _signal_names(evidence_quiet)
    )


def test_icmp_sentinel_ports_do_not_trigger_unusual_port_signal():
    flow = _flow(
        protocol="icmp",
        source_port=0,
        destination_port=0,
        packet_count=1,
        byte_count=64,
        duration=0.01,
    )
    detection = {"threat_name": "unknown", "anomaly_score": 0.75}

    names = _signal_names(build_evidence(flow, detection))
    assert "unusual_destination_port" not in names
    assert "very_short_duration" in names


def test_output_shape_and_json_serializable():
    flow = _flow()
    detection = {"threat_name": "normal", "confidence": 0.9, "anomaly_score": 0.1}

    evidence = build_evidence(flow, detection)

    assert set(evidence) == {"metrics", "network", "signals"}
    assert set(evidence["metrics"]) == {
        "packet_count", "byte_count", "duration",
        "packets_per_second", "bytes_per_second",
    }
    assert set(evidence["network"]) == {
        "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol",
    }
    # Round-trips through the JSON encoder without error.
    import json
    json.dumps(evidence)
