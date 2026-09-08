"""Deterministic tests for the unified DIODEx pipeline (no models needed).

Detector functions are injected as fakes, so the tests never require the
trained artifacts under backend/artifacts/.
"""

from datetime import datetime, timedelta, timezone

from app.services.pipeline import run_detection_on_flow, run_pipeline

BASE = datetime(2024, 6, 3, 8, 0, 0, tzinfo=timezone.utc)


def make_flow(minutes, src, dst):
    return {
        "timestamp": BASE + timedelta(minutes=minutes),
        "source_ip": src,
        "destination_ip": dst,
        "source_port": 12345,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 100,
        "byte_count": 10000,
        "duration": 1.0,
    }


def make_detectors(known_result, anomaly_result):
    """Return (predict_known, predict_anomaly) fakes for fixed outputs."""

    def predict_known(flow):
        return dict(known_result)

    def predict_anomaly(flow):
        return dict(anomaly_result)

    return predict_known, predict_anomaly


# --------------------------------------------------------------------------
# 1. Known DDoS flow -> known DDoS alert, NOT an unknown alert
# --------------------------------------------------------------------------


def test_known_ddos_flow_produces_ddos_alert_not_unknown():
    flow = make_flow(0, "10.0.0.5", "10.0.1.10")
    known, anomaly = make_detectors(
        {"threat_name": "ddos", "confidence": 0.95},
        {"is_anomaly": True, "anomaly_score": 0.9},  # IF also flags it
    )
    result = run_detection_on_flow(flow, known, anomaly)

    assert result is not None
    assert result["threat_name"] == "ddos"          # known threat wins
    assert result["threat_name"] != "unknown"
    assert result["confidence"] == 0.95
    assert result["anomaly_score"] == 0.9           # signal preserved
    assert result["source_ip"] == "10.0.0.5"
    assert result["destination_ip"] == "10.0.1.10"

    pipeline = run_pipeline([flow], predict_known=known, predict_anomaly=anomaly)
    assert pipeline["summary"]["total_alerts"] == 1  # no extra unknown alert
    assert pipeline["alerts"][0]["threat_name"] == "ddos"


# --------------------------------------------------------------------------
# 2. Normal flow -> no alert
# --------------------------------------------------------------------------


def test_normal_flow_produces_no_alert():
    flow = make_flow(0, "10.0.0.5", "8.8.8.8")
    known, anomaly = make_detectors(
        {"threat_name": "normal", "confidence": 0.97},
        {"is_anomaly": False, "anomaly_score": 0.1},
    )
    assert run_detection_on_flow(flow, known, anomaly) is None

    pipeline = run_pipeline([flow], predict_known=known, predict_anomaly=anomaly)
    assert pipeline["summary"]["total_flows"] == 1
    assert pipeline["summary"]["total_alerts"] == 0
    assert pipeline["summary"]["total_incidents"] == 0
    assert pipeline["alerts"] == []
    assert pipeline["incidents"] == []


# --------------------------------------------------------------------------
# 3. Unknown-style flow -> unknown alert when anomaly detector flags it
# --------------------------------------------------------------------------


def test_unknown_flow_produces_unknown_alert():
    flow = make_flow(0, "10.0.0.9", "198.41.0.4")
    known, anomaly = make_detectors(
        {"threat_name": "normal", "confidence": 0.6},
        {"is_anomaly": True, "anomaly_score": 0.88},
    )
    result = run_detection_on_flow(flow, known, anomaly)

    assert result is not None
    assert result["threat_name"] == "unknown"
    assert result["anomaly_score"] == 0.88
    assert result["confidence"] == 0.0


def test_anomaly_without_flag_does_not_alert():
    flow = make_flow(0, "10.0.0.9", "8.8.8.8")
    known, anomaly = make_detectors(
        {"threat_name": "normal", "confidence": 0.9},
        {"is_anomaly": False, "anomaly_score": 0.99},  # odd but not flagged
    )
    assert run_detection_on_flow(flow, known, anomaly) is None


# --------------------------------------------------------------------------
# 4. Multiple related alerts -> one correlated incident
# --------------------------------------------------------------------------


def test_related_alerts_form_one_incident():
    # Same source IP, different destinations -> dedup keeps all three,
    # correlation merges them (shared source, inside the window).
    flows = [
        make_flow(0, "10.0.0.5", "8.8.8.8"),
        make_flow(1, "10.0.0.5", "9.9.9.9"),
        make_flow(2, "10.0.0.5", "1.1.1.1"),
    ]
    known, anomaly = make_detectors(
        {"threat_name": "ddos", "confidence": 0.9},
        {"is_anomaly": False, "anomaly_score": 0.0},
    )
    pipeline = run_pipeline(
        flows, window_seconds=300, predict_known=known, predict_anomaly=anomaly
    )

    assert pipeline["summary"]["total_flows"] == 3
    assert pipeline["summary"]["total_alerts"] == 3
    assert pipeline["summary"]["total_incidents"] == 1
    assert pipeline["incidents"][0]["alert_count"] == 3
    assert pipeline["incidents"][0]["source_ips"] == ["10.0.0.5"]

    # Three high-confidence DDoS alerts -> Critical; bands add up to 1.
    summary = pipeline["summary"]
    assert summary["critical"] + summary["high"] + summary["medium"] + summary["low"] == 1
    assert pipeline["incidents"][0]["priority"] == "Critical"


def test_unrelated_alerts_stay_separate():
    flows = [
        make_flow(0, "10.0.0.1", "8.8.8.8"),
        make_flow(1, "10.0.0.2", "9.9.9.9"),  # no shared endpoint
    ]
    known, anomaly = make_detectors(
        {"threat_name": "scan", "confidence": 0.8},
        {"is_anomaly": False, "anomaly_score": 0.0},
    )
    pipeline = run_pipeline(flows, predict_known=known, predict_anomaly=anomaly)
    assert pipeline["summary"]["total_alerts"] == 2
    assert pipeline["summary"]["total_incidents"] == 2
