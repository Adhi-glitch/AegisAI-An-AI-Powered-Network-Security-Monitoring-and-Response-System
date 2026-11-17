from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP

import backend.app as app_module
import network_capture
from agents.coordinator import coordinator
from backend.app import app
from backend.auth import get_current_admin, get_current_user, get_current_viewer
from backend.routers import alerts as alerts_router
from backend.routers import capture as capture_router
from backend.routers import detections as detections_router
from backend.routers import stats as stats_router
from agents.detection.live_rules import DOS_RATE_RULE_SOURCE, DOS_SYN_THRESHOLD
from agents.detection.threat_policy import threat_severity
from database import models
from ml.data.multidataset import LIVE_FEATURE_COLUMNS
from ml.models.bundle import load_bundle


class FakeSniffer:
    def __init__(self, **kwargs):
        self.callback = kwargs["prn"]
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def test_admin_can_capture_flow_and_persist_detection(tmp_path, monkeypatch):
    database_path = tmp_path / "capture-test.sqlite"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(capture_router, "SessionLocal", test_session)
    monkeypatch.setattr(capture_router, "process_features", lambda features: {
        "predicted": "DoS",
        "confidence": 0.91,
        "action": "block",
        "response": {"status": "dry_run_blocked", "ip": features.get("source_ip")},
    })
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr(network_capture, "_new_sniffer", make_sniffer)
    monkeypatch.setattr(network_capture, "_resolve_interface", lambda interface: interface)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    try:
        with TestClient(app) as client:
            started = client.post("/api/v1/capture/start", json={"interface": "test0"})
            assert started.status_code == 200
            assert started.json()["status"] == "running"

            packet = IP(src="192.0.2.5", dst="198.51.100.8") / TCP(sport=45000, dport=443)
            packet.time = 1.0
            sniffer_holder["sniffer"].callback(packet)
            stopped = client.post("/api/v1/capture/stop")
            assert stopped.status_code == 200
            assert stopped.json()["flow_count"] == 1

        session = test_session()
        try:
            detections = session.query(models.Detection).all()
            alerts = session.query(models.Alert).all()
            assert len(detections) == 1
            assert detections[0].predicted_class == "DoS"
            assert detections[0].alert_id == alerts[0].id
            assert alerts[0].raw_features["total_packets"] == 1
            assert session.query(models.Action).one().action_type == "dry_run_blocked"
        finally:
            session.close()
    finally:
        network_capture.stop_capture()
        app.dependency_overrides.pop(get_current_admin, None)
        engine.dispose()


def test_live_capture_stores_real_active_model_prediction(tmp_path, monkeypatch):
    database_path = tmp_path / "real-model-capture.sqlite"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(capture_router, "SessionLocal", test_session)
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr(network_capture, "_new_sniffer", make_sniffer)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    previous_runtime = coordinator._cached.copy()
    try:
        runtime = coordinator.load_runtime(force=True)
        bundle = load_bundle()
        assert bundle.feature_columns == LIVE_FEATURE_COLUMNS
        packet = IP(src="192.0.2.15", dst="198.51.100.18") / TCP(sport=46000, dport=8080)
        packet.time = 10.0
        tracker = network_capture.FlowTracker()
        tracker.add_packet(packet)
        flow = tracker.flush()[0]
        assert any(flow[column] != 0 for column in LIVE_FEATURE_COLUMNS)
        expected_result = coordinator.process_features(flow)
        expected_class = expected_result["predicted"]

        with TestClient(app) as client:
            assert client.post("/api/v1/capture/start", json={}).status_code == 200
            sniffer_holder["sniffer"].callback(packet)
            stopped = client.post("/api/v1/capture/stop")
            assert stopped.status_code == 200

        session = test_session()
        try:
            assert expected_class in bundle.label_classes
            if threat_severity(expected_class, expected_result["confidence"]) is None:
                assert session.query(models.Alert).count() == 0
                assert session.query(models.Detection).count() == 0
                assert session.query(models.Action).count() == 0
            else:
                detection = session.query(models.Detection).one()
                action = session.query(models.Action).one()
                assert detection.predicted_class == expected_class
                assert action.action_type == expected_result["response"]["status"]
        finally:
            session.close()
    finally:
        network_capture.stop_capture()
        coordinator._cached.update(previous_runtime)
        app.dependency_overrides.pop(get_current_admin, None)
        engine.dispose()


def test_capture_controls_require_admin():
    with TestClient(app) as client:
        assert client.get("/api/v1/capture/status").status_code == 401
        assert client.get("/api/v1/capture/interfaces").status_code == 401
        assert client.post("/api/v1/capture/start", json={}).status_code == 401
        assert client.post("/api/v1/capture/stop").status_code == 401


def test_capture_start_reports_missing_packet_provider(tmp_path, monkeypatch):
    def missing_provider(**_kwargs):
        raise RuntimeError("Scapy has no Npcap/libpcap provider")

    monkeypatch.setattr(network_capture, "_new_sniffer", missing_provider)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/capture/start", json={})
        assert response.status_code == 503
        assert "Npcap/libpcap" in response.json()["detail"]
    finally:
        network_capture.stop_capture()
        app.dependency_overrides.pop(get_current_admin, None)


def test_capture_start_rejects_incompatible_model_bundle(monkeypatch):
    monkeypatch.setattr(capture_router, "load_runtime", lambda: {
        "columns": [" Flow Duration"],
        "bundle_dir": "incompatible-bundle",
    })
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/capture/start", json={})
        assert response.status_code == 503
        assert "does not match the live flow feature schema" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_current_admin, None)


def test_live_syn_port_scan_is_persisted_and_listed_without_response_action(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "port-scan-capture.sqlite"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(capture_router, "SessionLocal", test_session)
    monkeypatch.setattr(app_module, "SessionLocal", test_session)
    monkeypatch.setattr(alerts_router, "SessionLocal", test_session)
    monkeypatch.setattr(detections_router, "SessionLocal", test_session)
    monkeypatch.setattr(stats_router, "SessionLocal", test_session)
    monkeypatch.setattr(capture_router, "_validate_live_model_schema", lambda: None)
    monkeypatch.setattr(capture_router, "process_features", lambda _features: {
        "predicted": "Benign",
        "confidence": 0.99,
        "action": "none",
    })
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr(network_capture, "_new_sniffer", make_sniffer)
    monkeypatch.setattr(network_capture, "_resolve_interface", lambda interface: interface)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    app.dependency_overrides[get_current_viewer] = lambda: {
        "username": "prototype-viewer", "role": "viewer", "is_active": True
    }
    try:
        with TestClient(app) as client:
            started = client.post("/api/v1/capture/start", json={"interface": "test0"})
            assert started.status_code == 200

            for index in range(20):
                packet = (
                    IP(src="192.0.2.20", dst="198.51.100.10")
                    / TCP(sport=50000 + index, dport=40000 + index, flags="S")
                )
                packet.time = 100.0 + index * 0.01
                sniffer_holder["sniffer"].callback(packet)

            stopped = client.post("/api/v1/capture/stop")
            assert stopped.status_code == 200

            detections_response = client.get("/api/v1/detections")
            assert detections_response.status_code == 200
            detection = detections_response.json()["items"][0]
            assert detection["predicted_class"] == "Port Scan"
            assert detection["confidence"] is None
            assert detection["detection_source"] == "port_scan_rule"
            assert detection["severity"] == "low"

            alerts_response = client.get("/api/v1/alerts")
            assert alerts_response.status_code == 200
            alert = alerts_response.json()["items"][0]
            assert alert["severity"] == "low"

            detail_response = client.get(f"/api/v1/alerts/{alert['id']}")
            assert detail_response.status_code == 200
            assert detail_response.json()["detections"][0]["detection_source"] == "port_scan_rule"

            csv_response = client.get("/api/v1/detections/export.csv")
            assert csv_response.status_code == 200
            assert "TCP scan rule" not in csv_response.text
            assert "port_scan_rule" in csv_response.text
            assert "low" in csv_response.text

            dashboard_detections = client.get("/detections?limit=50").json()
            assert dashboard_detections[0]["detection_source"] == "port_scan_rule"
            assert dashboard_detections[0]["severity"] == "low"
            dashboard_alerts = client.get("/alerts?limit=50").json()
            assert dashboard_alerts[0]["severity"] == "low"

            stats = client.get("/api/v1/stats").json()
            assert stats["by_class"]["Port Scan"] == 1
            assert stats["actions"] == 0

        session = test_session()
        try:
            detection = session.query(models.Detection).one()
            alert = session.query(models.Alert).one()
            assert detection.confidence is None
            assert detection.detection_source == "port_scan_rule"
            assert alert.severity == "low"
            assert session.query(models.Action).count() == 0
        finally:
            session.close()
    finally:
        network_capture.stop_capture()
        app.dependency_overrides.pop(get_current_admin, None)
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_viewer, None)
        engine.dispose()


def test_live_syn_rate_indicator_is_persisted_without_response_action(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "dos-rate-capture.sqlite"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    models.Base.metadata.create_all(engine)
    test_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    monkeypatch.setattr(capture_router, "SessionLocal", test_session)
    monkeypatch.setattr(app_module, "SessionLocal", test_session)
    monkeypatch.setattr(alerts_router, "SessionLocal", test_session)
    monkeypatch.setattr(detections_router, "SessionLocal", test_session)
    monkeypatch.setattr(stats_router, "SessionLocal", test_session)
    monkeypatch.setattr(capture_router, "_validate_live_model_schema", lambda: None)
    monkeypatch.setattr(capture_router, "process_features", lambda _features: {
        "predicted": "Benign",
        "confidence": 0.99,
        "action": "none",
    })
    sniffer_holder = {}

    def make_sniffer(**kwargs):
        sniffer_holder["sniffer"] = FakeSniffer(**kwargs)
        return sniffer_holder["sniffer"]

    monkeypatch.setattr(network_capture, "_new_sniffer", make_sniffer)
    monkeypatch.setattr(network_capture, "_resolve_interface", lambda interface: interface)
    app.dependency_overrides[get_current_admin] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "prototype-admin", "role": "admin", "is_active": True
    }
    try:
        with TestClient(app) as client:
            started = client.post("/api/v1/capture/start", json={"interface": "test0"})
            assert started.status_code == 200

            for index in range(DOS_SYN_THRESHOLD):
                packet = (
                    IP(src="192.0.2.25", dst="198.51.100.15")
                    / TCP(sport=50000, dport=80, flags="S")
                )
                packet.time = 200.0 + index * 0.01
                sniffer_holder["sniffer"].callback(packet)

            stopped = client.post("/api/v1/capture/stop")
            assert stopped.status_code == 200

            detections = client.get("/api/v1/detections").json()["items"]
            assert len(detections) == 1
            assert detections[0]["predicted_class"] == "DoS"
            assert detections[0]["detection_source"] == DOS_RATE_RULE_SOURCE
            assert detections[0]["confidence"] is None
            assert detections[0]["severity"] == "medium"

            alerts = client.get("/api/v1/alerts").json()["items"]
            assert len(alerts) == 1
            assert alerts[0]["severity"] == "medium"
            assert client.get("/api/v1/stats").json()["actions"] == 0

        session = test_session()
        try:
            detection = session.query(models.Detection).one()
            alert = session.query(models.Alert).one()
            assert detection.detection_source == DOS_RATE_RULE_SOURCE
            assert detection.confidence is None
            assert alert.severity == "medium"
            assert session.query(models.Action).count() == 0
        finally:
            session.close()
    finally:
        network_capture.stop_capture()
        app.dependency_overrides.pop(get_current_admin, None)
        app.dependency_overrides.pop(get_current_user, None)
        engine.dispose()