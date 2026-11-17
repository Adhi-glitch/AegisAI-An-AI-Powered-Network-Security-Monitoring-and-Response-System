import pytest

from agents.detection.threat_policy import threat_severity


@pytest.mark.parametrize(
    ("predicted", "confidence", "expected"),
    [
        ("Benign", 0.99, None),
        ("DoS", 0.49, None),
        ("DoS", 0.5, "low"),
        ("Port Scan", 0.65, "medium"),
        ("DDoS", 0.8, "high"),
        ("unsupported", 0.99, None),
        ("Botnet", float("nan"), None),
        ("Web Attack", 1.01, None),
    ],
)
def test_threat_severity_only_accepts_supported_confident_threats(
    predicted, confidence, expected
):
    assert threat_severity(predicted, confidence) == expected
