from agents.explainability.explain import explain_prediction_2


def test_explainability_v2_returns_counterfactual_and_contributions():
    result = explain_prediction_2("Port Scan", {"packet_rate": 12, "source_ip": "198.51.100.1"})
    assert result["values"][0]["feature"] == "packet_rate"
    assert "what_would_change" in result
    assert result["calibration"]["available"] is False