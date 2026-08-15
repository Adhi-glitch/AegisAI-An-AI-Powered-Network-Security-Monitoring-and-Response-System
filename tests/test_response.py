from agents.response.response_engine import ResponseEngine


def test_response_decision():
    engine = ResponseEngine(dry_run=True)
    action = engine.decide_action(0.85)
    assert action in ("block", "rate_limit", "log")
    res = engine.apply_action("198.51.100.5", action)
    assert "status" in res
