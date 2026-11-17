import pytest

from ml.evaluation.evaluate import _false_positive_rates


def test_false_positive_rates_are_one_vs_rest_per_class():
    rates = _false_positive_rates([[8, 2], [1, 9]], ["Benign", "DoS"])

    assert rates["Benign"] == pytest.approx(0.1)
    assert rates["DoS"] == pytest.approx(0.2)