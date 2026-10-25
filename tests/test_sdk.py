import pytest
from unittest.mock import patch, MagicMock
from sdk.sherlock_client import Sherlock, SherlockBlocked, SherlockStepUp


def test_sdk_exceptions():
    blocked_exc = SherlockBlocked({"verdict": "BLOCK", "why": ["Contract violation", "Tainted session"]})
    assert "Blocked by Sherlock: Contract violation; Tainted session" in str(blocked_exc)
    assert blocked_exc.result["verdict"] == "BLOCK"

    stepup_exc = SherlockStepUp({"verdict": "STEP-UP", "why": ["Approval needed over threshold"]})
    assert "Sherlock requires human approval: Approval needed over threshold" in str(stepup_exc)
    assert stepup_exc.result["verdict"] == "STEP-UP"


def test_sdk_check_success():
    client = Sherlock("http://127.0.0.1:8000", prompt="Test task")
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"session_id": "S123", "verdict": "ALLOW", "score": 0, "why": []}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.check("calculate_quote", {"amount": 500})
        assert res["verdict"] == "ALLOW"
        assert client.session_id == "S123"


def test_sdk_guard_allow():
    client = Sherlock("http://127.0.0.1:8000")
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"session_id": "S123", "verdict": "ALLOW", "score": 0, "why": []}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        @client.guard("calc")
        def calculate(a, b):
            return a + b

        val = calculate(10, 20)
        assert val == 30


def test_sdk_guard_blocked_raises():
    client = Sherlock("http://127.0.0.1:8000")
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"session_id": "S123", "verdict": "BLOCK", "score": 100, "why": ["Forbidden area"]}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        @client.guard("read_file")
        def read_file(path):
            return "secret contents"

        with pytest.raises(SherlockBlocked) as exc_info:
            read_file(path="/hr/salaries.csv")
        assert "Forbidden area" in str(exc_info.value)


def test_sdk_guard_stepup_raises():
    client = Sherlock("http://127.0.0.1:8000")
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"session_id": "S123", "verdict": "STEP-UP", "score": 40, "why": ["Amount exceeds approval threshold"]}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        @client.guard("submit_po")
        def submit_po(amount):
            return "po_sent"

        with pytest.raises(SherlockStepUp) as exc_info:
            submit_po(amount=12000)
        assert "Amount exceeds approval threshold" in str(exc_info.value)


def test_sdk_guard_untrusted():
    client = Sherlock("http://127.0.0.1:8000")
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"session_id": "S123", "verdict": "ALLOW", "score": 0, "why": []}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        @client.guard("fetch_quote", untrusted=True)
        def fetch_quote(url):
            return "Vendor quote text"

        out = fetch_quote("https://vendor.corp/quote.txt")
        assert out == "Vendor quote text"
