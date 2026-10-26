"""Unit tests for provenance.py."""

from provenance import evaluate_provenance

def test_trusted_user_provenance():
    res = evaluate_provenance(instruction_source="trusted_user")
    assert res.source == "trusted_user"
    assert res.trust_score == 1.0
    assert res.is_untrusted is False
    assert res.risk_multiplier == 1.0

def test_system_provenance():
    res = evaluate_provenance(instruction_source="system")
    assert res.source == "system"
    assert res.trust_score == 0.95
    assert res.is_untrusted is False

def test_uploaded_file_provenance():
    res = evaluate_provenance(instruction_source="uploaded_file")
    assert res.source == "uploaded_file"
    assert res.trust_score == 0.40
    assert res.is_untrusted is True
    assert res.risk_multiplier > 1.0

def test_web_content_provenance():
    res = evaluate_provenance(instruction_source="web_content")
    assert res.source == "web_content"
    assert res.trust_score == 0.30
    assert res.is_untrusted is True
    assert res.risk_multiplier >= 1.5

def test_unknown_provenance():
    res = evaluate_provenance(instruction_source="unregistered_origin")
    assert res.source == "unknown"
    assert res.trust_score == 0.20
    assert res.is_untrusted is True

def test_provenance_taint_detection():
    # User input claims to be trusted, but payload contains untrusted scraped URL
    payload = {"scraped_url": "http://malicious-site.com/payload"}
    res = evaluate_provenance(instruction_source="trusted_user", payload=payload)
    assert res.is_untrusted is True
    assert res.trust_score < 1.0
    assert any("Provenance Taint Warning" in r for r in res.reasons)
