"""Tests for SpiderShield DLP — PII, Secrets, and Engine (Week 5)."""

from __future__ import annotations

from spidershield.dlp.engine import DLPAction, DLPEngine
from spidershield.dlp.pii import PIIType, detect_pii
from spidershield.dlp.secrets import SecretType, detect_secrets

# ---------------------------------------------------------------------------
# PII Detection
# ---------------------------------------------------------------------------


class TestPIIDetection:
    def test_credit_card_visa(self) -> None:
        matches = detect_pii("Card: 4111 1111 1111 1111")
        assert len(matches) == 1
        assert matches[0].pii_type == PIIType.CREDIT_CARD
        assert matches[0].severity == "high"
        assert "****" in matches[0].masked
        assert matches[0].masked.endswith("1111")

    def test_credit_card_mastercard(self) -> None:
        matches = detect_pii("MC: 5500-0000-0000-0004")
        assert any(m.pii_type == PIIType.CREDIT_CARD for m in matches)

    def test_credit_card_luhn_rejects_invalid(self) -> None:
        # 4111 1111 1111 1112 fails Luhn
        matches = detect_pii("Card: 4111 1111 1111 1112")
        cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
        assert len(cc_matches) == 0

    def test_ssn(self) -> None:
        matches = detect_pii("SSN: 123-45-6789")
        ssn = [m for m in matches if m.pii_type == PIIType.SSN]
        assert len(ssn) == 1
        assert ssn[0].severity == "high"
        assert ssn[0].masked == "***-**-6789"

    def test_ssn_invalid_prefix(self) -> None:
        # 000 and 666 are invalid SSN prefixes
        matches = detect_pii("SSN: 000-12-3456")
        ssn = [m for m in matches if m.pii_type == PIIType.SSN]
        assert len(ssn) == 0

    def test_email(self) -> None:
        matches = detect_pii("Contact: user@example.com")
        emails = [m for m in matches if m.pii_type == PIIType.EMAIL]
        assert len(emails) == 1
        assert "***@example.com" in emails[0].masked

    def test_phone_us(self) -> None:
        matches = detect_pii("Call: (555) 123-4567")
        phones = [m for m in matches if m.pii_type == PIIType.PHONE]
        assert len(phones) == 1
        assert phones[0].masked.endswith("4567")

    def test_ip_public(self) -> None:
        matches = detect_pii("Server: 8.8.8.8")
        ips = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ips) == 1
        assert ips[0].severity == "low"

    def test_ip_internal(self) -> None:
        matches = detect_pii("Host: 192.168.1.100")
        ips = [m for m in matches if m.pii_type == PIIType.IP_INTERNAL]
        assert len(ips) == 1
        assert ips[0].severity == "medium"

    def test_no_pii(self) -> None:
        matches = detect_pii("Hello world, this is a normal message.")
        assert len(matches) == 0

    def test_multiple_pii(self) -> None:
        text = "Name: user@test.com, SSN: 123-45-6789, IP: 10.0.0.1"
        matches = detect_pii(text)
        types = {m.pii_type for m in matches}
        assert PIIType.EMAIL in types
        assert PIIType.SSN in types
        assert PIIType.IP_INTERNAL in types


# ---------------------------------------------------------------------------
# Secret Detection
# ---------------------------------------------------------------------------


class TestSecretDetection:
    def test_aws_key(self) -> None:
        matches = detect_secrets("KEY=AKIAIOSFODNN7EXAMPLE")
        aws = [m for m in matches if m.secret_type == SecretType.AWS_KEY]
        assert len(aws) == 1
        assert aws[0].severity == "critical"

    def test_openai_key(self) -> None:
        matches = detect_secrets("OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012")
        oai = [m for m in matches if m.secret_type == SecretType.OPENAI_KEY]
        assert len(oai) == 1
        assert oai[0].severity == "critical"

    def test_anthropic_key(self) -> None:
        matches = detect_secrets("key=sk-ant-api03-abcdef123456789012345")
        ant = [m for m in matches if m.secret_type == SecretType.ANTHROPIC_KEY]
        assert len(ant) == 1

    def test_stripe_key(self) -> None:
        matches = detect_secrets("sk_test_4eC39HqLyjWDarjtT1zdp7dc0000")
        stripe = [m for m in matches if m.secret_type == SecretType.STRIPE_KEY]
        assert len(stripe) == 1

    def test_github_token(self) -> None:
        matches = detect_secrets("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        gh = [m for m in matches if m.secret_type == SecretType.GITHUB_TOKEN]
        assert len(gh) == 1

    def test_google_api_key(self) -> None:
        matches = detect_secrets("AIzaSyA1234567890abcdefghijklmnopqrstuv")
        goog = [m for m in matches if m.secret_type == SecretType.GOOGLE_API_KEY]
        assert len(goog) == 1

    def test_slack_token(self) -> None:
        matches = detect_secrets("SLACK_TOKEN=xoxb-1234567890-abcdefghij")
        slack = [m for m in matches if m.secret_type == SecretType.SLACK_TOKEN]
        assert len(slack) == 1

    def test_private_key(self) -> None:
        matches = detect_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        pk = [m for m in matches if m.secret_type == SecretType.PRIVATE_KEY]
        assert len(pk) == 1
        assert pk[0].severity == "critical"

    def test_jwt(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        matches = detect_secrets(jwt)
        jwts = [m for m in matches if m.secret_type == SecretType.JWT]
        assert len(jwts) == 1

    def test_db_connection_string(self) -> None:
        matches = detect_secrets("DATABASE_URL=postgresql://user:pass@localhost:5432/mydb")
        db = [m for m in matches if m.secret_type == SecretType.DB_CONNECTION]
        assert len(db) == 1

    def test_no_secrets(self) -> None:
        matches = detect_secrets("This is normal text with no secrets.")
        assert len(matches) == 0

    def test_generic_high_entropy(self) -> None:
        # A 40-char base64 string with high entropy
        high_entropy = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA"
        matches = detect_secrets(f"TOKEN={high_entropy}")
        generic = [m for m in matches if m.secret_type == SecretType.GENERIC_SECRET]
        assert len(generic) >= 1


# ---------------------------------------------------------------------------
# DLP Engine
# ---------------------------------------------------------------------------


class TestDLPEngine:
    def test_log_only_no_modification(self) -> None:
        engine = DLPEngine(action="log_only")
        text = "My key: sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        assert result.output == text  # unchanged
        assert result.has_findings
        assert result.action_taken == DLPAction.LOG_ONLY

    def test_redact_secrets(self) -> None:
        engine = DLPEngine(action="redact")
        text = "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        assert "[REDACTED:openai_key]" in result.output
        assert "sk-proj" not in result.output
        assert result.action_taken == DLPAction.REDACT

    def test_redact_pii(self) -> None:
        engine = DLPEngine(action="redact")
        text = "SSN: 123-45-6789, Email: user@test.com"
        result = engine.scan(text)
        assert "[REDACTED:ssn]" in result.output
        assert "[REDACTED:email]" in result.output
        assert "123-45-6789" not in result.output

    def test_mask_secrets(self) -> None:
        engine = DLPEngine(action="mask")
        text = "KEY=sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        assert "sk-proj-" in result.output  # prefix preserved
        assert result.action_taken == DLPAction.MASK

    def test_mask_pii(self) -> None:
        engine = DLPEngine(action="mask")
        text = "SSN: 123-45-6789"
        result = engine.scan(text)
        assert "6789" in result.output  # last 4 preserved
        assert "123-45" not in result.output

    def test_block(self) -> None:
        engine = DLPEngine(action="block")
        text = "Secret: sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        assert "[BLOCKED]" in result.output
        assert result.blocked is True
        assert "sk-proj" not in result.output

    def test_no_findings(self) -> None:
        engine = DLPEngine(action="redact")
        result = engine.scan("Hello, world!")
        assert result.output == "Hello, world!"
        assert not result.has_findings

    def test_scan_and_act_interface(self) -> None:
        engine = DLPEngine(action="redact")
        output, types = engine.scan_and_act("SSN: 123-45-6789")
        assert "[REDACTED:ssn]" in output
        assert "ssn" in types

    def test_pii_only_mode(self) -> None:
        engine = DLPEngine(action="redact", scan_secrets=False)
        text = "SSN: 123-45-6789, KEY=sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        assert "[REDACTED:ssn]" in result.output
        # Secret should NOT be redacted
        assert "sk-proj" in result.output

    def test_secrets_only_mode(self) -> None:
        engine = DLPEngine(action="redact", scan_pii=False)
        text = "SSN: 123-45-6789, KEY=sk-proj-abc123def456ghi789jkl012"
        result = engine.scan(text)
        # SSN should NOT be redacted
        assert "123-45-6789" in result.output
        assert "[REDACTED:openai_key]" in result.output

    def test_dict_output_scanning(self) -> None:
        engine = DLPEngine(action="log_only")
        output = {"content": "SSN: 123-45-6789", "status": "ok"}
        result = engine.scan(output)
        assert result.has_findings
        ssn_findings = [f for f in result.findings if f.finding_type == "ssn"]
        assert len(ssn_findings) == 1

    def test_finding_to_dict(self) -> None:
        engine = DLPEngine(action="log_only")
        result = engine.scan("SSN: 123-45-6789")
        assert result.has_findings
        d = result.findings[0].to_dict()
        assert "type" in d
        assert "category" in d
        assert "severity" in d
        assert "masked" in d


# ---------------------------------------------------------------------------
# Integration: RuntimeGuard + DLP
# ---------------------------------------------------------------------------


class TestGuardDLPIntegration:
    def test_after_call_with_dlp_redact(self) -> None:
        from spidershield.guard.context import CallContext
        from spidershield.guard.core import RuntimeGuard

        dlp = DLPEngine(action="redact")
        guard = RuntimeGuard(dlp_engine=dlp)

        ctx = CallContext(
            session_id="s1",
            agent_id="a1",
            tool_name="read_file",
            arguments={"path": "/app/config.txt"},
        )
        result = guard.after_call(ctx, "API_KEY=sk-proj-abc123def456ghi789jkl012")
        assert "[REDACTED:openai_key]" in result
        assert "sk-proj" not in result

        # Check audit recorded the detection
        assert len(guard._audit_log) == 1
        assert guard._audit_log[0]["phase"] == "after_call"
        assert "openai_key" in guard._audit_log[0]["pii_detected"]

    def test_after_call_without_dlp(self) -> None:
        from spidershield.guard.context import CallContext
        from spidershield.guard.core import RuntimeGuard

        guard = RuntimeGuard()  # no DLP
        ctx = CallContext(
            session_id="s1",
            agent_id="a1",
            tool_name="read_file",
            arguments={},
        )
        result = guard.after_call(ctx, "sk-proj-abc123def456ghi789jkl012")
        assert result == "sk-proj-abc123def456ghi789jkl012"  # unchanged

    def test_spider_guard_dlp_param(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced", dlp="redact")
        result = guard.after_check("read_file", "SSN: 123-45-6789")
        assert "[REDACTED:ssn]" in result
        assert "123-45-6789" not in result

    def test_spider_guard_no_dlp(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.after_check("read_file", "SSN: 123-45-6789")
        assert result == "SSN: 123-45-6789"  # unchanged, no DLP
