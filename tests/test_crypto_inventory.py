import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from crypto_inventory import assess, uses_public_key


def record(**overrides):
    result = {
        "asset_id": "SIM-TEST",
        "service": "Example service",
        "owner": "Example owner",
        "environment": "simulated",
        "data_type": "fictional records",
        "data_sensitivity": "high",
        "expected_data_lifetime_years": "15",
        "transport": "TLS",
        "protocol": "TLS 1.3",
        "certificate_expiry": "unknown",
        "public_key_algorithm": "RSA",
        "key_establishment": "ECDHE",
        "crypto_dependency_known": "yes",
        "provider_or_dependency": "Example provider",
        "evidence_status": "simulated",
        "confidence": "low",
    }
    result.update(overrides)
    return result


class CryptoInventoryTests(unittest.TestCase):
    def test_sensitive_long_lived_public_key_record_is_high_review(self):
        result = assess(record(), date(2026, 10, 6))
        self.assertEqual(result["triage_priority"], "High review priority")
        self.assertIn("at least 10 years", result["triage_reason"])

    def test_unknown_data_lifetime_prompts_follow_up(self):
        result = assess(record(expected_data_lifetime_years="unknown"), date(2026, 10, 6))
        self.assertEqual(result["triage_priority"], "Needs review")
        self.assertIn("Confirm how long", result["follow_up"])

    def test_expiry_threshold_is_deterministic(self):
        result = assess(record(certificate_expiry="2026-10-20"), date(2026, 10, 6))
        self.assertEqual(result["triage_priority"], "High review priority")
        self.assertIn("14 days", result["triage_reason"])

    def test_expired_certificate_is_flagged(self):
        result = assess(record(certificate_expiry="2026-10-05"), date(2026, 10, 6))
        self.assertEqual(result["triage_priority"], "High review priority")
        self.assertIn("has passed", result["triage_reason"])

    def test_plain_dh_term_does_not_match_unrelated_word(self):
        self.assertFalse(uses_public_key("child record"))
        self.assertTrue(uses_public_key("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"))

    def test_unknown_public_key_and_exchange_are_reviewed(self):
        result = assess(
            record(public_key_algorithm="unknown", key_establishment="unknown"),
            date(2026, 10, 6),
        )
        self.assertEqual(result["triage_priority"], "Needs review")
        self.assertIn("perform discovery", result["triage_reason"])


if __name__ == "__main__":
    unittest.main()
