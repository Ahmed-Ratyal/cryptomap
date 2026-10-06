import csv
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from certificates import inspect_file
from crypto_inventory import assess, FIELDS, DETAIL_FIELDS, write_html_report
from demo_run import create_certificate, run_demo
from test_crypto_inventory import record

ROOT = Path(__file__).resolve().parents[1]


class EvidenceTests(unittest.TestCase):
    def test_certificate_authentication_does_not_prove_key_exchange(self):
        result = assess(record(key_establishment="unknown"), date(2026, 10, 6))
        self.assertEqual(result["triage_priority"], "Needs review")
        self.assertIn("does not establish", result["triage_reason"])
        self.assertNotIn("long-term confidentiality", result["triage_reason"])

    def test_ed25519_authentication_is_classical(self):
        result = assess(record(public_key_algorithm="Ed25519", key_establishment="unknown"), date(2026, 10, 6))
        self.assertIn("classical authentication", result["triage_reason"])

    def test_pem_bundle_der_and_malformed_file(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
            create_certificate(cert, key, datetime.now(timezone.utc), 14)
            details = inspect_file(cert)[0]
            self.assertEqual(details["public_key_bits"], 2048)
            self.assertEqual(details["key_establishment"], "unknown")
            self.assertIn("localhost", details["subject_alternative_names"])
            der = Path(folder) / "cert.der"
            der.write_bytes(x509.load_pem_x509_certificate(cert.read_bytes()).public_bytes(serialization.Encoding.DER))
            self.assertEqual(inspect_file(der)[0]["sha256_fingerprint"], details["sha256_fingerprint"])
            cert.write_bytes(cert.read_bytes() * 2)
            self.assertEqual(len(inspect_file(cert)), 2)
            cert.write_bytes(b"not a certificate")
            with self.assertRaises(ValueError):
                inspect_file(cert)

    def test_html_escapes_supplied_text(self):
        row = record(service='<script>alert("x")</script>', **{field: "" for field in DETAIL_FIELDS})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            write_html_report([assess(row, date(2026, 10, 6))], path, date(2026, 10, 6))
            rendered = path.read_text(encoding="utf-8")
            self.assertNotIn("<script>", rendered)
            self.assertIn("&lt;script&gt;", rendered)

    def test_invalid_lifetime_and_duplicate_ids_fail_without_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            inventory, out = Path(folder) / "inventory.csv", Path(folder) / "out"
            for rows in ([record(expected_data_lifetime_years="nan")], [record(), record()]):
                with inventory.open("w", newline="", encoding="utf-8") as stream:
                    writer = csv.DictWriter(stream, fieldnames=FIELDS)
                    writer.writeheader()
                    writer.writerows(rows)
                run = subprocess.run([sys.executable, str(ROOT / "crypto_inventory.py"), str(inventory), "--out", str(out)], capture_output=True, text=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(out.exists())

    def test_complete_local_demo_renewal_and_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            summary = run_demo(out)
            self.assertEqual(summary["verified_local_tls_handshakes"], 2)
            self.assertTrue(summary["replacement_fingerprint_changed"])
            before = (out / "before" / "triage_summary.md").read_text(encoding="utf-8")
            after = (out / "after" / "triage_summary.md").read_text(encoding="utf-8")
            self.assertIn("expires in 14 days", before)
            self.assertNotIn("expires in 14 days", after)
            self.assertIn("has passed", after)
            self.assertIn("key-exchange group", after)
            self.assertTrue((out / "after" / "report.html").is_file())
            self.assertFalse(list(out.rglob("*.key")))
            self.assertFalse(any(b"PRIVATE KEY" in p.read_bytes() for p in out.rglob("*") if p.is_file()))


if __name__ == "__main__":
    unittest.main()
