"""Run a local-only certificate inventory, renewal and TLS retest demonstration."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certificates import inspect_file
from crypto_inventory import FIELDS, DETAIL_FIELDS

ROOT = Path(__file__).resolve().parent


def create_certificate(cert_path: Path, key_path: Path, now: datetime,
                       days: int, algorithm: str = "RSA") -> None:
    """Create a disposable lab certificate using a supported cryptography library."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if algorithm == "RSA" else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    start = now - timedelta(days=60 if days < 0 else 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            ]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=algorithm == "RSA", data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def measure_local_tls(cert_path: Path, key_path: Path) -> dict:
    """Verify one TLS handshake against an explicitly trusted lab certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_path), str(key_path))
    errors = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    port = listener.getsockname()[1]

    def serve():
        try:
            with listener:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(8)
                    with context.wrap_socket(connection, server_side=True) as secure:
                        if secure.recv(16) != b"inventory-demo":
                            raise RuntimeError("Unexpected demo request")
                        secure.sendall(b"verified")
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        client = ssl.create_default_context(cafile=str(cert_path))
        client.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", port), timeout=8) as connection:
            with client.wrap_socket(connection, server_hostname="localhost") as secure:
                secure.sendall(b"inventory-demo")
                response = secure.recv(16)
                if response != b"verified":
                    raise RuntimeError("TLS demo response was not verified")
                peer = x509.load_der_x509_certificate(secure.getpeercert(binary_form=True))
                result = {
                    "endpoint": "127.0.0.1 (ephemeral loopback port)",
                    "hostname": "localhost", "negotiated_protocol": secure.version(),
                    "cipher_suite": secure.cipher()[0],
                    "peer_certificate_sha256": peer.fingerprint(hashes.SHA256()).hex(),
                    "hostname_and_expiry_verified": True,
                    "trust_scope": "Explicit trust of this lab certificate only; not public CA validation.",
                    "key_establishment": "unknown",
                    "key_exchange_note": "The Python TLS API used here does not report the negotiated key-exchange group; no inference from the certificate or cipher suite.",
                }
    finally:
        thread.join(timeout=9)
        listener.close()
    if thread.is_alive():
        raise RuntimeError("Local TLS worker did not stop")
    if errors:
        raise RuntimeError(f"Local TLS worker failed: {errors[0]}")
    return result


def inventory_record(asset_id: str, service: str, metadata: dict, tls: dict | None) -> dict:
    note = ("Observed: generated local certificate metadata" +
            (" and verified loopback TLS handshake." if tls else "; no handshake attempted for this expired certificate.") +
            " Fictional: service name, owner, data type, sensitivity and 15-year protection lifetime. Key exchange is unknown.")
    return {
        "asset_id": asset_id, "service": service, "owner": "Fictional service owner",
        "environment": "local lab / fictional business context", "data_type": "fictional customer records",
        "data_sensitivity": "high", "expected_data_lifetime_years": "15",
        "transport": "TLS", "protocol": tls["negotiated_protocol"] if tls else "unknown",
        "certificate_expiry": metadata["certificate_expiry"],
        "public_key_algorithm": metadata["public_key_algorithm"], "key_establishment": "unknown",
        "crypto_dependency_known": "partial", "provider_or_dependency": "Python ssl + cryptography (local lab)",
        "evidence_status": "observed", "confidence": "medium", "evidence_notes": note,
        "certificate_fingerprint": metadata["sha256_fingerprint"],
        "public_key_bits": str(metadata["public_key_bits"]),
        "signature_algorithm": metadata["signature_algorithm_oid"],
    }


def write_inventory(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS + DETAIL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def run_demo(output: Path) -> dict:
    started = time.perf_counter()
    output.mkdir(parents=True, exist_ok=True)
    public_folder = output / "certificates"
    public_folder.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    specs = [("archive-expired", -2, "ECDSA"), ("portal-before", 14, "RSA"), ("portal-after", 365, "RSA")]
    metadata, handshakes = {}, {}
    with tempfile.TemporaryDirectory(prefix="cryptomap-keys-") as private_folder:
        for name, days, algorithm in specs:
            cert_path = public_folder / f"{name}.pem"
            key_path = Path(private_folder) / f"{name}.key"
            create_certificate(cert_path, key_path, now, days, algorithm)
            metadata[name] = inspect_file(cert_path)[0]
            if name.startswith("portal"):
                handshakes[name] = measure_local_tls(cert_path, key_path)
                if handshakes[name]["peer_certificate_sha256"] != metadata[name]["sha256_fingerprint"]:
                    raise RuntimeError("Presented certificate does not match inventory evidence")
    (output / "certificate_metadata.json").write_text(json.dumps(list(metadata.values()), indent=2) + "\n", encoding="utf-8")
    (output / "tls_observations.json").write_text(json.dumps(handshakes, indent=2) + "\n", encoding="utf-8")
    archive = inventory_record("LAB-01", "Customer archive (fictional)", metadata["archive-expired"], None)
    for stage in ("before", "after"):
        name = f"portal-{stage}"
        inventory = output / f"{stage}_inventory.csv"
        write_inventory(inventory, [archive, inventory_record("LAB-02", "Customer portal (fictional)", metadata[name], handshakes[name])])
        subprocess.run([sys.executable, str(ROOT / "crypto_inventory.py"), str(inventory),
                        "--out", str(output / stage), "--as-of", now.date().isoformat()], check=True, capture_output=True, text=True)
    before, after = metadata["portal-before"], metadata["portal-after"]
    summary = {
        "assessment_date": now.date().isoformat(), "certificates_inspected": 3,
        "verified_local_tls_handshakes": 2, "before_expiry": before["certificate_expiry"],
        "after_expiry": after["certificate_expiry"],
        "replacement_fingerprint_changed": before["sha256_fingerprint"] != after["sha256_fingerprint"],
        "private_keys_saved_in_output": False,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }
    (output / "demo_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "renewal_evidence.md").write_text(f"""# Local certificate replacement and retest

Assessment date: {summary['assessment_date']}. This is a controlled lab with fictional banking context.

| Check | Before | After |
|---|---|---|
| Portal certificate expiry | {before['certificate_expiry']} (14 days from run date) | {after['certificate_expiry']} (365 days from run date) |
| Trusted local TLS connection | Verified | Verified |
| Negotiated protocol | {handshakes['portal-before']['negotiated_protocol']} | {handshakes['portal-after']['negotiated_protocol']} |
| Certificate fingerprint | {before['sha256_fingerprint']} | {after['sha256_fingerprint']} |
| Near-expiry flag | Present | Removed |
| Key-exchange method | Unknown | Unknown |

The expired archive remains a high review priority. The portal still needs discovery because its key-exchange method is unknown: removing a renewal flag does not prove post-quantum readiness. The before/after priority label can stay the same even though a specific issue has been resolved.

Three public certificates were inspected and two local TLS handshakes were verified. The server accepted connections on loopback only. Each client explicitly trusted its current lab certificate and checked the localhost name and validity; this is not public CA validation. Private keys were generated in a temporary directory and removed on completion. Public certificates and fingerprints are retained so the measurements can be checked.

This models certificate replacement using two disposable local server instances. It does not claim a production CA renewal, continuity of a running service, revocation testing, PQC migration or reduced banking risk. No HSBC systems were accessed. Runtime ({summary['elapsed_seconds']} seconds) measures this tiny local demonstration only.
""", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "demo")
    args = parser.parse_args()
    try:
        summary = run_demo(args.out)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Local demo failed: {error}\n")
    print(f"Demo completed: {summary['certificates_inspected']} certificates, {summary['verified_local_tls_handshakes']} verified local TLS connections.")
    print(f"Report: {args.out / 'after' / 'report.html'}")
    print(f"Evidence: {args.out / 'renewal_evidence.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
