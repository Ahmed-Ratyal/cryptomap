"""Inspect local X.509 certificate files; do not infer negotiated key exchange."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa


def certificate_metadata(cert: x509.Certificate, source: str) -> dict:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm, bits = "ECDSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        algorithm, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        algorithm, bits = "Ed448", 448
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, bits = "DSA", key.key_size
    else:
        algorithm, bits = type(key).__name__, None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(value.value) for value in san]
    except x509.ExtensionNotFound:
        names = []
    return {
        "source": source,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_issued": cert.subject == cert.issuer,
        "public_key_algorithm": algorithm,
        "public_key_bits": bits,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "intrinsic",
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_until": cert.not_valid_after_utc.isoformat(),
        "certificate_expiry": cert.not_valid_after_utc.date().isoformat(),
        "subject_alternative_names": names,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "key_establishment": "unknown",
        "evidence_scope": "Observed certificate bytes only; no chain, revocation, TLS exchange or business-data assessment.",
    }


def inspect_file(path: Path) -> list[dict]:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        certs = x509.load_pem_x509_certificates(data)
    else:
        certs = [x509.load_der_x509_certificate(data)]
    return [certificate_metadata(cert, f"{path.name}#{index}") for index, cert in enumerate(certs, 1)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--out", type=Path, default=Path("results/certificate_metadata.json"))
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error("certificate folder does not exist")
    paths = sorted(p for p in args.folder.iterdir() if p.is_file() and p.suffix.lower() in {".pem", ".crt", ".cer", ".der"})
    if not paths:
        parser.error("no certificate files found")
    records = []
    for path in paths:
        try:
            records.extend(inspect_file(path))
        except (ValueError, OSError) as error:
            parser.error(f"cannot inspect {path.name}: {error}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"Inspected {len(records)} local certificates; wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
