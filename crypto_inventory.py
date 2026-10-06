#!/usr/bin/env python3
"""Review a small CSV cryptographic inventory and explain follow-up priorities.

This educational helper does not discover assets or calculate an official risk
score. It applies visible triage rules to evidence supplied by the user.
"""

from __future__ import annotations

import argparse
import csv
import html
import math
import re
from datetime import date, datetime
from pathlib import Path


FIELDS = [
    "asset_id", "service", "owner", "environment", "data_type",
    "data_sensitivity", "expected_data_lifetime_years", "transport",
    "protocol", "certificate_expiry", "public_key_algorithm",
    "key_establishment", "crypto_dependency_known", "provider_or_dependency",
    "evidence_status", "confidence",
]
DETAIL_FIELDS = ["evidence_notes", "certificate_fingerprint", "public_key_bits", "signature_algorithm"]

PUBLIC_KEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:RSA|ECDSA|DSA|Ed25519|Ed448|ECDH|ECDHE|elliptic[- ]curve|Diffie[- ]Hellman|DH)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
SENSITIVE = {"high", "very high", "restricted", "confidential"}
KEY_EXCHANGE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:RSA|ECDH|ECDHE|Diffie[- ]Hellman|DHE|DH)(?![A-Za-z0-9])", re.IGNORECASE,
)


def is_unknown(value: str) -> bool:
    return value.strip().casefold() in {"", "unknown", "n/a", "not recorded"}


def uses_public_key(value: str) -> bool:
    return bool(PUBLIC_KEY_PATTERN.search(value.strip()))


def assess(row: dict[str, str], today: date) -> dict[str, str]:
    reasons: list[str] = []
    follow_up: list[str] = []
    urgency = 0

    for key, label in (("owner", "owner"), ("protocol", "protocol"),
                        ("public_key_algorithm", "public-key algorithm"),
                        ("key_establishment", "key-establishment method"),
                        ("provider_or_dependency", "supplier or dependency")):
        if is_unknown(row.get(key, "")):
            follow_up.append(f"Confirm the {label}.")

    sensitivity = row.get("data_sensitivity", "").strip().casefold()
    lifetime = row.get("expected_data_lifetime_years", "").strip()
    try:
        years = float(lifetime)
    except ValueError:
        years = None

    classical_auth = uses_public_key(row.get("public_key_algorithm", ""))
    classical_exchange = bool(KEY_EXCHANGE_PATTERN.search(row.get("key_establishment", "")))
    public_key = classical_auth or classical_exchange
    long_lived = years is not None and years >= 10
    if sensitivity in SENSITIVE and long_lived and classical_exchange:
        urgency = max(urgency, 3)
        reasons.append(
            "Sensitive data is expected to remain valuable for at least 10 years, "
            "and the record names classical public-key key establishment; assess "
            "long-term confidentiality and migration dependencies."
        )
    elif sensitivity in SENSITIVE and public_key:
        urgency = max(urgency, 2)
        reasons.append(
            "Sensitive data and a public-key dependency warrant cryptographic "
            "discovery; confirm the data lifetime before setting migration priority."
        )
    if classical_auth and is_unknown(row.get("key_establishment", "")):
        urgency = max(urgency, 2)
        reasons.append(
            "The certificate records a classical authentication key. Its key type "
            "does not establish the TLS key-exchange group or quantum readiness."
        )

    if years is None:
        follow_up.append("Confirm how long the data must remain confidential or useful.")
    if is_unknown(row.get("data_sensitivity", "")):
        follow_up.append("Have the data owner classify the information.")
    if is_unknown(row.get("public_key_algorithm", "")) and is_unknown(
        row.get("key_establishment", "")
    ):
        urgency = max(urgency, 2)
        reasons.append("Cryptographic dependencies are unknown; perform discovery.")

    expiry = row.get("certificate_expiry", "").strip()
    if not is_unknown(expiry):
        try:
            expires = datetime.strptime(expiry, "%Y-%m-%d").date()
            days_left = (expires - today).days
            if days_left < 0:
                urgency = max(urgency, 3)
                reasons.append("Recorded certificate expiry has passed; validate and renew.")
                follow_up.append("Validate the expiry with the service owner, replace the certificate and retest.")
            elif days_left <= 30:
                urgency = max(urgency, 2)
                reasons.append(f"Recorded certificate expires in {days_left} days; plan renewal.")
                follow_up.append("Schedule certificate replacement and a TLS retest before expiry.")
        except ValueError:
            follow_up.append("Check certificate_expiry; use YYYY-MM-DD or unknown.")

    if follow_up:
        urgency = max(urgency, 2)
        if not reasons:
            reasons.append("Inventory gaps need human validation before a risk decision.")
    if not reasons:
        reasons.append(
            "No high-priority condition was established by these simple rules; "
            "this does not mean the service is secure or migration-ready."
        )
    if not follow_up:
        follow_up.append("Validate the record with the service owner and evidence source.")

    priority = {3: "High review priority", 2: "Needs review", 0: "No rule triggered"}[urgency]
    return {
        **row,
        "triage_priority": priority,
        "triage_reason": " ".join(reasons),
        "follow_up": " ".join(follow_up),
        "assessment_date": today.isoformat(),
    }


def write_html_report(rows: list[dict[str, str]], output: Path, assessment_date: date) -> None:
    """Write a standalone, escaped HTML report with no external resources."""
    escape = lambda value: html.escape(str(value), quote=True)
    counts = {level: sum(r["triage_priority"] == level for r in rows) for level in
              ("High review priority", "Needs review", "No rule triggered")}
    cards = []
    for row in rows:
        badge = "high" if row["triage_priority"] == "High review priority" else "review"
        note = row.get("evidence_notes") or "Supplied inventory record; validate against its source."
        cards.append(f'''<article><div class="top"><h2>{escape(row['service'])}</h2>
<span class="badge {badge}">{escape(row['triage_priority'])}</span></div>
<p class="meta">{escape(row['asset_id'])} · {escape(row['environment'])} · evidence: {escape(row['evidence_status'])} · confidence: {escape(row['confidence'])}</p>
<dl><dt>Data context</dt><dd>{escape(row['data_type'])}; {escape(row['data_sensitivity'])}; lifetime {escape(row['expected_data_lifetime_years'])} years</dd>
<dt>Certificate / transport</dt><dd>{escape(row['public_key_algorithm'])} / {escape(row['public_key_bits'] or 'unknown')} bits · {escape(row['protocol'])} · expiry {escape(row['certificate_expiry'])}</dd>
<dt>Key establishment</dt><dd>{escape(row['key_establishment'])}</dd>
<dt>Why review</dt><dd>{escape(row['triage_reason'])}</dd>
<dt>Next action</dt><dd>{escape(row['follow_up'])}</dd>
<dt>Evidence scope</dt><dd>{escape(note)}</dd></dl>
<details><summary>Certificate evidence</summary><p class="meta">SHA-256 fingerprint: {escape(row.get('certificate_fingerprint') or 'not recorded')}<br>Signature algorithm OID: {escape(row.get('signature_algorithm') or 'not recorded')}</p></details></article>''')
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CryptoMap review</title>
<style>body{{font:16px/1.55 system-ui,sans-serif;color:#172437;background:#f3f5f7;margin:0}}main{{max-width:1040px;margin:auto;padding:40px 22px}}h1{{font-size:36px;letter-spacing:-1px;margin:8px 0}}h2{{font-size:21px;margin:0}}.eyebrow{{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#486173}}.lead{{max-width:760px;color:#526173}}.stats{{display:flex;gap:14px;flex-wrap:wrap;margin:28px 0}}.stat{{background:white;border:1px solid #dfe4e8;border-radius:10px;padding:17px 24px;flex:1;min-width:145px}}.stat strong{{font-size:29px;display:block}}article{{background:white;border:1px solid #dfe4e8;border-radius:10px;margin:16px 0;padding:24px}}.top{{display:flex;justify-content:space-between;gap:15px;align-items:center;flex-wrap:wrap}}.badge{{font-size:13px;padding:5px 10px;border-radius:5px;background:#e8eff5;color:#23405a}}.badge.high{{background:#fff0de;color:#754100}}.meta{{color:#647386;font-size:14px}}dl{{display:grid;grid-template-columns:170px 1fr;gap:10px;margin-bottom:0}}dt{{font-weight:600}}dd{{margin:0;overflow-wrap:anywhere}}.scope{{border-left:4px solid #3b617c;padding:12px 18px;background:#e8eff5;margin:24px 0}}footer{{font-size:14px;color:#526173;margin-top:30px}}a{{color:#285a7d}}@media(max-width:600px){{dl{{grid-template-columns:1fr;gap:4px}}dd{{margin-bottom:12px}}h1{{font-size:29px}}}}@media print{{body{{background:white}}main{{padding:0}}article{{break-inside:avoid}}}}</style></head><body><main>
<div class="eyebrow">Independent cryptography and data-security lab</div><h1>CryptoMap review</h1>
<p class="lead">Evidence-led discovery and follow-up priorities. Assessment date: {escape(assessment_date.isoformat())}. These labels guide review; they are not official risk scores.</p>
<div class="stats">{''.join(f'<div class="stat"><strong>{number}</strong>{escape(label)}</div>' for label, number in counts.items())}</div>
<div class="scope"><strong>Read the evidence scope.</strong> The included banking scenarios are fictional. Local certificate properties can be measured, while sensitivity and retention remain scenario assumptions. A certificate's key type does not identify TLS key exchange, and renewal does not establish post-quantum security.</div>
{''.join(cards)}<footer><strong>Limitations:</strong> inventory review does not establish exploitability, trust-chain validity, revocation status, regulatory compliance or production readiness.
<p>Context: <a href="https://www.ventures.hsbc.com/view">HSBC cryptographic-inventory research</a> · <a href="https://www.ncsc.gov.uk/guidance/pqc-migration-timelines">NCSC migration guidance</a></p></footer></main></body></html>'''
    output.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="Input inventory CSV")
    parser.add_argument("--out", type=Path, default=Path("results"), help="Output directory")
    parser.add_argument(
        "--as-of", type=date.fromisoformat, default=date.today(), metavar="YYYY-MM-DD",
        help="Date for certificate-expiry triage (defaults to today)",
    )
    args = parser.parse_args()

    if not args.inventory.is_file():
        parser.error(f"inventory file not found: {args.inventory}")

    with args.inventory.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if len(reader.fieldnames or []) != len(set(reader.fieldnames or [])):
            parser.error("inventory has duplicate column names")
        missing = [field for field in FIELDS if field not in (reader.fieldnames or [])]
        if missing:
            parser.error("inventory is missing required columns: " + ", ".join(missing))
        raw_rows = list(reader)
    if not raw_rows:
        parser.error("inventory contains no asset records")

    rows: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for line_number, raw in enumerate(raw_rows, start=2):
        if None in raw:
            parser.error(f"line {line_number} has more values than the CSV header")
        row = {key: (raw.get(key) or "").strip() for key in FIELDS + DETAIL_FIELDS}
        asset_id = row["asset_id"]
        if is_unknown(asset_id):
            parser.error(f"line {line_number} has no asset_id")
        if asset_id.casefold() in seen_ids:
            parser.error(f"line {line_number} repeats asset_id {asset_id!r}")
        seen_ids.add(asset_id.casefold())
        lifetime = row["expected_data_lifetime_years"]
        if not is_unknown(lifetime):
            try:
                parsed_lifetime = float(lifetime)
                if not math.isfinite(parsed_lifetime) or parsed_lifetime < 0:
                    raise ValueError
            except ValueError:
                parser.error(f"line {line_number} has invalid expected_data_lifetime_years")
        sensitivity = row["data_sensitivity"].casefold()
        if sensitivity not in {"", "unknown", "low", "medium", "high", "very high", "public", "confidential", "restricted"}:
            parser.error(f"line {line_number} has unrecognised data_sensitivity {row['data_sensitivity']!r}")
        confidence = row["confidence"].casefold()
        if confidence not in {"", "unknown", "low", "medium", "high"}:
            parser.error(f"line {line_number} has unrecognised confidence {row['confidence']!r}")
        evidence_status = row["evidence_status"].casefold()
        if evidence_status not in {"", "unknown", "observed", "simulated", "example only", "manual"}:
            parser.error(f"line {line_number} has unrecognised evidence_status {row['evidence_status']!r}")
        expiry = row["certificate_expiry"]
        if not is_unknown(expiry):
            try:
                date.fromisoformat(expiry)
            except ValueError:
                parser.error(f"line {line_number} has invalid certificate_expiry; use YYYY-MM-DD")
        rows.append(row)

    assessed = [assess(row, args.as_of) for row in rows]
    rank = {"High review priority": 0, "Needs review": 1, "No rule triggered": 2}
    assessed.sort(key=lambda row: (rank[row["triage_priority"]], row["asset_id"].casefold()))

    args.out.mkdir(parents=True, exist_ok=True)
    csv_path = args.out / "priority_review.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS + DETAIL_FIELDS + [
            "triage_priority", "triage_reason", "follow_up", "assessment_date",
        ])
        writer.writeheader()
        writer.writerows(assessed)

    report_path = args.out / "triage_summary.md"
    with report_path.open("w", encoding="utf-8") as stream:
        stream.write("# Cryptographic inventory triage\n\n")
        stream.write(
            "Educational review only. Priorities below come from simple, visible rules; "
            "they are not CVSS, a regulatory rating, or any HSBC risk model. Verify "
            "records with system owners before acting.\n\n"
        )
        stream.write(f"Assessment date: {args.as_of.isoformat()}  \nRecords reviewed: {len(assessed)}\n\n")
        for row in assessed:
            stream.write(f"## {row['asset_id']}: {row['service']}\n\n")
            stream.write(f"- Environment/evidence: {row['environment']} / {row['evidence_status']}\n")
            stream.write(f"- Data: {row['data_type']} ({row['data_sensitivity']}); expected lifetime: {row['expected_data_lifetime_years']} years\n")
            stream.write(f"- Recorded cryptography: {row['protocol']}; public key: {row['public_key_algorithm']}; key establishment: {row['key_establishment']}\n")
            stream.write(f"- Triage: **{row['triage_priority']}** — {row['triage_reason']}\n")
            stream.write(f"- Follow-up: {row['follow_up']}\n\n")
            if row.get("evidence_notes"):
                stream.write(f"- Evidence scope: {row['evidence_notes']}\n\n")
        stream.write(
            "## Limitations\n\nThis tool reads only the supplied CSV. It does not scan systems, "
            "verify algorithms, determine exploitability, implement post-quantum "
            "cryptography, or prove that an asset is secure. Simulated records must "
            "remain labelled as simulated.\n"
        )

    print(f"Reviewed {len(assessed)} records.")
    print(f"CSV: {csv_path}")
    print(f"Summary: {report_path}")
    html_path = args.out / "report.html"
    write_html_report(assessed, html_path, args.as_of)
    print(f"HTML: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
