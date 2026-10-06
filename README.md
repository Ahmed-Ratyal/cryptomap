# CryptoMap

**Certificate inventory and risk-review lab with verified local TLS evidence.**

CryptoMap inspects local X.509 certificates, demonstrates certificate replacement and retesting, and produces explainable review reports. It connects measured technical properties to explicitly fictional financial-services scenarios while preserving uncertainty.

The project explores Cryptography, Data Security, secure communications and risk-review themes named in [HSBC's Cyber Graduate advert](https://apply.careers.hsbc.com/emergingtalent/job/Sheffield-Cyber-Graduate-S1-4NB/1373794857/). HSBC's [public inventory research description](https://www.ventures.hsbc.com/view) provides the motivation: discovery can support current security and future quantum-resistant infrastructure. This is independent learning work, with AI-assisted implementation; it is not HSBC software or evidence of its internal technology stack.

## Demonstrated result

| Observation | Before replacement | After replacement |
|---|---|---|
| Portal certificate lifetime | 14 days remaining | 365 days remaining |
| Explicitly trusted local TLS connection | Verified | Verified |
| Peer fingerprint matches inspected certificate | Yes | Yes; new fingerprint |
| Near-expiry warning | Present | Removed |
| Key-exchange group | Unknown | Unknown; follow-up retained |
| Separate expired archive certificate | High review priority | High review priority |

The lab inspects three certificate files and verifies two loopback TLS connections. Business names, owners, data classification and protection lifetimes are scenario assumptions. Each record explains that scope. Certificate replacement resolves the expiry condition; it does not establish post-quantum readiness.

See the [before/after evidence](examples/demo/renewal_evidence.md), [TLS observations](examples/demo/tls_observations.json), [certificate metadata](examples/demo/certificate_metadata.json) and [saved report](examples/demo/after/report.html). Download the repository and open the HTML file locally to view its layout; GitHub shows the source. Saved dates reflect the example run, not current service status.

## Quick start

Requires Python 3.10+; tested on Windows with Python 3.12 and cryptography 50.0.1.

```powershell
python -m pip install -r requirements.txt
python demo_run.py
python -m unittest discover -s tests -v
```

Open `results/demo/after/report.html` and compare it with `results/demo/before/report.html`. The demo only uses loopback networking. Internet access is needed to install the pinned dependency, not to run the demonstration. Windows users may use `py -3` instead of `python`, or `run_windows.ps1` with an optional `-PythonPath`. If scripts are blocked, use the Python commands without changing your system policy.

Review supplied CSV records independently (standard library only):

```powershell
python crypto_inventory.py data/sample_inventory.csv --out results/inventory --as-of 2026-10-06
```

Inspect local PEM certificates/bundles or DER certificate files:

```powershell
python certificates.py examples/demo/certificates --out results/certificates.json
```

## How it works

```text
Local public certificates -> X.509 inspection -> metadata and fingerprints
Loopback TLS verification -> protocol, cipher and presented-certificate evidence
Measured properties + labelled scenario context -> validated inventory
Explainable review rules -> CSV, Markdown and standalone HTML reports
```

- Expired certificates receive high review priority; certificates expiring within 30 days need review.
- Sensitive information with at least ten years of protection and recorded classical key establishment receives high review priority for long-term confidentiality discovery.
- Unknown dependencies produce follow-up actions. Classical certificate authentication alone does not prove the negotiated key-exchange group.
- The 10-year and 30-day thresholds are lab assumptions, not HSBC policy, CVSS or an NCSC risk model.
- Input validation rejects duplicate asset IDs, missing columns, empty datasets, invalid dates and non-finite/negative lifetimes. HTML escapes supplied values and needs no external assets or scripts.

## Evidence and security boundaries

The TLS clients check the localhost name and certificate validity using explicit trust of each disposable lab certificate. Verification is not disabled. Private keys are created in temporary storage and removed on completion; only public certificates are saved. This is local certificate replacement using separate server instances, not enterprise CA renewal or a continuous-service availability test.

The Python API used here records the negotiated TLS version and cipher but does not expose the exchange group. A TLS 1.3 cipher name and an RSA/ECDSA certificate are insufficient to infer that group, so the observed inventory keeps it unknown.

The project does not scan external systems, use customer data, check production trust chains/revocation, implement cryptographic algorithms, establish compliance or perform PQC migration. Runtime measurements apply only to this tiny local demonstration.

## Structure and validation

| Component | Purpose |
|---|---|
| `certificates.py` | Inspect local certificate metadata |
| `demo_run.py` | Generate lab certificates and run replacement/retest workflow |
| `crypto_inventory.py` | Validate inventory, apply rules and generate reports |
| `data/` | Five wholly simulated records for rule exploration |
| `examples/demo/` | Retained public certificates and observed before/after evidence |
| `tests/` | 12 automated checks, including the complete local TLS workflow |
| `docs/` | Demo guide, design choices and local verification record |
| `.github/workflows/tests.yml` | Windows/Python test workflow |

Tests cover certificate formats, malformed input, authentication/exchange separation, HTML escaping, replacement fingerprints and the cleared expiry warning. See the [verification record](docs/verification.md). The GitHub workflow is supplied separately from the recorded local checks.

Next steps: approved discovery scope, per-field provenance, suitable tooling for exchange-group measurement, owner-validated data lifetimes, supplier support and compatibility testing for supported PQC changes.

## Further reading

- [HSBC cryptographic inventory paper](https://www.ventures.hsbc.com/-/media/ventures/250602-cryptographic-inventory-deriving-value-today-preparing-for-tomorrow-2025.pdf) — background, not an implemented bank methodology.
- [NCSC PQC migration guidance](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines).
- [cryptography X.509 reference](https://cryptography.io/en/latest/x509/reference/) and [Python TLS reference](https://docs.python.org/3/library/ssl.html).

Licensed under the [MIT License](LICENSE).
