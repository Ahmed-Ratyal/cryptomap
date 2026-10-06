# Cryptographic inventory triage

Educational review only. Priorities below come from simple, visible rules; they are not CVSS, a regulatory rating, or any HSBC risk model. Verify records with system owners before acting.

Assessment date: 2026-10-06  
Records reviewed: 5

## SIM-01: Customer document archive

- Environment/evidence: simulated / simulated
- Data: Identity and account documents (high); expected lifetime: 15 years
- Recorded cryptography: TLS 1.3; public key: RSA; key establishment: ECDHE
- Triage: **High review priority** — Sensitive data is expected to remain valuable for at least 10 years, and the record names classical public-key key establishment; assess long-term confidentiality and migration dependencies.
- Follow-up: Validate the record with the service owner and evidence source.

## SIM-02: Payment API

- Environment/evidence: simulated / simulated
- Data: Payment transaction metadata (high); expected lifetime: 12 years
- Recorded cryptography: TLS 1.2; public key: ECDSA; key establishment: ECDHE
- Triage: **High review priority** — Sensitive data is expected to remain valuable for at least 10 years, and the record names classical public-key key establishment; assess long-term confidentiality and migration dependencies.
- Follow-up: Validate the record with the service owner and evidence source.

## SIM-05: Partner document exchange

- Environment/evidence: simulated / simulated
- Data: Fictional financial documents (high); expected lifetime: 20 years
- Recorded cryptography: TLS 1.2; public key: RSA; key establishment: DHE
- Triage: **High review priority** — Sensitive data is expected to remain valuable for at least 10 years, and the record names classical public-key key establishment; assess long-term confidentiality and migration dependencies.
- Follow-up: Validate the record with the service owner and evidence source.

## SIM-04: Legacy report exchange

- Environment/evidence: simulated / simulated
- Data: Confidential reports (high); expected lifetime: unknown years
- Recorded cryptography: unknown; public key: unknown; key establishment: unknown
- Triage: **Needs review** — Cryptographic dependencies are unknown; perform discovery.
- Follow-up: Confirm the owner. Confirm the protocol. Confirm the public-key algorithm. Confirm the key-establishment method. Confirm the supplier or dependency. Confirm how long the data must remain confidential or useful.

## SIM-03: Staff information page

- Environment/evidence: simulated / simulated
- Data: Public information (low); expected lifetime: 1 years
- Recorded cryptography: TLS 1.3; public key: ECDSA; key establishment: ECDHE
- Triage: **No rule triggered** — No high-priority condition was established by these simple rules; this does not mean the service is secure or migration-ready.
- Follow-up: Validate the record with the service owner and evidence source.

## Limitations

This tool reads only the supplied CSV. It does not scan systems, verify algorithms, determine exploitability, implement post-quantum cryptography, or prove that an asset is secure. Simulated records must remain labelled as simulated.
