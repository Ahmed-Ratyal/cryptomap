# Cryptographic inventory triage

Educational review only. Priorities below come from simple, visible rules; they are not CVSS, a regulatory rating, or any HSBC risk model. Verify records with system owners before acting.

Assessment date: 2026-10-06  
Records reviewed: 2

## LAB-01: Customer archive (fictional)

- Environment/evidence: local lab / fictional business context / observed
- Data: fictional customer records (high); expected lifetime: 15 years
- Recorded cryptography: unknown; public key: ECDSA; key establishment: unknown
- Triage: **High review priority** — Sensitive data and a public-key dependency warrant cryptographic discovery; confirm the data lifetime before setting migration priority. The certificate records a classical authentication key. Its key type does not establish the TLS key-exchange group or quantum readiness. Recorded certificate expiry has passed; validate and renew.
- Follow-up: Confirm the protocol. Confirm the key-establishment method. Validate the expiry with the service owner, replace the certificate and retest.

- Evidence scope: Observed: generated local certificate metadata; no handshake attempted for this expired certificate. Fictional: service name, owner, data type, sensitivity and 15-year protection lifetime. Key exchange is unknown.

## LAB-02: Customer portal (fictional)

- Environment/evidence: local lab / fictional business context / observed
- Data: fictional customer records (high); expected lifetime: 15 years
- Recorded cryptography: TLSv1.3; public key: RSA; key establishment: unknown
- Triage: **Needs review** — Sensitive data and a public-key dependency warrant cryptographic discovery; confirm the data lifetime before setting migration priority. The certificate records a classical authentication key. Its key type does not establish the TLS key-exchange group or quantum readiness. Recorded certificate expires in 14 days; plan renewal.
- Follow-up: Confirm the key-establishment method. Schedule certificate replacement and a TLS retest before expiry.

- Evidence scope: Observed: generated local certificate metadata and verified loopback TLS handshake. Fictional: service name, owner, data type, sensitivity and 15-year protection lifetime. Key exchange is unknown.

## Limitations

This tool reads only the supplied CSV. It does not scan systems, verify algorithms, determine exploitability, implement post-quantum cryptography, or prove that an asset is secure. Simulated records must remain labelled as simulated.
