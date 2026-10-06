# Local certificate replacement and retest

Assessment date: 2026-10-06. This is a controlled lab with fictional banking context.

| Check | Before | After |
|---|---|---|
| Portal certificate expiry | 2026-10-20 (14 days from run date) | 2027-10-06 (365 days from run date) |
| Trusted local TLS connection | Verified | Verified |
| Negotiated protocol | TLSv1.3 | TLSv1.3 |
| Certificate fingerprint | 8f2deb34fc6c98c70b9ec69b99ba4cc0fbda042ce57f3cdc77fd1f88a0d5b1ff | ffd5ef5faf607aa811b388f1fa00d7d1fd04b657bf039be7b968f9bcb089830a |
| Near-expiry flag | Present | Removed |
| Key-exchange method | Unknown | Unknown |

The expired archive remains a high review priority. The portal still needs discovery because its key-exchange method is unknown: removing a renewal flag does not prove post-quantum readiness. The before/after priority label can stay the same even though a specific issue has been resolved.

Three public certificates were inspected and two local TLS handshakes were verified. The server accepted connections on loopback only. Each client explicitly trusted its current lab certificate and checked the localhost name and validity; this is not public CA validation. Private keys were generated in a temporary directory and removed on completion. Public certificates and fingerprints are retained so the measurements can be checked.

This models certificate replacement using two disposable local server instances. It does not claim a production CA renewal, continuity of a running service, revocation testing, PQC migration or reduced banking risk. No HSBC systems were accessed. Runtime (0.518 seconds) measures this tiny local demonstration only.
