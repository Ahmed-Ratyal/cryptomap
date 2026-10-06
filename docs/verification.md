# Verification record

Validated on 6 October 2026 on Windows, Python 3.12, cryptography 50.0.1.

- 12 automated tests passed, including actual loopback TLS integration.
- Three certificates inspected; two verified local TLS handshakes completed.
- Replacement changed the portal fingerprint and removed its 14-day expiry warning.
- Unknown key exchange remained visible; the expired archive stayed flagged.
- Certificate inspector parsed all three saved demo certificates.
- The Windows launcher worked from outside the project folder in demo and inventory-only modes, with script execution allowed for that test process only. No persistent PowerShell policy was changed. The README offers direct Python commands when scripts are blocked.
- ZIP integrity passed; directory structure was retained; private keys, caches and working results were excluded.
- The ZIP was extracted into a separate temporary folder; tests, demo, inspector and launcher modes passed there.

GitHub workflow results are recorded separately in the repository Actions tab. These checks used the installed pinned dependency; a fresh internet-based dependency installation was not part of this local verification.
