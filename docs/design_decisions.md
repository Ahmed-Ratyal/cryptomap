# Design decisions and limits

| Decision | Reason | Limit |
|---|---|---|
| Local certificate files plus loopback TLS | Reproducible observed evidence without touching outside systems | Does not discover an estate |
| Explicit trust of each lab certificate and hostname validation | Avoids disabling certificate verification in the demonstration | Not public CA chain assessment |
| Temporary disposable private keys | Public examples can be shared without secrets | File deletion is not a secure-erasure guarantee |
| Key exchange recorded as unknown | Certificate key and TLS 1.3 cipher do not identify the negotiated group through this API | Further approved TLS inspection needed |
| Auth and key-establishment rules separated | Avoids conflating authentication quantum risk with long-term confidentiality | Supplied manual records still need verification |
| Fixed visible lab thresholds | Easy to review and explain | Not an official bank risk model |
| Mixed records have explicit evidence notes | Measured properties remain distinguishable from assumptions | Per-field provenance is a future improvement |
| CSV, JSON, Markdown and static HTML | Machine-readable evidence and readable stakeholder output | No enterprise UI, database or integrations |
| Automated test of the full local workflow | Confirms replacement and remaining uncertainty | Does not demonstrate production reliability |

AI assistance was used to implement and package this learning project. Evidence files contain lab certificates, not live customer or organisational data.
