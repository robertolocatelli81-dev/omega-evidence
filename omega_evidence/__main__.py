"""`python -m omega_evidence <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]`."""
from .verifier import main

raise SystemExit(main())
