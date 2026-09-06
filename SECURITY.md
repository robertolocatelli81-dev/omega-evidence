# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub's
"Report a vulnerability" (Security tab → Advisories) on this repository.
If that is unavailable, open an issue *asking for a private contact channel*
without disclosing details.

- You will receive an acknowledgement as soon as reasonably possible
  (best effort — this is an independently maintained open-source project,
  not a staffed security team; no SLA is promised).
- Coordinated disclosure is preferred: please allow a reasonable window
  for a fix before publishing details.
- Verified fixes are released with a changelog entry crediting the
  reporter (unless anonymity is requested).

## Supported versions

Only the **latest tagged release** receives security fixes.

## Supply-chain transparency (CRA-aligned practice)

Each release ships a **CycloneDX SBOM** and a hash-chained **CRA-style evidence
pack** as release assets. Honest scope: this project is non-commercial open
source (outside the EU Cyber Resilience Act's obligations for commercial
products); the artifacts demonstrate the evidence practice the tools themselves
implement — they are not a legal conformity claim.
