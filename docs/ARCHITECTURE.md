# Architecture

## Pipeline

```
OpenAPI spec ─▶ spec_parser.parse_spec() ─▶ [Endpoint]
                                                │
roles.yaml ─▶ config.loader.load_scan_config() │
                    │                           │
                    ▼                           ▼
              ScanConfig(roles, workflows, ...) │
                    │                           │
                    └────────────┬──────────────┘
                                 ▼
                     engine.runner.run_scan()
                                 │
        ┌───────────┬───────────┼───────────┬────────────┐
        ▼           ▼           ▼           ▼            ▼
     BolaCheck   BflaCheck  PrivEscCheck  ParamTamper  BusinessLogic
        │           │           │           │            │
        └───────────┴───────────┴───────────┴────────────┘
                                 │  (candidate Findings, evidence attached)
                                 ▼
                     verification.Verifier.verify_all()
                                 │  (confirmed / unverified Findings)
                                 ▼
                   attack_path.graph.build_attack_paths()
                                 │
                                 ▼
                          ScanResult (findings + attack_paths)
                                 │
                                 ▼
                     reporting.report.write_{md,html,json}()
```

## Design principles

**1. Checks over-flag on purpose; verification is a separate, mandatory stage.**
Every check module (`checks/*.py`) follows the same contract: emit a `Finding` for any
cross-role request that returns a successful status code, and attach the full evidence
(request + response) for it. Checks never decide `confirmed=True` themselves. This keeps
each check simple (it only has to express "this looks worth investigating") and keeps all
false-positive-reduction logic in one auditable place: `verification/verifier.py`.

**2. Verification inspects content, not just status codes.**
A 200 response with an empty body, a redirect page, or an "access denied" message dressed
up as a 200 (some apps do this) is not evidence of a real BOLA. The verifier:
- re-issues the request to check reproducibility,
- regex-scans the response body for error-shaped language and drops matches,
- for BOLA, looks for a configured `identity_marker` belonging to the victim role to reach
  the highest confidence tier,
- for privilege escalation, actually re-probes a restricted endpoint post-tamper to see if
  a capability change is directly observable, rather than trusting the PATCH/PUT response
  alone.

This is what separates "a scanner that flags status codes" from "a tool that verifies
findings," which was an explicit design requirement.

**3. Business logic can't be inferred from a spec - so it's config-driven.**
BOLA/BFLA/privesc/param-tampering can all be derived heuristically from endpoint shape
(ID-bearing paths, sensitive field names, declared role requirements). "Is this the
correct order of operations for checkout" cannot be - so `business_logic.py` only acts on
explicitly declared `workflows` in the scan config, testing two concrete abuse patterns
(step-skipping, unsafe replay) rather than trying to guess business intent.

**4. Privileged roles are excluded from acting as BOLA attackers.**
Early in development, testing against the included lab surfaced a real false-positive
class: an admin persona reading another user's data via a legitimately-permissive endpoint
was being flagged as a BOLA violation. `BolaCheck` now identifies the highest
`privilege_rank` role(s) in the config and excludes them from the "attacker" side of BOLA
probes (they can still be tested as a *victim* - can a lower-privileged role read the
admin's data?). This mirrors how a human tester would scope the test: you don't attack
with your own admin credentials and call the result a vulnerability.

**5. Attack paths are additive, not a replacement.**
`attack_path/graph.py` only chains **confirmed** findings, using two grounded heuristics
(privesc → BFLA, BOLA-recon → privesc/BFLA). If no chain exists, every confirmed finding is
still reported individually. Attack paths exist to communicate compounding impact to a
reader who needs to prioritize remediation, not to replace the finding list.

**6. Evidence is first-class and redacted.**
Every HTTP call made by the tool goes through `engine/http_client.py`, which captures an
`Evidence` object (method, URL, status, timing, request/response bodies) and redacts
`Authorization`/`Cookie`/`X-Api-Key` headers before it's ever stored or rendered into a
report. This is what lets a report reader independently verify a finding rather than
trusting a one-line summary.

## Extension points

- **New check module**: subclass `checks.base.BaseCheck`, implement `run(endpoints) ->
  List[Finding]`, register it in `checks/__init__.py::ALL_CHECKS`. It will automatically
  get picked up by `--checks` filtering and the verification/attack-path stages, as long
  as it sets `vuln_class` to a value the verifier and attack-path builder know how to
  handle (or falls through to the default pass-through in `Verifier._verify_one`).
- **New verification strategy**: add a `_verify_<name>` method to `Verifier` and dispatch
  to it in `_verify_one` based on `f.vuln_class`.
- **New attack-path heuristic**: add a chaining function in `attack_path/graph.py`; it
  only needs `confirmed` findings grouped by actor role, which `build_attack_paths`
  already provides.
- **New report format**: add a Jinja2 template under `reporting/templates/` and a
  `write_<format>()` function in `reporting/report.py` that renders `ScanResult`.

## Why not an LLM-driven agent?

An LLM-driven "autonomous pentester" is non-deterministic, hard to audit, and hard to
scope safely (it can decide to try things nobody asked for). This project intentionally
uses a fixed, reviewable set of testing strategies with deterministic verification logic,
so every finding in a report can be traced back to exact, reproducible request/response
evidence and a specific, readable code path that produced it. That auditability is the
point.
