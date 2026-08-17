# API Attack-Path & Authorization Tester

**Authorized API security testing focused on real authorization bugs, not generic
vulnerability noise.**

Given an OpenAPI spec and a set of role-based credentials, this tool automatically probes
for the authorization flaws that dominate real-world API breaches - BOLA/IDOR, broken
function-level authorization (BFLA), privilege escalation via mass assignment, parameter
tampering, and business-logic/workflow abuse - and it **verifies every finding** before
reporting it: reproduces the request, inspects response content (not just status codes),
and drops or clearly downgrades anything that doesn't hold up. Confirmed findings are then
chained into **attack paths** showing how they compound (e.g. "low-priv user escalates
their own role, then reaches an admin-only endpoint").

> ⚠️ **For authorized security testing only.** The CLI refuses to run without an explicit
> `--yes-i-am-authorized` flag, and this project is not, and is not intended to become,
> an autonomous "AI pentesting agent" - it's a focused, deterministic, evidence-driven
> testing tool you point at systems you're authorized to test.

## Why this exists

Most "API security scanners" either (a) fuzz everything and drown you in unconfirmed noise,
or (b) are general-purpose DAST tools with authorization testing bolted on as an
afterthought. This tool does one thing: given the identities of your test personas, it
systematically exercises the OWASP API Security Top 10's authorization-related categories
(API1 BOLA, API3 broken property-level authorization, API5 BFLA, API6 business flow abuse)
and only reports what it can back up with request/response evidence.

## Features

- **OpenAPI-driven discovery** - parses OpenAPI 3.x (JSON or YAML) into a normalized
  endpoint inventory, including `x-required-roles` for declaring intended access control.
- **Five focused check modules**: BOLA/IDOR, BFLA, privilege escalation (mass assignment,
  with live capability re-verification), parameter tampering, and config-driven
  business-logic/workflow abuse (step-skipping, unsafe replay).
- **Verification, not just detection** - a dedicated verification layer re-tests every
  candidate for reproducibility and inspects response content before marking anything
  `confirmed`. Unconfirmed candidates are kept in the report, clearly labeled, never
  silently dropped and never overstated.
- **Attack-path correlation** - chains confirmed findings into narratives ("recon via BOLA,
  then abuse a function-level flaw") grounded entirely in what was actually observed.
- **Evidence-based reporting** - every finding ships with the full redacted
  request/response pairs that back it up, in Markdown, HTML, and JSON.
- **CLI-first**, scriptable, CI-friendly, Docker-ready.
- **A deliberately vulnerable lab** included, with 8 seeded vulnerabilities and 2 safe
  control endpoints, so you (or anyone reviewing this project) can see it work end-to-end
  in minutes with zero setup.

## Quickstart

```bash
git clone <this-repo>
cd api-attack-tester
./setup.sh
```

That's the whole install: it creates a `.venv`, installs pinned dependencies, and verifies
the `apiattack` CLI runs. (Kali/Debian users: if `python3-venv` is missing, `setup.sh` will
offer to install it via `apt` for you.)

### 1. Try it against the included vulnerable lab

The fastest path - one command starts the lab, generates role tokens, and runs a full scan:

```bash
make lab-scan
```

Open `./report/report.html` (or `report.md`). A pre-generated example lives at
[`examples/sample-report/report.md`](examples/sample-report/report.md).

Other useful `make` targets: `make lab` (start lab only), `make lab-stop`, `make test`,
`make docker-demo` (same thing via Docker), `make clean` (reset everything). Run `make help`
for the full list.

<details>
<summary>Prefer to run it manually instead of via <code>make</code>?</summary>

```bash
source .venv/bin/activate
cd lab && python app.py &
cd ..
python3 scripts/generate_lab_config.py http://localhost:8000
apiattack scan \
  --spec examples/openapi_lab.yaml \
  --config examples/roles_lab.yaml \
  --out ./report \
  --yes-i-am-authorized
```
</details>

Or, with Docker only (no local Python needed):

```bash
./scripts/run_demo.sh
```

Open `./report/report.html` (or `report.md`). A pre-generated example lives at
[`examples/sample-report/report.md`](examples/sample-report/report.md).

### 2. Point it at your own API

```bash
source .venv/bin/activate
apiattack init-config --out roles.yaml   # scaffold a config
# edit roles.yaml: base_url, role tokens, owned_resources, endpoint_role_requirements, workflows
apiattack inspect-spec --spec your-openapi.yaml   # sanity-check what will be tested
apiattack scan --spec your-openapi.yaml --config roles.yaml --out ./report --yes-i-am-authorized
```

## How verification works (the important part)

Check modules deliberately over-flag: any cross-role success is a *candidate*. The
verification layer then:

1. **Re-issues the request** to confirm the result reproduces (not a one-off flake/race).
2. **Inspects response content**, not just the status code - an empty body or an
   error-shaped message on a 200 is not treated as evidence of a real leak.
3. **Checks for victim identity markers** (configurable per role) to reach
   `verified-high-confidence` when the response demonstrably contains another
   principal's data.
4. For privilege escalation, **replays a restricted-endpoint call** after the suspected
   escalation to directly observe whether a capability change actually occurred, rather
   than trusting that a 200 on a PATCH means anything changed.

Anything that doesn't clear these bars stays in the report as `unverified` (visibly
labeled, not counted as confirmed) rather than being hidden or inflated.

## Example finding types detected

| Class | OWASP API Security Top 10 | Example |
|---|---|---|
| BOLA/IDOR | API1:2023 | User A reads/mutates User B's resource via a predictable ID. |
| BFLA | API5:2023 | A non-admin role calls an admin-only endpoint directly. |
| Privilege escalation | API5/API3:2023 | Mass assignment lets a user set their own `role` field to `admin`. |
| Parameter tampering | API6:2023 | Client-controlled `price`/`status` fields are trusted server-side. |
| Business logic flaw | API6:2023 | Checkout succeeds without a completed payment step; a coupon is reusable. |

## Project layout

```
src/apiattack/       Core library + CLI
  spec_parser.py      OpenAPI -> Endpoint objects
  config/loader.py     roles/workflow scan configuration
  engine/              HTTP client + scan orchestrator
  checks/              BOLA, BFLA, privesc, param tampering, business logic
  verification/        confirms/downgrades candidates
  attack_path/         chains confirmed findings into attack paths
  reporting/           Markdown/HTML/JSON report generation
lab/                  Deliberately vulnerable Flask target + its own README
examples/             Sample OpenAPI spec, config scaffold, sample report
tests/                Unit + integration tests (integration runs against the lab in-process)
docs/ARCHITECTURE.md  Design notes and extension points
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a deeper design walkthrough.

## Configuring roles (the authorization boundary you're testing)

`apiattack init-config` scaffolds a `roles.yaml`. The important pieces:

- **`roles`** - each test identity: its auth header, which resources it owns
  (`owned_resources`, mapped by path-parameter name), a `privilege_rank` (used to identify
  which role is allowed broad cross-account access, e.g. an admin persona, so it isn't
  flagged as an attacker in BOLA tests), and optional `identity_markers` (strings that
  should only appear in that role's own data, used to confirm data leakage with high
  confidence).
- **`endpoint_role_requirements`** - explicitly declares which roles *should* be allowed
  to call a given endpoint; this drives the BFLA check. (Can also be set per-operation in
  the OpenAPI spec via `x-required-roles`.)
- **`workflows`** - ordered business-flow definitions, with `skip_step_test` /
  `replay_step_test` marking which abuse pattern to try; this drives the business-logic
  check, since correct sequencing can't be inferred from a spec alone.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q                    # unit tests + integration tests against the in-process lab
pytest --cov=apiattack -q    # with coverage
```

Integration tests assert both that every seeded vulnerability in the lab is confirmed
**and** that the two safe control endpoints are *not* flagged - i.e. the suite checks for
false negatives and false positives.

## Docker

```bash
docker compose build
docker compose up -d lab
docker compose run --rm apiattack scan \
  --spec examples/openapi_lab.yaml --config examples/roles_lab.yaml \
  --out reports --yes-i-am-authorized
```

## Roadmap / deliberate non-goals

- **In scope for future work**: GraphQL support, OAuth2/OIDC login flow automation,
  rate-limit/DoS-adjacent business-logic checks, SARIF output for CI gating.
- **Deliberately out of scope**: this is not a generic vulnerability scanner (no SQLi/XSS/
  fuzzing engine) and not an autonomous LLM-driven pentesting agent - it's a
  deterministic, auditable authorization-testing tool with a fixed, reviewable set of
  check strategies.

## Legal / ethical use

Only run this against systems you own or have explicit written authorization to test.
The tool will refuse to scan without `--yes-i-am-authorized`; that flag is a reminder, not
a substitute for actual authorization. The included lab is intentionally vulnerable and
must not be exposed outside a local/isolated environment.

## License

MIT - see [`LICENSE`](LICENSE).
