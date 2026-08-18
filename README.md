# API Attack-Path Tester (APIAT)

**API Attack-Path Tester (APIAT)** is an authorization-focused API security testing framework for identifying, verifying, and correlating API authorization and business-logic vulnerabilities.

The project is designed around **role-based testing, resource ownership, HTTP evidence, verification, and attack-path correlation** rather than treating every suspicious response as a confirmed vulnerability.

## Author & Development

**Nish (d3zathon)** is the project author and maintainer.

APIAT is an independent cybersecurity research and engineering project. Development has included AI-assisted implementation, debugging, code review, test design, and documentation. See [AUTHORS.md](AUTHORS.md) for transparent human/AI attribution.

The Git history, tests, issue/fix history, and repository state are the authoritative record of development.

> ⚠️ **Authorization Required**
>
> Only use APIAT against APIs, accounts, and systems that you own or are explicitly authorized to test. The `--yes-i-am-authorized` flag is an explicit authorization gate.

---

## What APIAT Tests

APIAT focuses primarily on API authorization and business-logic weaknesses, including:

- **BOLA** — Broken Object Level Authorization
- **BFLA** — Broken Function Level Authorization
- Privilege escalation
- Parameter tampering
- Mass assignment
- Business-logic and workflow abuse
- Cross-user resource access
- Role-based authorization failures

Confirmed findings can also be correlated into **attack paths**.

Example:

```text
Low-privileged identity
        │
        ▼
      BOLA
Cross-user object access
        │
        ▼
Privilege-related modification
        │
        ▼
      BFLA
Restricted functionality
```

---

## Architecture

```text
OpenAPI Specification
        │
        ▼
Endpoint Discovery
        │
        ▼
Role / Credential Configuration
        │
        ▼
Authorization Checks
        │
        ├── BOLA
        ├── BFLA
        ├── Privilege Escalation
        ├── Parameter Tampering
        └── Workflow Testing
        │
        ▼
Candidate Findings
        │
        ▼
HTTP Evidence
        │
        ▼
Verification
        │
        ▼
Confirmed Findings
        │
        ▼
Attack-Path Correlation
        │
        ▼
HTML / Markdown / JSON Reports
```

A candidate is not automatically a vulnerability. APIAT separates candidate generation from evidence-based verification.

---

# Installation

### Quick installation

```bash
git clone https://github.com/d3zathon/api-attack-path-tester.git
cd api-attack-path-tester
chmod +x setup.sh
./setup.sh
apiattack --help
```

### Manual installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
apiattack --help
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -e .
```

---

# Included Demo Lab

APIAT includes a deliberately vulnerable local Flask lab for reproducible testing.

The bundled demo lab runs on **port 8010 by default**, keeping it separate from applications commonly running on port 8000.

Run the complete demo:

```bash
make lab-scan
```

Stop the demo:

```bash
make lab-stop
```

The demo lab contains intentionally vulnerable endpoints for BOLA, BFLA, parameter tampering, privilege escalation, and business-logic testing.

**Do not expose the demo lab to an untrusted network.**

---

# Testing an Authorized API

APIAT is OpenAPI-driven. The specification defines the available endpoints and operations; the role configuration defines identities, ownership, privilege boundaries, and other testing context.

Typical workflow:

```text
1. Obtain OpenAPI specification
2. Prepare authorized test identities
3. Configure resource ownership / role expectations
4. Inspect the specification
5. Run the scan
6. Review evidence and verification notes
7. Review confirmed findings and attack paths
```

## Inspect the API specification

```bash
apiattack inspect-spec --spec openapi.yaml
```

## Run an authorized scan

```bash
apiattack scan \
  --spec openapi.yaml \
  --config roles.yaml \
  --out ./report \
  --yes-i-am-authorized
```

---

# Role Configuration

A simplified configuration looks like:

```yaml
base_url: "https://api.example.com"

roles:
  - name: user_a
    privilege_rank: 0
    auth_header:
      Authorization: "Bearer <USER_A_TEST_TOKEN>"
    owned_resources:
      order_id: ["1001"]

  - name: user_b
    privilege_rank: 0
    auth_header:
      Authorization: "Bearer <USER_B_TEST_TOKEN>"
    owned_resources:
      order_id: ["1002"]

  - name: admin
    privilege_rank: 9
    auth_header:
      Authorization: "Bearer <ADMIN_TEST_TOKEN>"
```

Resource ownership is especially important for BOLA testing.

```text
User A owns object 1001
User B owns object 1002

User A → 1001    ALLOWED
User A → 1002    SHOULD BE BLOCKED
```

APIAT uses parameter and endpoint context to avoid treating the same numeric ID as a global identifier across unrelated resource types.

Never commit real credentials, tokens, cookies, or production secrets.

---

# BOLA Verification

A strong BOLA test compares access by two different authenticated principals to the same concrete object.

Conceptually:

```text
Owner request
    │
    ├── HTTP 2xx → object is accessible
    │
    ▼
Cross-role request
    │
    ├── HTTP 401/403 → authorization boundary blocked access
    ├── HTTP 404/422 → resource/probe problem; not automatically BOLA
    └── HTTP 2xx → potential cross-user access
                     │
                     ▼
                 Verification
                     │
                     ▼
             Confirmed BOLA
```

This distinction is intentional: a `404`, `401`, or `403` should not be promoted to a vulnerability merely because the endpoint was selected as a candidate.

---

# Reports

APIAT writes structured results to the configured output directory:

```bash
--out ./report
```

Supported report formats include:

- JSON
- Markdown
- HTML

Reports include findings, verification status, evidence, affected endpoints, tested roles, and attack paths.

---

# Demo Lab vs. Your Own API

The repository contains two separate workflows:

```text
Bundled VulnAPI demo  → localhost:8010
Your own authorized API → whatever target URL you configure
```

This separation prevents the demo lab from accidentally sending `/login` requests or scan traffic to another application already using port 8000.

---

# Troubleshooting

### `apiattack: command not found`

Activate the virtual environment and reinstall:

```bash
source .venv/bin/activate
pip install -e .
```

### Demo lab reports a login/route error

Make sure the demo lab is using its dedicated port and that no stale lab process is running:

```bash
make lab-stop
rm -f .lab.pid lab.log
make lab-scan
```

### Scan produces many candidates but no confirmed findings

Inspect the HTTP evidence and verification notes. In particular, distinguish:

```text
401 → authentication problem
403 → authorization blocked
404 → resource/fixture mismatch or wrong identifier
422 → invalid request / probe construction problem
2xx → successful application response requiring verification
```

### Credentials or IDs appear inconsistent

For deterministic lab fixtures, restart/reset the lab environment rather than modifying APIAT to ignore incorrect target state.

---

# Development

The repository contains tests and a deliberately vulnerable local lab so authorization behavior can be reproduced during development.

When extending a check, preserve this model:

```text
Candidate
   ↓
Evidence
   ↓
Verification
   ↓
Confirmed finding
```

False positives are a design concern: HTTP status codes alone are not sufficient proof of every vulnerability class.

---

# Security Disclaimer

APIAT is intended for authorized security testing and controlled research environments only.

Do not scan third-party systems without explicit permission.

The included laboratory applications are deliberately vulnerable and should remain isolated from untrusted networks.

---

# Author

**Nish (d3zathon)**

API Attack-Path Tester is independently developed and maintained by Nish.

For transparent human/AI development attribution, see [AUTHORS.md](AUTHORS.md).

---

# License

See the repository license file for the applicable terms.
