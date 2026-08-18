# API Attack-Path Tester

**API Attack-Path Tester (APIAT)** is an authorization-focused API security testing tool designed to identify, verify, and correlate API authorization and business-logic vulnerabilities.

Instead of simply flagging suspicious HTTP responses, APIAT uses **role-based testing, ownership information, response verification, and attack-path correlation** to produce evidence-backed findings.

> ⚠️ **Authorization Required**
>
> Only use APIAT against APIs, accounts, and systems that you own or have explicit permission to test. The tool includes an explicit authorization flag and is designed for authorized security testing.

---

## What Can APIAT Test?

APIAT focuses primarily on authorization and API business-logic weaknesses, including:

* **BOLA** — Broken Object Level Authorization
* **BFLA** — Broken Function Level Authorization
* **Privilege Escalation**
* **Parameter Tampering**
* **Mass Assignment**
* **Business Logic / Workflow Abuse**
* Cross-user resource access
* Unauthorized function access
* Role-based authorization failures

The tool can also correlate confirmed findings into potential **attack paths**.

For example:

```text
Low-privileged User
        │
        ▼
BOLA
Access another user's resource
        │
        ▼
Privilege Escalation
Modify a restricted property
        │
        ▼
BFLA
Access administrative functionality
```

---

# How APIAT Works

The general workflow is:

```text
OpenAPI Specification
        │
        ▼
Endpoint Discovery
        │
        ▼
Role & Credential Configuration
        │
        ▼
Authorization Testing
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
Verification
        │
        ▼
Confirmed Findings
        │
        ▼
Attack-Path Correlation
        │
        ▼
Security Report
```

APIAT is **OpenAPI-driven**. The OpenAPI specification tells the tool what endpoints and operations exist, while the role configuration tells it who is authorized to access those operations and which resources belong to which test identities.

---

# Requirements

Before using APIAT, make sure you have:

* Python 3.x
* Git
* An OpenAPI 3.x specification for the API you want to test
* Authorized test accounts or API tokens
* Permission to perform security testing against the target API

You should ideally have separate test identities such as:

```text
User
Manager
Admin
```

Do **not** use production credentials unless you have explicit authorization and understand the potential impact.

---

# Installation

APIAT provides a setup script to simplify installation and configuration.

## Quick Installation

Clone the repository:

```bash
git clone https://github.com/d3zathon/api-attack-path-tester.git
cd api-attack-path-tester
```

Make the setup script executable:

```bash
chmod +x setup.sh
```

Run the setup script:

```bash
./setup.sh
```

The setup script handles the required project installation and environment setup.

After installation, verify that APIAT is available:

```bash
apiattack --help
```

If the command is available, the installation was successful.

---

## If `setup.sh` Doesn't Run

If you receive:

```text
Permission denied
```

run:

```bash
chmod +x setup.sh
```

and then:

```bash
./setup.sh
```

If you receive:

```text
No such file or directory
```

make sure you are running the command from the project root:

```bash
cd api-attack-path-tester
ls
```

You should see the project files, including:

```text
setup.sh
```

Then run:

```bash
./setup.sh
```

---

## Manual Installation

If you prefer not to use the setup script, you can install APIAT manually.

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

### Linux / macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\Activate.ps1
```

Install APIAT:

```bash
pip install -e .
```

Verify:

```bash
apiattack --help
```

---

## Recommended Installation

For most users, use:

```bash
git clone https://github.com/d3zathon/api-attack-path-tester.git
cd api-attack-path-tester
chmod +x setup.sh
./setup.sh
apiattack --help
```

Once `apiattack --help` works, continue to the **Quick Start** or **Testing Your Own API** section.

# Quick Start: Test the Included Lab

APIAT includes a deliberately vulnerable API lab that you can use without connecting to an external API.

Start the lab according to the repository's lab instructions, then run:

```bash
make lab-scan
```

The lab contains intentionally vulnerable endpoints designed to demonstrate APIAT's testing and verification capabilities.

Use the lab first if you are learning how the tool works.

---

# Testing Your Own API

APIAT can also test an external API that you are authorized to assess.

The recommended workflow is:

```text
1. Obtain OpenAPI specification
2. Identify authorized test accounts
3. Create role configuration
4. Inspect the specification
5. Run the scan
6. Review findings
7. Review attack paths
```

---

# 1. Obtain an OpenAPI Specification

APIAT expects an **OpenAPI 3.x** specification.

You may have a file such as:

```text
openapi.yaml
```

or:

```text
openapi.json
```

For example:

```yaml
openapi: 3.0.0

info:
  title: Example API
  version: 1.0.0

servers:
  - url: https://api.example.com

paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: Successful response
```

You can also use an OpenAPI specification hosted by your own application.

For example:

```text
https://api.example.com/openapi.json
```

Download it locally if necessary:

```bash
curl -o openapi.json https://api.example.com/openapi.json
```

Then use:

```text
openapi.json
```

with APIAT.

> APIAT is not currently intended to be a general-purpose API crawler. It relies on an OpenAPI specification to understand the API's available endpoints and operations.

---

# 2. Create the Role Configuration

Generate a configuration template:

```bash
apiattack init-config --out roles.yaml
```

Open the configuration:

```bash
nano roles.yaml
```

The configuration describes the authorized test identities and authorization model.

A simplified example:

```yaml
base_url: "https://api.example.com"

roles:

  user:
    token: "${USER_TOKEN}"

  manager:
    token: "${MANAGER_TOKEN}"

  admin:
    token: "${ADMIN_TOKEN}"
```

Your actual configuration may contain additional information such as:

* Owned resources
* Privilege levels
* Endpoint-role requirements
* Identity markers
* Workflow definitions

---

# 3. Configure Resource Ownership

Ownership information is especially important for testing **BOLA**.

For example:

```text
User A → resource 1001
User B → resource 1002
```

The security expectation is:

```text
User A → resource 1001    ✅
User A → resource 1002    ❌
```

Your configuration can describe these ownership relationships.

Conceptually:

```yaml
roles:

  user_a:
    token: "${USER_A_TOKEN}"

    owned_resources:
      id:
        - "1001"

  user_b:
    token: "${USER_B_TOKEN}"

    owned_resources:
      id:
        - "1002"
```

This allows APIAT to test whether one identity can access another identity's resources.

---

# 4. Define Endpoint Authorization

For BFLA and privilege-related testing, APIAT needs to understand which roles should have access to specific operations.

For example:

```yaml
endpoint_role_requirements:

  "GET /users/{id}":
    - user
    - manager
    - admin

  "DELETE /users/{id}":
    - admin

  "POST /admin/users":
    - admin
```

This creates an expected authorization model:

```text
User
 ├── GET /users/{id}       ALLOWED
 ├── DELETE /users/{id}    DENIED
 └── POST /admin/users     DENIED

Admin
 ├── GET /users/{id}       ALLOWED
 ├── DELETE /users/{id}    ALLOWED
 └── POST /admin/users     ALLOWED
```

APIAT can then test whether the actual API behavior matches the expected authorization policy.

---

# 5. Use Environment Variables for Credentials

Avoid hardcoding sensitive tokens into configuration files whenever possible.

For example:

```bash
export USER_TOKEN="your-user-test-token"
export MANAGER_TOKEN="your-manager-test-token"
export ADMIN_TOKEN="your-admin-test-token"
```

Then reference them from your configuration:

```yaml
roles:

  user:
    token: "${USER_TOKEN}"

  manager:
    token: "${MANAGER_TOKEN}"

  admin:
    token: "${ADMIN_TOKEN}"
```

Never commit real credentials to Git.

Add sensitive configuration files to `.gitignore` if necessary:

```gitignore
roles.yaml
.env
*.token
```

---

# 6. Inspect the OpenAPI Specification

Before running a scan, inspect the specification:

```bash
apiattack inspect-spec --spec openapi.yaml
```

This allows you to verify that APIAT is seeing the endpoints you expect.

For example:

```text
GET    /users/{id}
PATCH  /users/{id}
DELETE /users/{id}

GET    /orders/{id}
POST   /orders

POST   /admin/users
```

If the endpoints are not represented correctly in the OpenAPI specification, fix the specification before testing.

---

# 7. Run an Authorized Scan

Once the API specification and role configuration are ready:

```bash
apiattack scan \
  --spec openapi.yaml \
  --config roles.yaml \
  --out ./report \
  --yes-i-am-authorized
```

The `--yes-i-am-authorized` flag is an explicit authorization gate.

APIAT should only be used when you have permission to test the target.

---

# 8. What Happens During a Scan?

APIAT performs several stages.

### Endpoint discovery

The tool parses the OpenAPI specification and builds an inventory of API operations.

### Role-based testing

The tool uses the configured identities to test authorization boundaries.

### Vulnerability checks

Depending on the configuration and available endpoints, APIAT can test for issues such as:

```text
BOLA
BFLA
Privilege Escalation
Parameter Tampering
Mass Assignment
Workflow Abuse
```

### Verification

A suspicious response is not automatically treated as a confirmed vulnerability.

APIAT attempts to verify the finding using additional evidence.

Conceptually:

```text
Suspicious behavior
        │
        ▼
Re-test
        │
        ▼
Inspect response
        │
        ▼
Check identity/resource evidence
        │
        ▼
Verify impact
        │
        ▼
Confirmed finding
```

This separation helps reduce false positives.

---

# 9. Understanding BOLA Testing

Suppose:

```text
User A owns object 1001
User B owns object 1002
```

The legitimate request is:

```http
GET /users/1001
Authorization: Bearer USER_A_TOKEN
```

APIAT can test whether the same identity can access:

```http
GET /users/1002
Authorization: Bearer USER_A_TOKEN
```

If User A receives User B's protected information, the tool has evidence of a potential **Broken Object Level Authorization** vulnerability.

The important distinction is:

```text
HTTP 200
```

does not automatically mean:

```text
BOLA confirmed
```

The tool needs evidence that the returned object belongs to another identity or violates the configured authorization model.

---

# 10. Understanding BFLA Testing

BFLA occurs when a lower-privileged role can execute functionality intended for a higher-privileged role.

For example:

```text
User:
    GET /profile          ✅
    DELETE /users/{id}    ❌

Admin:
    GET /profile          ✅
    DELETE /users/{id}    ✅
```

APIAT can test whether the actual API enforces those boundaries.

If:

```text
User → DELETE /users/1002
```

succeeds despite the configured policy requiring an administrator, APIAT can report the behavior for verification.

---

# 11. Understanding Privilege Escalation

Consider an API that allows users to update their profile:

```http
PATCH /users/1001
```

A legitimate request might contain:

```json
{
  "name": "Alice"
}
```

A vulnerable implementation might also accept:

```json
{
  "name": "Alice",
  "role": "admin"
}
```

APIAT can test for this class of behavior where the API and configuration provide enough information to verify the resulting capability.

The important part is that simply changing:

```text
role = admin
```

is not sufficient evidence.

A stronger verification is:

```text
Attempt modification
       ↓
Check resulting state/capability
       ↓
Attempt privileged operation
       ↓
Determine whether privilege actually changed
```

---

# 12. Testing Business Logic

Some API vulnerabilities cannot be detected from individual requests.

For example, imagine:

```text
1. Create order
2. Pay for order
3. Confirm order
4. Ship order
```

The API may expose:

```text
POST /orders
POST /orders/{id}/pay
POST /orders/{id}/confirm
POST /orders/{id}/ship
```

If the API allows:

```text
POST /orders/123/ship
```

without completing payment, that may represent a business-logic flaw.

APIAT supports workflow-oriented testing for these scenarios.

A workflow can describe the expected sequence:

```text
Create
  ↓
Pay
  ↓
Confirm
  ↓
Ship
```

The tester can then investigate whether steps can be skipped or replayed in an unexpected way.

---

# 13. Understanding Attack Paths

Individual vulnerabilities don't always tell the complete story.

For example:

```text
Finding 1
BOLA
   ↓
Access another user's resource

Finding 2
Mass Assignment
   ↓
Modify a privileged property

Finding 3
BFLA
   ↓
Access administrative functionality
```

APIAT can correlate confirmed findings into an attack-path narrative:

```text
Low-privileged identity
        ↓
Unauthorized object access
        ↓
Privilege-related modification
        ↓
Administrative capability
```

This helps security teams understand **how vulnerabilities can combine**, rather than viewing every finding in isolation.

---

# 14. Reports

Specify an output directory:

```bash
--out ./report
```

For example:

```bash
apiattack scan \
  --spec openapi.yaml \
  --config roles.yaml \
  --out ./report \
  --yes-i-am-authorized
```

The generated reports can be used to review:

* Vulnerability findings
* Verification status
* Evidence
* Requests/responses
* Affected endpoints
* Roles
* Attack paths

APIAT supports structured output formats such as JSON, Markdown, and HTML.

---

# External API Example

A complete external API workflow might look like:

```bash
# Clone the project
git clone https://github.com/d3zathon/api-attack-path-tester.git

cd api-attack-path-tester

# Create environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .

# Create configuration
apiattack init-config --out roles.yaml

# Inspect API specification
apiattack inspect-spec --spec openapi.yaml

# Run authorized security test
apiattack scan \
  --spec openapi.yaml \
  --config roles.yaml \
  --out ./report \
  --yes-i-am-authorized
```

---

# Example Project Layout

A practical setup could look like:

```text
my-api-security-test/
│
├── openapi.yaml
├── roles.yaml
├── .env
│
└── report/
    ├── report.html
    ├── report.md
    └── report.json
```

Keep credentials and other sensitive information out of source control.

---

# Troubleshooting

## APIAT command not found

Make sure the virtual environment is activated:

```bash
source .venv/bin/activate
```

Then reinstall:

```bash
pip install -e .
```

Verify:

```bash
apiattack --help
```

---

## OpenAPI specification cannot be parsed

Check that the document is valid OpenAPI 3.x YAML or JSON.

You can also inspect it using:

```bash
apiattack inspect-spec --spec openapi.yaml
```

---

## No vulnerabilities are found

A clean result does **not** necessarily mean the API is completely secure.

Check:

* Are the correct test accounts configured?
* Are ownership relationships correct?
* Are endpoint-role requirements defined?
* Are the test accounts actually different privilege levels?
* Does the OpenAPI specification accurately describe the API?
* Are workflows configured where business logic needs to be tested?

APIAT is intentionally focused on the authorization model and information available through the specification/configuration. It cannot infer every application-specific security rule automatically.

---

# Security & Authorization

APIAT is intended for:

* Your own applications
* Local development environments
* Security testing labs
* Authorized penetration tests
* Bug bounty programs where the target and testing method are explicitly permitted
* Internal security assessments

Do **not** use the tool against systems without authorization.

Because APIAT can perform state-changing operations, testing an API can potentially modify or delete data.

Use dedicated test accounts and test environments whenever possible.

---

# Limitations

APIAT is not a universal API security scanner.

It currently relies heavily on:

1. A valid OpenAPI specification
2. Correct role configuration
3. Authorized credentials
4. Accurate resource ownership information
5. Explicit authorization expectations
6. Workflow definitions for application-specific business logic

If the authorization model is incorrectly configured, the tool may produce inaccurate results.

APIAT also does not guarantee detection of every API vulnerability.

Its primary focus is **authorization testing, verification, and attack-path correlation**.

---

# Recommended Testing Environment

For learning and development, use:

```text
                    Your Computer
                         │
                         ▼
                  API Attack-Path
                      Tester
                         │
                         ▼
                 Vulnerable API
                    Test Lab
                         │
                  ┌──────┼──────┐
                  ▼      ▼      ▼
                User  Manager  Admin
```

Use dedicated test data and credentials.

This makes it possible to safely experiment with:

* BOLA
* BFLA
* Privilege escalation
* Mass assignment
* Parameter tampering
* Workflow abuse
* Attack-path correlation

---

# Why APIAT?

Traditional API testing can produce a large number of individual findings.

APIAT focuses on a narrower but important question:

> **Can a specific role perform an action or access a resource that it should not be able to access?**

The tool then attempts to verify the behavior and determine whether confirmed vulnerabilities can be chained into a meaningful attack path.

The core philosophy is:

```text
Don't just detect.
        ↓
Verify.
        ↓
Correlate.
        ↓
Explain the attack path.
```

---

# Disclaimer

API Attack-Path Tester is a security research and authorized testing tool.

The developers and contributors are not responsible for unauthorized use, damage, data loss, service disruption, or other consequences resulting from misuse of the software.

Always obtain appropriate authorization before testing an API.

---

## Project

**GitHub:** https://github.com/d3zathon/api-attack-path-tester

**Author:** d3zathon

If you find a bug or want to contribute improvements, open an issue or pull request in the repository.
