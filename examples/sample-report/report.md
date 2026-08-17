# API Attack-Path & Authorization Test Report

**Target:** `http://localhost:8000`
**Roles tested:** attacker_low_priv, victim_user, admin
**Endpoints discovered / in scope:** 13 / 13
**Candidate findings before verification:** 13
**Confirmed findings:** 13 / 13 total flagged

---

## Executive Summary

This report covers automated authorization-focused testing of the target API, including
Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA),
privilege escalation via mass assignment, parameter tampering, and business-logic/workflow
abuse. Every finding below went through an explicit verification pass; findings that could
not be independently reproduced or corroborated are labeled **unverified** rather than
discarded silently, so nothing is hidden but nothing is overstated either.

## Attack Paths

### Cross-account recon feeding a privilege/function abuse (victim_user)  `[HIGH]`

**Starting role:** victim_user
**Impact:** Unauthorized read access to other users' data can be combined with a separate authorization weakness to broaden impact beyond simple data disclosure.

1. Read another principal's data without authorization via GET /users/{user_id}. _(finding F-897cba07)_
2. Read another principal's data without authorization via GET /orders/{order_id}. _(finding F-712eee5c)_
3. Leverage information/context from the prior step to abuse GET /admin/reports. _(finding F-35f9c23a)_

### Self-service privilege escalation to restricted functionality (attacker_low_priv)  `[CRITICAL]`

**Starting role:** attacker_low_priv
**Impact:** An authenticated low-privilege user can grant themselves elevated privileges and then directly exercise administrative or restricted functionality.

1. Escalate privileges as 'attacker_low_priv' via PUT /users/{user_id}/profile. _(finding F-3e3e4cde)_
2. Using the elevated context, reach restricted function GET /admin/reports (originally out of scope for 'attacker_low_priv'). _(finding F-b448df85)_

### Cross-account recon feeding a privilege/function abuse (attacker_low_priv)  `[HIGH]`

**Starting role:** attacker_low_priv
**Impact:** Unauthorized read access to other users' data can be combined with a separate authorization weakness to broaden impact beyond simple data disclosure.

1. Read another principal's data without authorization via GET /users/{user_id}. _(finding F-75298985)_
2. Read another principal's data without authorization via GET /orders/{order_id}. _(finding F-ff2ab737)_
3. Leverage information/context from the prior step to abuse PUT /users/{user_id}/profile. _(finding F-3e3e4cde)_
4. Leverage information/context from the prior step to abuse GET /admin/reports. _(finding F-b448df85)_


## Findings

### [CRITICAL] Possible privilege escalation via mass assignment on PUT /users/{user_id}/profile

- **ID:** `F-3e3e4cde`
- **Class:** Privilege Escalation (API5:2023 / API3:2023, CWE-269)
- **Endpoint:** `PUT /users/{user_id}/profile`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified-high-confidence`

**Description**

Role 'attacker_low_priv' was able to set the privileged field 'role' to an elevated value via PUT /users/{user_id}/profile (status 200). A subsequent call to the restricted endpoint GET /admin/users then succeeded, directly confirming an elevated capability was gained.

**Verification notes**
- Escalation was confirmed by directly observing a subsequent restricted-endpoint call succeed after the privilege field was set.

**Remediation**

Use an explicit allow-list of client-settable fields on every write endpoint (avoid blind '**request_body') and never allow role/permission fields to be set through user-facing self-service endpoints. Privilege changes should go through a separate, tightly-authorized admin flow.

<details>
<summary>Evidence (2 request/response pair(s))</summary>

```
[1] Privilege escalation probe: role 'attacker_low_priv' sets 'role' -> 'admin' on PUT /users/{user_id}/profile
PUT http://localhost:8000/users/2/profile
Status: 200  (3.76 ms)
Request body: {'role': 'admin'}
Response excerpt:
{"balance":10,"email":"attacker@example.com","id":2,"role":"admin"}

```
```
[2] Post-escalation capability check: 'attacker_low_priv' retries restricted GET /admin/users
GET http://localhost:8000/admin/users
Status: 200  (2.74 ms)
Request body: None
Response excerpt:
[{"balance":50,"email":"victim@example.com","id":1,"role":"user"},{"balance":10,"email":"attacker@example.com","id":2,"role":"admin"},{"balance":0,"email":"admin@example.com","id":3,"role":"admin"}]

```

</details>

---
### [HIGH] Possible BOLA/IDOR on GET /users/{user_id}

- **ID:** `F-897cba07`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `GET /users/{user_id}`
- **Actor role:** victim_user | **Victim role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified-high-confidence`

**Description**

Role 'victim_user' received a 200 response when requesting resource '2' (user_id) owned by role 'attacker_low_priv'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Response body contained an identity marker belonging to the victim role, directly confirming cross-account data disclosure.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: attacker_low_priv accesses own resource 2
GET http://localhost:8000/users/2
Status: 200  (3.29 ms)
Request body: None
Response excerpt:
{"balance":10,"email":"attacker@example.com","id":2,"role":"user"}

```
```
[2] BOLA probe: victim_user attempts attacker_low_priv's resource 2
GET http://localhost:8000/users/2
Status: 200  (2.8 ms)
Request body: None
Response excerpt:
{"balance":10,"email":"attacker@example.com","id":2,"role":"user"}

```
```
[3] Verification re-check for F-897cba07
GET http://localhost:8000/users/2
Status: 200  (2.73 ms)
Request body: None
Response excerpt:
{"balance":999999,"email":"attacker@example.com","id":2,"role":"admin"}

```

</details>

---
### [HIGH] Possible BOLA/IDOR on GET /users/{user_id}

- **ID:** `F-75298985`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `GET /users/{user_id}`
- **Actor role:** attacker_low_priv | **Victim role:** victim_user
- **Status:** CONFIRMED — confidence: `verified-high-confidence`

**Description**

Role 'attacker_low_priv' received a 200 response when requesting resource '1' (user_id) owned by role 'victim_user'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Response body contained an identity marker belonging to the victim role, directly confirming cross-account data disclosure.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: victim_user accesses own resource 1
GET http://localhost:8000/users/1
Status: 200  (2.61 ms)
Request body: None
Response excerpt:
{"balance":50,"email":"victim@example.com","id":1,"role":"user"}

```
```
[2] BOLA probe: attacker_low_priv attempts victim_user's resource 1
GET http://localhost:8000/users/1
Status: 200  (2.66 ms)
Request body: None
Response excerpt:
{"balance":50,"email":"victim@example.com","id":1,"role":"user"}

```
```
[3] Verification re-check for F-75298985
GET http://localhost:8000/users/1
Status: 200  (2.86 ms)
Request body: None
Response excerpt:
{"balance":50,"email":"victim@example.com","id":1,"role":"user"}

```

</details>

---
### [HIGH] Possible BOLA/IDOR on GET /orders/{order_id}

- **ID:** `F-712eee5c`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `GET /orders/{order_id}`
- **Actor role:** victim_user | **Victim role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Role 'victim_user' received a 200 response when requesting resource 'ord_2' (order_id) owned by role 'attacker_low_priv'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Result reproduced consistently and the response body was non-empty and non-error-shaped; no explicit victim identity marker configured to confirm content further.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: attacker_low_priv accesses own resource ord_2
GET http://localhost:8000/orders/ord_2
Status: 200  (2.61 ms)
Request body: None
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":80,"status":"placed"}

```
```
[2] BOLA probe: victim_user attempts attacker_low_priv's resource ord_2
GET http://localhost:8000/orders/ord_2
Status: 200  (2.57 ms)
Request body: None
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":80,"status":"placed"}

```
```
[3] Verification re-check for F-712eee5c
GET http://localhost:8000/orders/ord_2
Status: 200  (3.0 ms)
Request body: None
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":0.01,"status":"approved"}

```

</details>

---
### [HIGH] Possible BOLA/IDOR on GET /orders/{order_id}

- **ID:** `F-ff2ab737`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `GET /orders/{order_id}`
- **Actor role:** attacker_low_priv | **Victim role:** victim_user
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Role 'attacker_low_priv' received a 200 response when requesting resource 'ord_1' (order_id) owned by role 'victim_user'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Result reproduced consistently and the response body was non-empty and non-error-shaped; no explicit victim identity marker configured to confirm content further.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: victim_user accesses own resource ord_1
GET http://localhost:8000/orders/ord_1
Status: 200  (2.56 ms)
Request body: None
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1200,"status":"placed"}

```
```
[2] BOLA probe: attacker_low_priv attempts victim_user's resource ord_1
GET http://localhost:8000/orders/ord_1
Status: 200  (2.44 ms)
Request body: None
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1200,"status":"placed"}

```
```
[3] Verification re-check for F-ff2ab737
GET http://localhost:8000/orders/ord_1
Status: 200  (2.68 ms)
Request body: None
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1,"status":"probe-value"}

```

</details>

---
### [HIGH] Possible BOLA/IDOR on PATCH /orders/{order_id}

- **ID:** `F-3279ecfb`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `PATCH /orders/{order_id}`
- **Actor role:** victim_user | **Victim role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Role 'victim_user' received a 200 response when requesting resource 'ord_2' (order_id) owned by role 'attacker_low_priv'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Result reproduced consistently and the response body was non-empty and non-error-shaped; no explicit victim identity marker configured to confirm content further.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: attacker_low_priv accesses own resource ord_2
PATCH http://localhost:8000/orders/ord_2
Status: 200  (2.84 ms)
Request body: None
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":80,"status":"placed"}

```
```
[2] BOLA probe: victim_user attempts attacker_low_priv's resource ord_2
PATCH http://localhost:8000/orders/ord_2
Status: 200  (2.8 ms)
Request body: {'status': 'probe-value', 'price': 1}
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":1,"status":"probe-value"}

```
```
[3] Verification re-check for F-3279ecfb
PATCH http://localhost:8000/orders/ord_2
Status: 200  (2.78 ms)
Request body: None
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":0.01,"status":"approved"}

```

</details>

---
### [HIGH] Possible BOLA/IDOR on PATCH /orders/{order_id}

- **ID:** `F-836759c9`
- **Class:** BOLA/IDOR (API1:2023, CWE-639)
- **Endpoint:** `PATCH /orders/{order_id}`
- **Actor role:** attacker_low_priv | **Victim role:** victim_user
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Role 'attacker_low_priv' received a 200 response when requesting resource 'ord_1' (order_id) owned by role 'victim_user'. Baseline owner access also succeeded (200), suggesting the endpoint may not enforce object-level ownership checks.

**Verification notes**
- Result reproduced consistently and the response body was non-empty and non-error-shaped; no explicit victim identity marker configured to confirm content further.

**Remediation**

Enforce object-level authorization on every access to this resource: verify the authenticated principal is the owner (or explicitly authorized) before returning or mutating data, server-side, on every request - never trust the client-supplied identifier alone.

<details>
<summary>Evidence (3 request/response pair(s))</summary>

```
[1] Baseline: victim_user accesses own resource ord_1
PATCH http://localhost:8000/orders/ord_1
Status: 200  (2.71 ms)
Request body: None
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1200,"status":"placed"}

```
```
[2] BOLA probe: attacker_low_priv attempts victim_user's resource ord_1
PATCH http://localhost:8000/orders/ord_1
Status: 200  (2.91 ms)
Request body: {'status': 'probe-value', 'price': 1}
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1,"status":"probe-value"}

```
```
[3] Verification re-check for F-836759c9
PATCH http://localhost:8000/orders/ord_1
Status: 200  (2.62 ms)
Request body: None
Response excerpt:
{"id":"ord_1","item":"Laptop","owner_id":1,"price":1,"status":"probe-value"}

```

</details>

---
### [HIGH] Possible broken function-level authorization on GET /admin/reports

- **ID:** `F-b448df85`
- **Class:** BFLA (API5:2023, CWE-862)
- **Endpoint:** `GET /admin/reports`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Endpoint GET /admin/reports is declared as restricted to role(s) ['admin'], but role 'attacker_low_priv' received a 200 response when calling it directly.

**Verification notes**
- Restricted endpoint reproducibly returned a success status to an unauthorized role, with a response body that does not read as an error.

**Remediation**

Add a server-side function-level authorization check on this endpoint (e.g. role/permission middleware) rather than relying on hiding the operation from lower-privileged clients in documentation or UI only.

<details>
<summary>Evidence (2 request/response pair(s))</summary>

```
[1] BFLA probe: unauthorized role 'attacker_low_priv' calls restricted GET /admin/reports
GET http://localhost:8000/admin/reports
Status: 200  (2.52 ms)
Request body: None
Response excerpt:
{"generated_for":"attacker@example.com","report":"quarterly revenue","total_revenue":184300}

```
```
[2] Verification re-check for F-b448df85
GET http://localhost:8000/admin/reports
Status: 200  (3.09 ms)
Request body: None
Response excerpt:
{"generated_for":"attacker@example.com","report":"quarterly revenue","total_revenue":184300}

```

</details>

---
### [HIGH] Possible broken function-level authorization on GET /admin/reports

- **ID:** `F-35f9c23a`
- **Class:** BFLA (API5:2023, CWE-862)
- **Endpoint:** `GET /admin/reports`
- **Actor role:** victim_user
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Endpoint GET /admin/reports is declared as restricted to role(s) ['admin'], but role 'victim_user' received a 200 response when calling it directly.

**Verification notes**
- Restricted endpoint reproducibly returned a success status to an unauthorized role, with a response body that does not read as an error.

**Remediation**

Add a server-side function-level authorization check on this endpoint (e.g. role/permission middleware) rather than relying on hiding the operation from lower-privileged clients in documentation or UI only.

<details>
<summary>Evidence (2 request/response pair(s))</summary>

```
[1] BFLA probe: unauthorized role 'victim_user' calls restricted GET /admin/reports
GET http://localhost:8000/admin/reports
Status: 200  (2.54 ms)
Request body: None
Response excerpt:
{"generated_for":"victim@example.com","report":"quarterly revenue","total_revenue":184300}

```
```
[2] Verification re-check for F-35f9c23a
GET http://localhost:8000/admin/reports
Status: 200  (4.05 ms)
Request body: None
Response excerpt:
{"generated_for":"victim@example.com","report":"quarterly revenue","total_revenue":184300}

```

</details>

---
### [HIGH] Workflow step skip accepted: 'pay' in 'checkout'

- **ID:** `F-99190406`
- **Class:** Business Logic Flaw (API6:2023, CWE-841)
- **Endpoint:** `checkout`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

The workflow 'checkout' completed successfully (final status 200) even though the 'pay' step was never performed. This suggests the server does not enforce workflow state/ordering and relies on the client to call steps in the correct sequence.

**Verification notes**
- Confirmed by directly executing the abusive workflow sequence and observing it complete successfully.

**Remediation**

Track workflow/order state server-side (e.g. a state machine) and reject any step whose preconditions were not met, instead of trusting the client to call endpoints in the intended order.

<details>
<summary>Evidence (2 request/response pair(s))</summary>

```
[1] Workflow 'create_cart' step as role 'attacker_low_priv'
POST http://localhost:8000/cart
Status: 200  (2.54 ms)
Request body: {}
Response excerpt:
{"cart_id":"1"}

```
```
[2] Workflow 'checkout' step as role 'attacker_low_priv'
POST http://localhost:8000/cart/1/checkout
Status: 200  (2.66 ms)
Request body: {}
Response excerpt:
{"cart_id":"1","paid_at_checkout":false,"status":"order placed"}

```

</details>

---
### [MEDIUM] Possible parameter tampering on PUT /users/{user_id}/profile (fields: balance)

- **ID:** `F-0de9c2db`
- **Class:** Parameter Tampering (API6:2023, CWE-20)
- **Endpoint:** `PUT /users/{user_id}/profile`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Submitting attacker-favorable values for ['balance'] as low-privilege role 'attacker_low_priv' returned 200, suggesting the server may not be re-validating these fields server-side.

**Verification notes**
- The tampered value was echoed back in the response, indicating the server accepted and likely persisted the client-supplied value.

**Remediation**

Never trust client-supplied values for fields that affect price, balance, ownership, or approval status. Recompute or re-validate these fields server-side from trusted state, and use allow-lists for which fields a given role may set on a resource.

<details>
<summary>Evidence (1 request/response pair(s))</summary>

```
[1] Parameter tampering probe: role 'attacker_low_priv' submits out-of-policy values for ['balance'] on PUT /users/{user_id}/profile
PUT http://localhost:8000/users/2/profile
Status: 200  (2.76 ms)
Request body: {'balance': 999999}
Response excerpt:
{"balance":999999,"email":"attacker@example.com","id":2,"role":"admin"}

```

</details>

---
### [MEDIUM] Possible parameter tampering on PATCH /orders/{order_id} (fields: price, status)

- **ID:** `F-6fd391d9`
- **Class:** Parameter Tampering (API6:2023, CWE-20)
- **Endpoint:** `PATCH /orders/{order_id}`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Submitting attacker-favorable values for ['price', 'status'] as low-privilege role 'attacker_low_priv' returned 200, suggesting the server may not be re-validating these fields server-side.

**Verification notes**
- The tampered value was echoed back in the response, indicating the server accepted and likely persisted the client-supplied value.

**Remediation**

Never trust client-supplied values for fields that affect price, balance, ownership, or approval status. Recompute or re-validate these fields server-side from trusted state, and use allow-lists for which fields a given role may set on a resource.

<details>
<summary>Evidence (1 request/response pair(s))</summary>

```
[1] Parameter tampering probe: role 'attacker_low_priv' submits out-of-policy values for ['price', 'status'] on PATCH /orders/{order_id}
PATCH http://localhost:8000/orders/ord_2
Status: 200  (2.83 ms)
Request body: {'price': 0.01, 'status': 'approved'}
Response excerpt:
{"id":"ord_2","item":"Headphones","owner_id":2,"price":0.01,"status":"approved"}

```

</details>

---
### [MEDIUM] Unsafe replay accepted: 'redeem' in workflow 'coupon_redeem'

- **ID:** `F-d18c8671`
- **Class:** Business Logic Flaw (API6:2023, CWE-841)
- **Endpoint:** `redeem`
- **Actor role:** attacker_low_priv
- **Status:** CONFIRMED — confidence: `verified`

**Description**

Step 'redeem' in workflow 'coupon_redeem' succeeded when called twice in a row with identical input (status 200, then 200), suggesting missing idempotency/state checks (e.g. a coupon or one-time action being usable more than once).

**Verification notes**
- Confirmed by directly executing the abusive workflow sequence and observing it complete successfully.

**Remediation**

Enforce idempotency or single-use constraints server-side (e.g. mark coupons/actions as consumed, use idempotency keys, or check current state before allowing the action to repeat).

<details>
<summary>Evidence (2 request/response pair(s))</summary>

```
[1] Workflow 'redeem' step as role 'attacker_low_priv'
POST http://localhost:8000/coupons/apply
Status: 200  (2.84 ms)
Request body: {'code': 'WELCOME10'}
Response excerpt:
{"applied_count":1,"code":"WELCOME10","discount_applied":true}

```
```
[2] Workflow 'redeem' step as role 'attacker_low_priv'
POST http://localhost:8000/coupons/apply
Status: 200  (2.64 ms)
Request body: {'code': 'WELCOME10'}
Response excerpt:
{"applied_count":2,"code":"WELCOME10","discount_applied":true}

```

</details>

---

## Methodology

1. **Discovery** — parse the provided OpenAPI spec into a normalized endpoint inventory.
2. **Probing** — for each check class (BOLA, BFLA, privilege escalation, parameter
   tampering, business logic), issue cross-role requests designed to surface authorization
   boundary violations, capturing full request/response evidence for every call.
3. **Verification** — re-test candidates for reproducibility, inspect response content
   (not just status codes) for genuine evidence of unauthorized access/mutation, and drop
   or downgrade anything that doesn't hold up.
4. **Attack-path correlation** — chain confirmed findings that compound into greater impact
   (e.g. self-escalation followed by restricted-function access).
5. **Reporting** — this document.

_This tool is intended for use only against systems you are explicitly authorized to test._