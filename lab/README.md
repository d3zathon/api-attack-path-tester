# VulnAPI Lab

A tiny, deliberately vulnerable Flask API used to exercise the API Attack-Path &
Authorization Tester end-to-end, and as a safe target to demo/screenshot the tool for
a portfolio. **Do not deploy this outside a local/isolated environment.**

## Seeded identities

| Email | Password | Role | User ID |
|---|---|---|---|
| victim@example.com | victim-pass | user | 1 |
| attacker@example.com | attacker-pass | user | 2 |
| admin@example.com | admin-pass | admin | 3 |

Get a token: `POST /login {"username": "...", "password": "..."}` → `{"token": "..."}`.
Use it as `Authorization: Bearer <token>`.

## Intentional vulnerabilities

| Endpoint | Method | Class | Bug |
|---|---|---|---|
| `/users/{id}` | GET | BOLA/IDOR | No ownership check; any authenticated user can read any profile. |
| `/users/{id}/profile` | PUT | Privilege escalation (mass assignment) | Accepts and blindly applies a `role` field from the request body. |
| `/admin/reports` | GET | BFLA | Admin-only report endpoint with no role check at all. |
| `/orders/{id}` | GET | BOLA/IDOR | No ownership check on order lookups. |
| `/orders/{id}/cancel` | POST | BOLA/IDOR | Any authenticated user can cancel any order. |
| `/orders/{id}` | PATCH | Parameter tampering | Client-supplied `status`/`price` applied with no validation. |
| `/cart/{id}/checkout` | POST | Business logic | Checkout succeeds without verifying payment was made. |
| `/coupons/apply` | POST | Business logic | Coupons can be applied an unlimited number of times. |

Two **safe control endpoints** are included on purpose (`GET /users/{id}/secure`,
`GET /admin/users`) so you can confirm the tool doesn't flag correctly-authorized code -
this is the difference between a scanner that verifies findings and one that just spams
status codes.

## Running

```bash
pip install -r requirements.txt
python app.py
# -> listening on http://localhost:8000
```

Or via Docker (see the top-level `docker-compose.yml`, service `lab`):

```bash
docker compose up lab
```
