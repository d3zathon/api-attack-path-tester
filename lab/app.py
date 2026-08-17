"""VulnAPI Lab - a small, DELIBERATELY VULNERABLE Flask API used to exercise the
API Attack-Path & Authorization Tester end-to-end. Do not deploy this anywhere reachable
by untrusted users; it exists purely as a local, disposable test target.

Seeded identities (see /login):
  victim@example.com / victim-pass      -> user id 1, role "user"
  attacker@example.com / attacker-pass  -> user id 2, role "user"
  admin@example.com / admin-pass        -> user id 3, role "admin"

Each endpoint below is annotated with the vulnerability class it demonstrates (or "SAFE"
for the intentionally-correct control endpoints used to check the tool doesn't false-positive).
"""
from __future__ import annotations

import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------------------
USERS = {
    1: {"id": 1, "email": "victim@example.com", "password": "victim-pass", "role": "user", "balance": 50},
    2: {"id": 2, "email": "attacker@example.com", "password": "attacker-pass", "role": "user", "balance": 10},
    3: {"id": 3, "email": "admin@example.com", "password": "admin-pass", "role": "admin", "balance": 0},
}
TOKENS = {}  # token -> user_id

ORDERS = {
    "ord_1": {"id": "ord_1", "owner_id": 1, "item": "Laptop", "status": "placed", "price": 1200},
    "ord_2": {"id": "ord_2", "owner_id": 2, "item": "Headphones", "status": "placed", "price": 80},
}

CARTS = {}       # cart_id -> {"paid": bool, "items": [...]}
COUPONS_USED = {}  # (user_id, code) -> count


def _new_token(user_id: int) -> str:
    token = f"tok_{uuid.uuid4().hex}"
    TOKENS[token] = user_id
    return token


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    user_id = TOKENS.get(token)
    return USERS.get(user_id)


def require_auth():
    user = current_user()
    if not user:
        return None, (jsonify({"error": "unauthorized"}), 401)
    return user, None


# ---------------------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------------------
@app.post("/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    email, password = data.get("username"), data.get("password")
    for u in USERS.values():
        if u["email"] == email and u["password"] == password:
            return jsonify({"token": _new_token(u["id"]), "user_id": u["id"], "role": u["role"]})
    return jsonify({"error": "invalid credentials"}), 401


# ---------------------------------------------------------------------------------------
# Users - BOLA (vulnerable) vs a SAFE control
# ---------------------------------------------------------------------------------------
@app.get("/users/<int:user_id>")
def get_user(user_id):
    """VULNERABLE: BOLA - returns any user's profile to any authenticated caller,
    with no ownership/role check."""
    user, err = require_auth()
    if err:
        return err
    target = USERS.get(user_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    return jsonify({k: v for k, v in target.items() if k != "password"})


@app.get("/users/<int:user_id>/secure")
def get_user_secure(user_id):
    """SAFE control endpoint: proper ownership check, used to verify the tool does not
    false-positive on correctly-authorized endpoints."""
    user, err = require_auth()
    if err:
        return err
    if user["id"] != user_id and user["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    target = USERS.get(user_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    return jsonify({k: v for k, v in target.items() if k != "password"})


@app.put("/users/<int:user_id>/profile")
def update_profile(user_id):
    """VULNERABLE: mass assignment / privilege escalation - blindly applies any field
    in the request body, including 'role', with only a weak ownership check."""
    user, err = require_auth()
    if err:
        return err
    if user["id"] != user_id:
        return jsonify({"error": "forbidden"}), 403
    target = USERS[user_id]
    data = request.get_json(force=True, silent=True) or {}
    for key, value in data.items():
        if key in ("id", "password"):
            continue
        target[key] = value  # <-- no allow-list; 'role' can be set by the user themselves
    return jsonify({k: v for k, v in target.items() if k != "password"})


# ---------------------------------------------------------------------------------------
# Admin - one SAFE, one VULNERABLE (BFLA)
# ---------------------------------------------------------------------------------------
@app.get("/admin/users")
def admin_list_users():
    """SAFE control endpoint: correctly enforces the admin role."""
    user, err = require_auth()
    if err:
        return err
    if user["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify([{k: v for k, v in u.items() if k != "password"} for u in USERS.values()])


@app.get("/admin/reports")
def admin_reports():
    """VULNERABLE: BFLA - an admin-only report endpoint that forgot its role check."""
    user, err = require_auth()
    if err:
        return err
    return jsonify({"report": "quarterly revenue", "total_revenue": 184300, "generated_for": user["email"]})


# ---------------------------------------------------------------------------------------
# Orders - BOLA + parameter tampering
# ---------------------------------------------------------------------------------------
@app.get("/orders/<order_id>")
def get_order(order_id):
    """VULNERABLE: BOLA - no ownership check on order lookups."""
    user, err = require_auth()
    if err:
        return err
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@app.post("/orders/<order_id>/cancel")
def cancel_order(order_id):
    """VULNERABLE: BOLA/IDOR - any authenticated user can cancel any order."""
    user, err = require_auth()
    if err:
        return err
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    order["status"] = "cancelled"
    return jsonify(order)


@app.patch("/orders/<order_id>")
def patch_order(order_id):
    """VULNERABLE: parameter tampering - accepts and applies a client-supplied 'status'
    and 'price' with no validation and no ownership check."""
    user, err = require_auth()
    if err:
        return err
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    for key in ("status", "price"):
        if key in data:
            order[key] = data[key]
    return jsonify(order)


# ---------------------------------------------------------------------------------------
# Business logic - checkout workflow bypass + coupon replay
# ---------------------------------------------------------------------------------------
@app.post("/cart")
def create_cart():
    user, err = require_auth()
    if err:
        return err
    cart_id = "1"  # fixed id for lab simplicity
    CARTS[cart_id] = {"paid": False, "owner_id": user["id"]}
    return jsonify({"cart_id": cart_id})


@app.post("/cart/<cart_id>/payment")
def pay_cart(cart_id):
    user, err = require_auth()
    if err:
        return err
    cart = CARTS.setdefault(cart_id, {"paid": False, "owner_id": user["id"]})
    cart["paid"] = True
    return jsonify({"cart_id": cart_id, "paid": True})


@app.post("/cart/<cart_id>/checkout")
def checkout_cart(cart_id):
    """VULNERABLE: business logic flaw - checkout does not verify `paid` is True before
    completing the order, so the payment step can be skipped entirely."""
    user, err = require_auth()
    if err:
        return err
    cart = CARTS.setdefault(cart_id, {"paid": False, "owner_id": user["id"]})
    # BUG: should check `if not cart["paid"]: return 402` - intentionally omitted
    return jsonify({"cart_id": cart_id, "status": "order placed", "paid_at_checkout": cart["paid"]})


@app.post("/coupons/apply")
def apply_coupon():
    """VULNERABLE: business logic flaw - a coupon can be applied an unlimited number of
    times by the same user; no single-use tracking is enforced."""
    user, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    code = data.get("code", "")
    key = (user["id"], code)
    COUPONS_USED[key] = COUPONS_USED.get(key, 0) + 1
    return jsonify({"code": code, "applied_count": COUPONS_USED[key], "discount_applied": True})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/debug/reset")
def debug_reset():
    """Test-only helper: resets all in-memory state back to the seeded defaults so
    automated test runs (which may include a successful privilege-escalation exploit
    that mutates state) don't leak side effects between test cases. Not part of the
    "vulnerable surface" under test - just lab plumbing.
    """
    global USERS, TOKENS, ORDERS, CARTS, COUPONS_USED
    USERS = {
        1: {"id": 1, "email": "victim@example.com", "password": "victim-pass", "role": "user", "balance": 50},
        2: {"id": 2, "email": "attacker@example.com", "password": "attacker-pass", "role": "user", "balance": 10},
        3: {"id": 3, "email": "admin@example.com", "password": "admin-pass", "role": "admin", "balance": 0},
    }
    TOKENS = {}
    ORDERS = {
        "ord_1": {"id": "ord_1", "owner_id": 1, "item": "Laptop", "status": "placed", "price": 1200},
        "ord_2": {"id": "ord_2", "owner_id": 2, "item": "Headphones", "status": "placed", "price": 80},
    }
    CARTS = {}
    COUPONS_USED = {}
    return jsonify({"reset": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
