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

import os
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
TOKENS = {}

ORDERS = {
    "ord_1": {"id": "ord_1", "owner_id": 1, "item": "Laptop", "status": "placed", "price": 1200},
    "ord_2": {"id": "ord_2", "owner_id": 2, "item": "Headphones", "status": "placed", "price": 80},
}

CARTS = {}
COUPONS_USED = {}


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
    user, err = require_auth()
    if err:
        return err
    target = USERS.get(user_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    return jsonify({k: v for k, v in target.items() if k != "password"})


@app.get("/users/<int:user_id>/secure")
def get_user_secure(user_id):
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
        target[key] = value
    return jsonify({k: v for k, v in target.items() if k != "password"})


@app.get("/admin/users")
def admin_list_users():
    user, err = require_auth()
    if err:
        return err
    if user["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify([{k: v for k, v in u.items() if k != "password"} for u in USERS.values()])


@app.get("/admin/reports")
def admin_reports():
    user, err = require_auth()
    if err:
        return err
    return jsonify({"report": "quarterly revenue", "total_revenue": 184300, "generated_for": user["email"]})


@app.get("/orders/<order_id>")
def get_order(order_id):
    user, err = require_auth()
    if err:
        return err
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@app.post("/orders/<order_id>/cancel")
def cancel_order(order_id):
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


@app.post("/cart")
def create_cart():
    user, err = require_auth()
    if err:
        return err
    cart_id = "1"
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
    user, err = require_auth()
    if err:
        return err
    cart = CARTS.setdefault(cart_id, {"paid": False, "owner_id": user["id"]})
    return jsonify({"cart_id": cart_id, "status": "order placed", "paid_at_checkout": cart["paid"]})


@app.post("/coupons/apply")
def apply_coupon():
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
    port = int(os.getenv("PORT", "8010"))
    app.run(host="0.0.0.0", port=port, debug=False)
