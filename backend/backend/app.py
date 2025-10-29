#!/usr/bin/env python3
import os
import hmac
import hashlib
import json
import logging
from urllib.parse import parse_qsl

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
CORS(app)

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID")
DATABASE_URL = os.getenv("DATABASE_URL")  # SQLAlchemy format

if not DATABASE_URL:
    # fallback to sqlite for local testing
    DATABASE_URL = "sqlite:///users.db"
    app.logger.warning("No DATABASE_URL provided — using sqlite users.db (local testing)")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.BigInteger, primary_key=True)
    points = db.Column(db.Integer, nullable=False, default=0)
    first_name = db.Column(db.String, nullable=True)

with app.app_context():
    db.create_all()

def verify_init_data(bot_token: str, init_data: str) -> dict:
    """
    Verify Telegram WebApp initData signature.
    Returns a dict of parsed parameters if signature matches; raises ValueError on failure.
    """
    if not init_data:
        raise ValueError("Missing init_data")

    # parse query-like string to list of pairs (handles URL encoding)
    pairs = parse_qsl(init_data, keep_blank_values=True)
    params = dict(pairs)

    if "hash" not in params:
        raise ValueError("No hash in init_data")

    hash_provided = params.pop("hash")

    # Build data_check_string: sorted by key name, format "key=value" joined by \n
    items = [f"{k}={params[k]}" for k in sorted(params.keys())]
    data_check_string = "\n".join(items)

    secret_key = hashlib.sha256(bot_token.encode()).digest()
    hmac_hash = hmac.new(secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256).hexdigest()

    if not hmac.compare_digest(hmac_hash, hash_provided):
        raise ValueError("Invalid init_data signature")

    # Return parsed params (values URL-decoded by parse_qsl)
    return params

@app.route("/api/auth", methods=["POST"])
def api_auth():
    """
    POST { "init_data": "<raw initData string from Telegram WebApp>" }
    Returns: { user_id, points, first_name }
    """
    if not BOT_TOKEN:
        return jsonify({"error": "Server not configured with BOT_TOKEN"}), 500

    data = request.get_json(force=True)
    if not data or "init_data" not in data:
        return jsonify({"error": "Missing init_data"}), 400

    init_data = data["init_data"]
    try:
        parsed = verify_init_data(BOT_TOKEN, init_data)
    except Exception as e:
        app.logger.exception("initData verification failed")
        return jsonify({"error": "Invalid init_data", "details": str(e)}), 400

    user_id = None
    first_name = None

    # Telegram WebApp often provides a 'user' param with JSON string, or keys like 'user_id' and 'user_first_name'.
    if "user" in parsed:
        try:
            user_json = json.loads(parsed["user"])
            user_id = int(user_json.get("id"))
            first_name = user_json.get("first_name")
        except Exception:
            pass

    if not user_id:
        if "user_id" in parsed:
            try:
                user_id = int(parsed["user_id"])
            except Exception:
                pass

    if not user_id:
        return jsonify({"error": "Could not determine user id from init_data"}), 400

    user = User.query.get(user_id)
    if user is None:
        user = User(id=user_id, points=100, first_name=first_name)
        db.session.add(user)
        db.session.commit()
        app.logger.info(f"Created new user {user_id} with 100 points")
    else:
        # update first name if we received it and it's not set
        if first_name and not user.first_name:
            user.first_name = first_name
            db.session.commit()

    return jsonify({"user_id": user.id, "points": user.points, "first_name": user.first_name})

@app.route("/api/user/<int:user_id>", methods=["GET"])
def api_get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"user_id": user_id, "points": 0}), 200
    return jsonify({"user_id": user.id, "points": user.points, "first_name": user.first_name})

@app.route("/webhook/<secret>", methods=["POST"])
def telegram_webhook(secret):
    """
    Telegram webhook endpoint.
    If you set your webhook to https://<BACKEND_URL>/webhook/<BOT_TOKEN> then secret == BOT_TOKEN.
    This endpoint handles admin commands like /add <user_id> <points>.
    """
    if not BOT_TOKEN:
        return "Server bot token not set", 500

    if secret != BOT_TOKEN:
        app.logger.warning("Webhook called with incorrect secret")
        return "Forbidden", 403

    update = request.get_json(force=True)
    app.logger.info(f"Received update: {update}")

    message = update.get("message") or update.get("edited_message")
    if not message:
        return jsonify({"ok": True})

    text = message.get("text", "")
    from_user = message.get("from", {})
    user_id = from_user.get("id")

    try:
        admin_int = int(ADMIN_ID) if ADMIN_ID else None
    except Exception:
        admin_int = None

    if admin_int and user_id == admin_int:
        if text and text.startswith("/add"):
            parts = text.strip().split()
            if len(parts) == 3:
                try:
                    target = int(parts[1])
                    pts = int(parts[2])
                    target_user = User.query.get(target)
                    if target_user is None:
                        target_user = User(id=target, points=pts)
                        db.session.add(target_user)
                        db.session.commit()
                        app.logger.info(f"Admin created user {target} with {pts} points")
                    else:
                        target_user.points = target_user.points + pts
                        db.session.commit()
                        app.logger.info(f"Admin added {pts} points to {target}")
                except Exception:
                    app.logger.exception("Failed to process /add command")
    return jsonify({"ok": True})

@app.route("/_health", methods=["GET"])
def health():
    return "OK", 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
