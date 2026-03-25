from flask import Flask, request, jsonify
import json, os, secrets, string
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

KEYS_FILE  = os.path.join(os.path.dirname(__file__), "keys.json")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-this-secret-token")

# ── Хранилище ─────────────────────────────────────────────────────────────────
def _load():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE) as f:
        return json.load(f)

def _save(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ── Авторизация админа ────────────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Admin-Token", "")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

# ── Публичный эндпоинт: проверка ключа ───────────────────────────────────────
@app.route("/validate", methods=["POST"])
def validate():
    key = request.json.get("key", "").strip().upper()
    data = _load()
    if key not in data:
        return jsonify({"ok": False, "msg": "Invalid key"})
    entry = data[key]
    if entry["status"] == "deleted":
        return jsonify({"ok": False, "msg": "Key has been deleted"})
    if entry["status"] == "frozen":
        return jsonify({"ok": False, "msg": "Key is frozen"})
    expire = datetime.fromisoformat(entry["expire"])
    if datetime.utcnow() > expire:
        return jsonify({"ok": False, "msg": "Key has expired"})
    return jsonify({"ok": True, "msg": "OK", "expire": entry["expire"]})

# ── Админ эндпоинты ───────────────────────────────────────────────────────────
@app.route("/admin/generate", methods=["POST"])
@require_admin
def generate():
    days = int(request.json.get("days", 30))
    chars = string.ascii_uppercase + string.digits
    key = "-".join("".join(secrets.choice(chars) for _ in range(5)) for _ in range(4))
    data = _load()
    data[key] = {
        "status":  "active",
        "expire":  (datetime.utcnow() + timedelta(days=days)).isoformat(),
        "days":    days,
        "created": datetime.utcnow().isoformat(),
    }
    _save(data)
    return jsonify({"ok": True, "key": key})

@app.route("/admin/keys", methods=["GET"])
@require_admin
def list_keys():
    return jsonify(_load())

@app.route("/admin/freeze", methods=["POST"])
@require_admin
def freeze():
    key = request.json.get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["status"] = "frozen"
        _save(data)
    return jsonify({"ok": True})

@app.route("/admin/unfreeze", methods=["POST"])
@require_admin
def unfreeze():
    key = request.json.get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["status"] = "active"
        _save(data)
    return jsonify({"ok": True})

@app.route("/admin/delete", methods=["POST"])
@require_admin
def delete():
    key = request.json.get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["status"] = "deleted"
        _save(data)
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
