from flask import Flask, request, jsonify
import os, secrets, string
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

KEYS_FILE   = os.path.join(os.path.dirname(__file__), "keys.json")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-this-secret-token")
MASTER_KEY  = os.environ.get("MASTER_KEY", "Bakaev1998")

def _load():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE) as f:
        import json
        return json.load(f)

def _save(data):
    import json
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route("/validate", methods=["POST"])
def validate():
    body = request.get_json(silent=True) or {}
    key  = body.get("key", "").strip().upper()
    hwid = body.get("hwid", "").strip()
    if key == MASTER_KEY.upper():
        expire = (datetime.utcnow() + timedelta(days=36500)).isoformat()
        return jsonify({"ok": True, "msg": "OK", "expire": expire})
    data = _load()
    if key not in data:
        return jsonify({"ok": False, "msg": "Invalid key"})
    entry = data[key]
    if entry["status"] == "frozen":
        return jsonify({"ok": False, "msg": "Key is frozen"})
    expire = datetime.fromisoformat(entry["expire"])
    if datetime.utcnow() > expire:
        return jsonify({"ok": False, "msg": "Key has expired"})
    bound = entry.get("hwid", "")
    if not bound:
        entry["hwid"] = hwid
        _save(data)
    elif bound != hwid:
        return jsonify({"ok": False, "msg": "Key is bound to another PC"})
    return jsonify({"ok": True, "msg": "OK", "expire": entry["expire"]})

@app.route("/admin/generate", methods=["POST"])
@require_admin
def generate():
    body  = request.get_json(silent=True) or {}
    days  = int(body.get("days", 30))
    chars = string.ascii_uppercase + string.digits
    key   = "-".join("".join(secrets.choice(chars) for _ in range(5)) for _ in range(4))
    data  = _load()
    data[key] = {
        "status":  "active",
        "expire":  (datetime.utcnow() + timedelta(days=days)).isoformat(),
        "days":    days,
        "created": datetime.utcnow().isoformat(),
        "hwid":    "",
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
    key  = (request.get_json(silent=True) or {}).get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["status"] = "frozen"
        _save(data)
    return jsonify({"ok": True})

@app.route("/admin/unfreeze", methods=["POST"])
@require_admin
def unfreeze():
    key  = (request.get_json(silent=True) or {}).get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["status"] = "active"
        _save(data)
    return jsonify({"ok": True})

@app.route("/admin/delete", methods=["POST"])
@require_admin
def delete():
    key  = (request.get_json(silent=True) or {}).get("key", "").upper()
    data = _load()
    if key in data:
        del data[key]
        _save(data)
    return jsonify({"ok": True})

@app.route("/admin/reset_hwid", methods=["POST"])
@require_admin
def reset_hwid():
    key  = (request.get_json(silent=True) or {}).get("key", "").upper()
    data = _load()
    if key in data:
        data[key]["hwid"] = ""
        _save(data)
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
