from flask import Flask, jsonify, request
from datetime import datetime, timezone
from functools import wraps

app = Flask(__name__)
import os
ADMIN_TOKEN = os.environ["CLOUDGUARD_ADMIN_TOKEN"]
sites = {"store": True, "restaurant": True, "clinic": True}

def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    return """
    <h1>CloudGuard Monitoring Platform</h1>
    <ul>
      <li><a href="/store">Online Store</a></li>
      <li><a href="/restaurant">Restaurant</a></li>
      <li><a href="/clinic">Clinic</a></li>
    </ul>
    """

@app.route("/<site>")
def website(site):
    if site not in sites:
        return "Not found", 404
    if not sites[site]:
        return f"{site.title()} is unavailable", 503
    return f"<h1>{site.title()} Demo Website</h1><p>Status: Healthy</p>"

@app.route("/health/<site>")
def health(site):
    if site not in sites:
        return jsonify({"error": "Unknown website"}), 404
    healthy = sites[site]
    return jsonify({
        "website": site,
        "healthy": healthy,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200 if healthy else 503

@app.route("/demo/fail/<site>", methods=["POST"])
@require_token
def fail(site):
    if site not in sites:
        return jsonify({"error": "Unknown website"}), 404
    sites[site] = False
    return jsonify({"website": site, "healthy": False})

@app.route("/demo/recover/<site>", methods=["POST"])
@require_token
def recover(site):
    if site not in sites:
        return jsonify({"error": "Unknown website"}), 404
    sites[site] = True
    return jsonify({"website": site, "healthy": True})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
