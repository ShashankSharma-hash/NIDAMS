"""
mock_backend.py - tiny stand-in for Shashank's backend, only for testing the runner.
    python mock_backend.py        (listens on 127.0.0.1:8000)
POST /alerts  -> stores the alert        GET /alerts -> lists them
"""
from flask import Flask, request, jsonify

app = Flask(__name__)
ALERTS = []


@app.post("/alerts")
def post_alert():
    ALERTS.append(request.get_json(force=True))
    return jsonify(ok=True, count=len(ALERTS)), 201


@app.get("/alerts")
def get_alerts():
    return jsonify(ALERTS)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
