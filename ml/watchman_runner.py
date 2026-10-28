"""
watchman_runner.py - tails the gateway/victim log, runs detect() every few seconds,
prints alerts, appends them to alerts.jsonl and (optionally) POSTs them to the backend.

Example:
    python watchman_runner.py --log ../victim/access_log.jsonl --model model.joblib \
           --api http://127.0.0.1:8000/alerts --site shop1 --owner owner1
Leave out --api to only print / save alerts.
"""
import argparse
import json
import os
import time

import joblib
import requests

from detect import detect, WINDOW


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="../victim/access_log.jsonl")
    ap.add_argument("--model", default="model.joblib")
    ap.add_argument("--api", default="", help="backend URL for POST /alerts (optional)")
    ap.add_argument("--out", default="alerts.jsonl")
    ap.add_argument("--site", default="shop1")
    ap.add_argument("--owner", default="owner1")
    ap.add_argument("--interval", type=float, default=3.0, help="seconds between checks")
    ap.add_argument("--window", type=float, default=WINDOW)
    ap.add_argument("--cooldown", type=float, default=300,
                    help="seconds before the same ip+threat can alert again (default 5 min)")
    a = ap.parse_args()

    bundle = joblib.load(a.model)
    buf, pos, last_alert = [], 0, {}
    print(f"watching {a.log} | window={a.window}s | api={a.api or 'none'}")
    while True:
        # ---- read only the NEW complete lines
        if os.path.exists(a.log):
            with open(a.log, "rb") as f:
                f.seek(pos)
                chunk = f.read()
            cut = chunk.rfind(b"\n") + 1
            for line in chunk[:cut].decode(errors="replace").splitlines():
                try:
                    buf.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            pos += cut
        now = time.time()
        buf = [r for r in buf if r["ts"] >= now - a.window]

        # ---- detect + de-duplicate (same ip+threat only once per --cooldown seconds)
        for al in detect(buf, bundle, a.site, a.owner):
            key = (al["src_ip"], al["threat_type"])
            if now - last_alert.get(key, 0) < a.cooldown:
                continue
            last_alert[key] = now
            print(f"[ALERT] {al['severity']:<8} {al['threat_type']:<13} ip={al['src_ip']:<16} "
                  f"by={al['detected_by']:<6} score={al['anomaly_score']}")
            with open(a.out, "a") as o:
                o.write(json.dumps(al) + "\n")
            if a.api:
                try:
                    requests.post(a.api, json=al, timeout=3)
                except requests.RequestException as e:
                    print("  (could not reach backend:", type(e).__name__, ")")
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
