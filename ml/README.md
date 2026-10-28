# Watchman - ML / Detection module

Log-based intrusion detection for hosted websites. The watchman reads the gateway's request logs,
detects suspicious behaviour with **rules + Isolation Forest (hybrid)**, and sends alerts to the
backend, where the site owner sees them on the dashboard.

```
gateway / victim app  ->  access_log.jsonl  ->  watchman_runner.py (detect.py)  ->  POST /alerts  ->  backend + dashboard
```

> All data in this folder is **simulated** (a local toy victim app and a traffic simulator on 127.0.0.1).

## Files

| File | Purpose |
|---|---|
| `victim_app.py` | Small Flask shop app (port 5000) that writes every request to `access_log.jsonl` |
| `simulate_traffic.py` | Generates labelled normal + attack traffic (brute force, slow brute force, scan, injection, flood) |
| `logs_to_csv.py` | Converts `access_log.jsonl` to `logs_labeled.csv` |
| `logs_labeled.csv` | Labelled training / evaluation data |
| `detect.py` | Feature extraction, rules, Isolation Forest, hybrid severity, `detect()`; `python detect.py train <csv>` trains and evaluates |
| `watchman_runner.py` | Tails the log, calls `detect()` every few seconds, writes `alerts.jsonl` and POSTs alerts to the backend |
| `mock_backend.py` | Tiny stand-in backend (only for testing without the real backend) |

## Setup

```
pip install flask requests pandas scikit-learn joblib
```

## 1. Create data and train the model (about 6 minutes)

```
python victim_app.py                              # terminal 1
python simulate_traffic.py --duration 150         # terminal 2, wait for "simulation done", then stop terminal 1
python logs_to_csv.py
python detect.py train logs_labeled.csv           # prints evaluation table, saves model.joblib
```

(`logs_labeled.csv` is already in the repo, so you can skip straight to the last command.)

## 2. Live demo

Delete or rename any old `access_log.jsonl` first, then start in this order:

```
python victim_app.py                                                              # 1: victim app
uvicorn main:app --port 8000                                                      # 2: real backend (from backend/), or: python mock_backend.py
python watchman_runner.py --log access_log.jsonl --api http://127.0.0.1:8000/alerts   # 3: watchman
python simulate_traffic.py --scale 0.5 --duration 60                              # 4: traffic + attacks
```

Alerts appear in terminal 3 and on the dashboard. Useful runner options: `--site`, `--owner`,
`--window` (seconds of logs analysed, default 60), `--cooldown` (seconds before the same IP+threat
alerts again, default 300).

## How detection works

1. **Features** per IP per 60 s window: request count and rate, unique paths, 4xx/404 ratio, login attempts,
   failed logins, suspicious query characters, inter-request gaps, bytes, response time.
   `user_agent` and the label are never used as features.
2. **Rules**: injection patterns, >= 6 failed logins, many 4xx on many paths (scan), very high request rate (flood).
3. **Isolation Forest** trained on normal windows only; the anomaly score is normalised to 0-1.
   ML only judges an IP after at least 3 requests.
4. **Hybrid**: alert if a rule fires or ML flags. Severity: rule + ML = High/Critical, one of them = Medium/Low.

## Alert JSON (schema 1.1)

```json
{
  "schema_version": "1.1", "alert_id": "17b86078352e", "timestamp": "2026-10-25T17:29:14+05:30",
  "window_start": "...", "window_end": "...", "site_id": "shop1", "owner": "owner1",
  "src_ip": "10.63.214.232", "dst_ip": null,
  "threat_type": "brute_force", "detected_by": "hybrid", "rule_triggered": "brute_force",
  "ml_flag": true, "anomaly_score": 1.0, "severity": "Critical",
  "features": {"n_requests": 13, "failed_logins": 13, "top_path": "/login"},
  "status": "new"
}
```

`threat_type`: brute_force | path_scan | injection | traffic_spike | anomaly.
`detected_by`: rule | ml | hybrid. `severity`: Low | Medium | High | Critical.

## Results (simulated data, held-out per IP-window)

| | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Rules only | 1.00 | 0.68 | 0.81 | 0.00 |
| ML only (Isolation Forest) | 1.00 | 0.61 | 0.75 | 0.00 |
| Hybrid | 1.00 | 0.91 | 0.96 | 0.00 |

Rules miss low-and-slow brute force (recall 0.0); Isolation Forest catches 73% of it. ML alone misses
floods and injections, which the rules catch.

## Known limitations / Phase 3

- Simulated, single-run data; small test set, so numbers vary between runs.
- Slow brute force is detected by ML only and alerts can repeat every few minutes.
- Phase 3: run on the real hosting platform's logs (an adapter maps its field names), time-window spike detector,
  distributed attacks, OCSVM/LOF comparison, SHAP explanations.
