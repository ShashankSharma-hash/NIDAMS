"""
detect.py - Watchman detection engine (log-based): features -> rules + Isolation Forest -> alerts.

Train + evaluate on a labeled CSV, save the model:
    python detect.py train ../data/logs_labeled.csv

Use from other code (this is what watchman_runner.py does):
    from detect import detect
    alerts = detect(records, bundle, site_id="shop1", owner="owner1")
where `records` is a list of dicts with keys: ts, ip, method, path, query, status, bytes,
resp_ms (user_agent / login_user / label are ignored by the model on purpose).
"""
import re
import sys
import uuid
import datetime as dt
from urllib.parse import unquote_plus

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

WINDOW = 60  # seconds
MODEL_PATH = "model.joblib"
ML_MIN_REQUESTS = 3  # ML only judges an IP after it has made at least this many requests

# user_agent and label are NOT features (UA leaked the label in the first dataset).
FEATURES = ["n_requests", "req_rate", "unique_paths", "path_repeat", "ratio_4xx", "ratio_404",
            "login_attempts", "failed_logins", "login_fail_ratio", "suspicious_query",
            "query_special", "mean_gap", "min_gap", "avg_bytes", "avg_resp_ms"]

SUSPICIOUS = re.compile(r"('|--|;|<|>|\.\./|%2e|union|select|script|sleep|drop|onerror)", re.I)
SPECIAL = re.compile(r"[^A-Za-z0-9=&_.%+\- ]")


# ------------------------------------------------------------------ features
def ip_features(g: pd.DataFrame) -> dict:
    """Features of ONE ip inside ONE time window."""
    g = g.sort_values("ts")
    n = len(g)
    ts = g["ts"].values
    gaps = np.diff(ts) if n > 1 else np.array([float(WINDOW)])
    span = max(ts.max() - ts.min(), 1.0)
    is_login = (g["path"] == "/login") & (g["method"] == "POST")
    failed = int((is_login & (g["status"] == 401)).sum())
    q = g["query"].fillna("").astype(str).map(unquote_plus)
    return dict(
        n_requests=n,
        req_rate=n / span,
        unique_paths=int(g["path"].nunique()),
        path_repeat=1 - g["path"].nunique() / n,
        ratio_4xx=float((g["status"] >= 400).mean()),
        ratio_404=float((g["status"] == 404).mean()),
        login_attempts=int(is_login.sum()),
        failed_logins=failed,
        login_fail_ratio=failed / max(int(is_login.sum()), 1),
        suspicious_query=int(q.map(lambda s: bool(SUSPICIOUS.search(s))).sum()),
        query_special=float(q.map(lambda s: len(SPECIAL.findall(s))).mean()),
        mean_gap=float(gaps.mean()),
        min_gap=float(gaps.min()),
        avg_bytes=float(g["bytes"].mean()),
        avg_resp_ms=float(g["resp_ms"].mean()),
        top_path=g["path"].mode().iloc[0],
    )


def windowed_features(df: pd.DataFrame, window=WINDOW) -> pd.DataFrame:
    """One row per (ip, window). Used for training / offline evaluation."""
    df = df.copy()
    df["w"] = (df["ts"] // window).astype(int)
    rows = []
    for (ip, w), g in df.groupby(["ip", "w"]):
        r = ip_features(g)
        r.update(ip=ip, w=w, t0=g["ts"].min(), t1=g["ts"].max())
        if "label" in g:
            r["label"] = g["label"].mode().iloc[0]
        rows.append(r)
    return pd.DataFrame(rows)


# ------------------------------------------------------------------ rules
def rule_name(f) -> str:
    if f["suspicious_query"] >= 2:
        return "injection"
    if f["failed_logins"] >= 6:
        return "brute_force"
    if f["ratio_4xx"] >= 0.7 and f["unique_paths"] >= 8:
        return "path_scan"
    if f["req_rate"] >= 30 and f["n_requests"] >= 40:
        return "traffic_spike"
    return ""


# ------------------------------------------------------------------ ML
def fit(normal: pd.DataFrame) -> dict:
    sc = StandardScaler().fit(normal[FEATURES])
    X = sc.transform(normal[FEATURES])
    m = IsolationForest(n_estimators=300, random_state=42).fit(X)
    raw = -m.score_samples(X)
    lo, hi = np.percentile(raw, 5), np.percentile(raw, 99.9)
    thr = np.percentile(raw, 97)  # ~3% of normal windows get flagged
    return dict(scaler=sc, model=m, lo=lo, hi=hi, threshold=float((thr - lo) / (hi - lo)), features=FEATURES)


def ml_score(b: dict, X: pd.DataFrame) -> np.ndarray:
    raw = -b["model"].score_samples(b["scaler"].transform(X[b["features"]]))
    return np.clip((raw - b["lo"]) / (b["hi"] - b["lo"]), 0, 1)


def severity(rule: str, ml_flag: bool, score: float) -> str:
    if rule and ml_flag:
        return "Critical" if score > 0.9 else "High"
    if rule or (ml_flag and score > 0.8):
        return "Medium"
    return "Low"


# ------------------------------------------------------------------ detect (used by the runner)
def detect(records, bundle, site_id="shop1", owner="owner1") -> list:
    """All `records` are treated as ONE window (the runner passes the last ~60 s of logs)."""
    if not records:
        return []
    df = pd.DataFrame(records)
    now = dt.datetime.now().astimezone()
    alerts = []
    for ip, g in df.groupby("ip"):
        f = ip_features(g)
        rule = rule_name(f)
        score = float(ml_score(bundle, pd.DataFrame([f]))[0])
        # ML needs a little evidence: 1-2 requests is a half-seen session, not a behaviour
        ml_flag = bool(f["n_requests"] >= ML_MIN_REQUESTS and score >= bundle["threshold"])
        if not rule and not ml_flag:
            continue
        # ML-only alert that looks like repeated failed logins = low-and-slow brute force
        threat = rule or "anomaly"
        if not rule and ml_flag and f["failed_logins"] >= 3 and f["login_fail_ratio"] >= 0.8:
            threat = "brute_force"
        iso = lambda t: dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")
        alerts.append({
            "schema_version": "1.1",
            "alert_id": uuid.uuid4().hex[:12],
            "timestamp": now.isoformat(timespec="seconds"),
            "window_start": iso(g["ts"].min()),
            "window_end": iso(g["ts"].max()),
            "site_id": site_id,
            "owner": owner,
            "src_ip": ip,
            "dst_ip": None,
            "threat_type": threat,
            "detected_by": "hybrid" if (rule and ml_flag) else ("rule" if rule else "ml"),
            "rule_triggered": rule or None,
            "ml_flag": bool(ml_flag),
            "anomaly_score": round(score, 3),
            "severity": severity(rule, ml_flag, score),
            "features": {k: (round(f[k], 3) if isinstance(f[k], float) else f[k])
                         for k in ["n_requests", "req_rate", "failed_logins", "unique_paths",
                                   "ratio_4xx", "suspicious_query", "top_path"]},
            "status": "new",
        })
    return alerts


# ------------------------------------------------------------------ offline evaluation
def _metrics(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return dict(precision=precision_score(y, p, zero_division=0), recall=recall_score(y, p, zero_division=0),
                f1=f1_score(y, p, zero_division=0), fpr=fp / max(fp + tn, 1), tp=tp, fp=fp, fn=fn, tn=tn)


def evaluate(f: pd.DataFrame, seed=42):
    f = f.copy()
    f["y"] = (f["label"] != "normal").astype(int)
    rng = np.random.default_rng(seed)
    normal_ips = f.loc[f.y == 0, "ip"].unique()
    test_ips = set(rng.choice(normal_ips, size=int(0.3 * len(normal_ips)), replace=False))
    is_test = f["ip"].isin(test_ips) | (f.y == 1)          # all attacks go to test, normal split by IP
    train, test = f[~is_test], f[is_test].copy()
    b = fit(train)
    test["rule"] = test.apply(rule_name, axis=1)
    test["score"] = ml_score(b, test)
    rule_p = (test["rule"] != "").astype(int)
    ml_p = ((test["score"] >= b["threshold"]) & (test["n_requests"] >= ML_MIN_REQUESTS)).astype(int)
    hyb_p = ((rule_p == 1) | (ml_p == 1)).astype(int)
    table = pd.DataFrame({"Rules only": _metrics(test.y, rule_p), "ML only (IsolationForest)": _metrics(test.y, ml_p),
                          "Hybrid": _metrics(test.y, hyb_p)}).T
    test["rules"], test["ml"], test["hybrid"] = rule_p, ml_p, hyb_p
    per_attack = test[test.y == 1].groupby("label")[["rules", "ml", "hybrid"]].mean()
    return table, per_attack, test


def train_cli(csv_path):
    df = pd.read_csv(csv_path)
    f = windowed_features(df)
    print("windows per label:\n" + f["label"].value_counts().to_string() + "\n")
    table, per_attack, _ = evaluate(f)
    print("=== Held-out evaluation (per IP-window) ===")
    print(table[["precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"]].round(3).to_string())
    print("\n=== Recall per attack type ===")
    print(per_attack.round(2).to_string())
    bundle = fit(f[f["label"] == "normal"])
    joblib.dump(bundle, MODEL_PATH)
    print(f"\nmodel saved -> {MODEL_PATH}  (ML threshold {bundle['threshold']:.3f})")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "train":
        train_cli(sys.argv[2])
    else:
        print(__doc__)
