"""
Traffic simulator for the local victim_app.py (127.0.0.1 only, your own lab).
Produces labeled normal + attack traffic so access_log.jsonl can be used for ML training.

Labels: normal, brute_force, brute_force_slow, scan, injection, flood

What changed vs the first version:
  * time spread  : sessions start at random times across --duration seconds (default 600),
                   so the log has a real timeline (needed for time-window features / spikes)
  * UA mixing    : ~8% of normal sessions use tool UAs (curl / python-requests) and ~30% of
                   attack sessions use browser UAs, so user_agent no longer leaks the label
  * slow attacks : brute_force_slow = one password try every ~15 s (stays under simple rules)

Usage:  python simulate_traffic.py [--scale 1.0] [--duration 600] [--slow-gap 15]
Tip  :  delete access_log.jsonl before a fresh run.
"""
import argparse
import random
import threading
import time
import requests
from requests.adapters import HTTPAdapter

BASE = "http://127.0.0.1:5000"
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) Mobile Safari/604.1",
]
TOOL_UAS = ["python-requests/2.31", "curl/8.4.0", "sqlmap-sim/1.0", "scanner-sim/0.9"]
USERS = {"alice": "alice123", "bob": "bobpass", "carol": "carol@789"}
WORDLIST = ["123456", "password", "qwerty", "letmein", "admin123", "welcome1", "iloveyou",
            "abc123", "monkey", "dragon", "football", "master", "login", "passw0rd", "shadow"]
SCAN_PATHS = ["/admin", "/.env", "/config", "/backup.zip", "/wp-login.php", "/phpmyadmin",
              "/.git/config", "/server-status", "/api/v1/users", "/debug", "/console", "/db.sql",
              "/test", "/old", "/uploads", "/cgi-bin/test", "/robots.txt", "/sitemap.xml"]
INJECTIONS = ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null,null--",
              "<script>alert(1)</script>", "../../etc/passwd", "%2e%2e%2f%2e%2e%2fetc/passwd",
              "\" OR 1=1 --", "<img src=x onerror=alert(1)>", "1' AND SLEEP(5)--"]

SLOW_GAP = 15.0
sess = requests.Session()
sess.mount("http://", HTTPAdapter(pool_connections=100, pool_maxsize=100))


def rip():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def ua_normal():
    # real users are mostly browsers, but some are scripts / monitoring tools
    return random.choice(BROWSER_UAS) if random.random() < 0.92 else random.choice(TOOL_UAS[:2])


def ua_attack():
    # attackers mostly use tools, but some spoof a browser
    return random.choice(TOOL_UAS) if random.random() < 0.70 else random.choice(BROWSER_UAS)


def hit(method, path, ip, label, ua, user="", **kw):
    h = {"X-Sim-IP": ip, "X-Sim-Label": label, "User-Agent": ua, "X-Sim-LoginUser": user}
    h.update(kw.pop("headers", {}))
    try:
        return sess.request(method, BASE + path, headers=h, timeout=5, **kw)
    except requests.RequestException:
        return None


def normal_user():
    ip, ua = rip(), ua_normal()
    for _ in range(random.randint(3, 12)):
        r = random.random()
        if r < 0.25:
            hit("GET", "/", ip, "normal", ua)
        elif r < 0.5:
            hit("GET", "/products", ip, "normal", ua)
        elif r < 0.7:
            hit("GET", f"/product/{random.randint(1, 50)}", ip, "normal", ua)
        elif r < 0.85:
            hit("GET", f"/search?q={random.choice(['gold', 'item', '1', '2', 'ring'])}", ip, "normal", ua)
        elif r < 0.95:
            u = random.choice(list(USERS))
            pw = USERS[u] if random.random() < 0.85 else "typo" + str(random.randint(0, 99))
            hit("POST", "/login", ip, "normal", ua, user=u, json={"username": u, "password": pw})
        else:
            hit("GET", "/api/orders", ip, "normal", ua)
        time.sleep(random.uniform(0.05, 0.4))


def brute_force():
    ip, ua = rip(), ua_attack()
    u = random.choice(list(USERS) + ["admin"])
    for pw in random.sample(WORDLIST, random.randint(10, len(WORDLIST))):
        hit("POST", "/login", ip, "brute_force", ua, user=u, json={"username": u, "password": pw})
        time.sleep(random.uniform(0.01, 0.08))


def brute_force_slow():
    """Low-and-slow: one try every ~SLOW_GAP seconds, so only ~4 per minute."""
    ip, ua = rip(), ua_attack()
    u = random.choice(list(USERS) + ["admin"])
    for pw in random.sample(WORDLIST, random.randint(8, 12)):
        hit("POST", "/login", ip, "brute_force_slow", ua, user=u, json={"username": u, "password": pw})
        time.sleep(random.uniform(SLOW_GAP * 0.8, SLOW_GAP * 1.2))


def scan():
    ip, ua = rip(), ua_attack()
    for p in random.sample(SCAN_PATHS, random.randint(10, len(SCAN_PATHS))):
        hit("GET", p, ip, "scan", ua)
        time.sleep(random.uniform(0.005, 0.05))


def injection():
    ip, ua = rip(), ua_attack()
    for _ in range(random.randint(5, 12)):
        payload = random.choice(INJECTIONS)
        if random.random() < 0.7:
            hit("GET", "/search", ip, "injection", ua, params={"q": payload})
        else:
            hit("GET", f"/product/{random.randint(1, 50)}", ip, "injection", ua, params={"id": payload})
        time.sleep(random.uniform(0.02, 0.15))


def flood():
    ip, ua = rip(), ua_attack()
    target = random.choice(["/", "/products", "/search?q=gold"])
    for _ in range(random.randint(60, 120)):
        hit("GET", target, ip, "flood", ua)   # no sleep: very high request rate from one IP


def schedule(fn, n, duration):
    """Start n sessions of fn at random moments inside [0, duration] seconds."""
    return [threading.Timer(random.uniform(0, duration), fn) for _ in range(n)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=600, help="seconds over which sessions start")
    ap.add_argument("--slow-gap", type=float, default=15.0, help="seconds between slow brute-force tries")
    a = ap.parse_args()
    SLOW_GAP = a.slow_gap
    s = a.scale
    plan = [(normal_user, int(200 * s)), (brute_force, int(15 * s)), (brute_force_slow, max(int(8 * s), 1)),
            (scan, int(15 * s)), (injection, int(15 * s)), (flood, int(10 * s))]
    timers = []
    for fn, n in plan:
        timers += schedule(fn, max(n, 1), a.duration)
    random.shuffle(timers)
    print(f"starting {len(timers)} sessions over {a.duration:.0f}s ...")
    for t in timers:
        t.start()
    for t in timers:
        t.join()
    print("simulation done")
