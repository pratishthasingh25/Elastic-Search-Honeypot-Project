import tornado.ioloop
import tornado.web
import tornado.httpclient
import psycopg
import datetime
import smtplib
import matplotlib.pyplot as plt
import io
import json
import os
import time
from dotenv import load_dotenv
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ===== Load Environment Variables =====
load_dotenv()

SMTP_SERVER         = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT           = int(os.getenv("SMTP_PORT", 587))
EMAIL               = os.getenv("ALERT_EMAIL")
PASSWORD            = os.getenv("ALERT_PASSWORD")
RECIPIENT           = os.getenv("ALERT_RECIPIENT")
ALERT_COOLDOWN      = int(os.getenv("ALERT_COOLDOWN_SECONDS", 600))
HONEYPOT_PORT       = int(os.environ.get("PORT", 9200))

# ===== Alert Throttle State =====
# Maps source_ip -> last alert timestamp (epoch seconds)
_alert_last_sent = {}

def should_send_alert(ip):
    """Return True if enough time has passed since the last alert for this IP."""
    now = time.time()
    last = _alert_last_sent.get(ip, 0)
    if now - last >= ALERT_COOLDOWN:
        _alert_last_sent[ip] = now
        return True
    return False

# ===== Database Setup =====
DATABASE_URL = os.getenv("DATABASE_URL")

db_conn = psycopg.connect(DATABASE_URL)
db_conn.autocommit = True

db_cursor = db_conn.cursor()

db_cursor.execute('''CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    timestamp   TEXT,
    source_ip   TEXT,
    event_type  TEXT,
    request_uri TEXT,
    method      TEXT DEFAULT 'GET',
    post_body   TEXT,
    user_agent  TEXT,
    country     TEXT,
    region      TEXT,
    city        TEXT,
    isp         TEXT,
    org         TEXT,
    lat         REAL,
    lon         REAL
)''')

db_cursor.execute('''CREATE TABLE IF NOT EXISTS harvested_credentials (
    id          SERIAL PRIMARY KEY,
    timestamp   TEXT,
    source_ip   TEXT,
    username    TEXT,
    password    TEXT,
    endpoint    TEXT,
    user_agent  TEXT,
    country     TEXT,
    city        TEXT
)''')

db_conn.commit()

# ===== Async Geolocation =====
async def geolocate_ip(ip_address):
    """Non-blocking geolocation via ip-api.com using Tornado AsyncHTTPClient."""
    try:
        client = tornado.httpclient.AsyncHTTPClient()
        url = (
            f"http://ip-api.com/json/{ip_address}"
            "?fields=status,country,regionName,city,lat,lon,isp,org"
        )
        response = await client.fetch(url, raise_error=False)
        data = json.loads(response.body)
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "region":  data.get("regionName"),
                "city":    data.get("city"),
                "isp":     data.get("isp"),
                "org":     data.get("org"),
                "lat":     data.get("lat"),
                "lon":     data.get("lon"),
            }
    except Exception as e:
        print(f"[GEO] Failed for {ip_address}: {e}")
    return None

# ===== Async Logging =====
async def log_event(source_ip, event_type, request_uri, user_agent,
                    method="GET", post_body=None):
    geo = await geolocate_ip(source_ip)
    timestamp = datetime.datetime.now().isoformat()
    db_cursor.execute("""
        INSERT INTO events
        (timestamp, source_ip, event_type, request_uri, method, post_body,
         user_agent, country, region, city, isp, org, lat, lon)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        timestamp, source_ip, event_type, request_uri, method, post_body,
        user_agent,
        geo.get("country") if geo else None,
        geo.get("region")  if geo else None,
        geo.get("city")    if geo else None,
        geo.get("isp")     if geo else None,
        geo.get("org")     if geo else None,
        geo.get("lat")     if geo else None,
        geo.get("lon")     if geo else None,
    ))
    db_conn.commit()
    return geo

# ===== Graph Generation =====
"""
def generate_attack_graphs():
    graphs = {}


    return graphs 
    
"""

# ===== Email Alert =====
def send_alert(source_ip, request_uri, user_agent, geo, method="GET", post_body=None):
    """Send alert email — call only after should_send_alert() check."""
    if not EMAIL or not PASSWORD:
        print("[ALERT] Email credentials not configured in .env")
        return

    summary = get_attack_summary()
    geo_str = ""
    if geo:
        geo_str = (f"\nLocation: {geo.get('city','')}, "
                   f"{geo.get('region','')}, {geo.get('country','')}"
                   f"\nISP: {geo.get('isp','Unknown')}")

    subject = f"🚨 Honeypot Alert: Attack from {source_ip}"
    body = f"""
⚠️ NEW ATTACK DETECTED ⚠️
--------------------------
Source IP:   {source_ip}{geo_str}
Method:      {method}
Time:        {datetime.datetime.now()}
Target URI:  {request_uri}
User Agent:  {user_agent}
{"POST Body:   " + str(post_body) if post_body else ""}

📊 ATTACK SUMMARY (Last 24h)
--------------------------
Total Attacks:     {summary['total_attacks']}
Attack Types:      {', '.join(summary['attack_types'])}
Attack Frequency:  {summary['attack_frequency']}/hour
Last 5 Attacks:
{summary['recent_attacks']}
"""
    graphs = generate_attack_graphs()

    msg = MIMEMultipart("related")
    msg["From"]    = EMAIL
    msg["To"]      = RECIPIENT
    msg["Subject"] = subject

    html = f"""<html><body>
    <h2 style="color:red;">⚠️ New Attack Detected ⚠️</h2>
    <p>
      <b>Source IP:</b> {source_ip}<br>
      <b>Method:</b> {method}<br>
      <b>Location:</b> {geo.get('city','N/A') if geo else 'N/A'},
                       {geo.get('region','N/A') if geo else 'N/A'},
                       {geo.get('country','N/A') if geo else 'N/A'}<br>
      <b>ISP:</b> {geo.get('isp','Unknown') if geo else 'Unknown'}<br>
      <b>Time:</b> {datetime.datetime.now()}<br>
      <b>Target:</b> {request_uri}
      {"<br><b>POST Body:</b> <code>" + str(post_body) + "</code>" if post_body else ""}
    </p>
    <h3>Attack Trends</h3>
    <img src="cid:hourly_graph"><br>
    <img src="cid:type_graph"><br>
    <img src="cid:attacker_graph">
    <h3>Recent Activity</h3>
    <pre>{summary['recent_attacks']}</pre>
    </body></html>"""

    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(html,  "html"))

    for name, img_data in graphs.items():
        img = MIMEImage(img_data)
        img.add_header("Content-ID", f"<{name}_graph>")
        msg.attach(img)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, RECIPIENT, msg.as_string())
        server.quit()
        print("📧 Alert email sent!")
    except Exception as e:
        print(f"❌ Email failed: {e}")

# ===== Attack Summary =====
def get_attack_summary():
    threshold = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
    db_cursor.execute("""
        SELECT COUNT(*) as total_attacks,
               GROUP_CONCAT(DISTINCT event_type) as attack_types,
               COUNT(*) / 24 as attack_frequency
        FROM events
        WHERE timestamp > %s AND event_type LIKE '%Attack%'
    """, (threshold,))
    stats = db_cursor.fetchone()

    db_cursor.execute("""
        SELECT timestamp, source_ip, event_type
        FROM events WHERE event_type LIKE '%Attack%'
        ORDER BY timestamp DESC LIMIT 5
    """)
    recent = db_cursor.fetchall()
    recent_attacks = "\n".join([f"{r[0]} | {r[1]} | {r[2]}" for r in recent])

    return {
        "total_attacks":    stats[0] or 0,
        "attack_types":     stats[1].split(",") if stats[1] else [],
        "attack_frequency": round(stats[2] or 0, 1),
        "recent_attacks":   recent_attacks,
    }

# ===== Attack Classifier =====
def classify_attack(uri, user_agent, post_body=""):
    payload = (uri + " " + (post_body or "")).lower()
    ua      = user_agent.lower()

    scanner_signatures = [
        "shodan", "masscan", "nmap", "zgrab", "censys",
        "python-requests", "go-http-client", "curl/", "libwww-perl",
        "nikto", "sqlmap", "dirbuster", "nuclei", "metasploit",
    ]
    if any(sig in ua for sig in scanner_signatures):
        return "Automated Scanner Detected"

    cve_patterns = [
        "${jndi:", "${${lower:j}ndi:", "jndi:ldap", "jndi:rmi",
        "() {", "() { :;};", "class.module.classloader",
        "heartbeat", "eval-stdin.php", "thinkphp", "%{#context",
    ]
    if any(p in payload for p in cve_patterns):
        return "CVE Exploit Probe"

    sql_patterns = [
        "' or '", "' or 1=1", "union select", "drop table",
        "insert into", "delete from", "'; --", "%27",
        "information_schema", "sleep(", "benchmark(",
        "xp_cmdshell", "or 1=1", "' and '",
    ]
    if any(p in payload for p in sql_patterns):
        return "SQL Injection Attempt"

    xss_patterns = [
        "<script", "javascript:", "onerror=", "onload=",
        "alert(", "document.cookie", "eval(", "<img src=",
        "svg/onload", "%3cscript",
    ]
    if any(p in payload for p in xss_patterns):
        return "XSS Attempt"

    traversal_patterns = [
        "../", "..\\", "%2e%2e%2f", "/etc/passwd", "/etc/shadow",
        "boot.ini", "win.ini", "/windows/system32", "../../../../",
    ]
    if any(p in payload for p in traversal_patterns):
        return "Path Traversal / LFI Attempt"

    injection_keywords = [
        "wget", "curl", "bash", " sh ", "nc", "chmod",
        ";ls", ";id", ";whoami", "|id", "|whoami",
        "&&id", "&&cat /etc", "cmd.exe", "powershell",
    ]
    if any(cmd in payload for cmd in injection_keywords):
        return "Command Injection Attempt"

    recon_paths = [
        "/_search", "/_cat", "/_cluster", "/_nodes",
        "/_bulk", "/_stats", "/_mapping", "/_aliases", "/_template",
    ]
    if any(path in uri for path in recon_paths):
        return "Reconnaissance Attack"

    admin_paths = [
        "/admin", "/administrator", "/wp-admin", "/wp-login",
        "/phpmyadmin", "/manager/html", "/console", "/login",
        "/.env", "/config", "/.git", "/actuator",
    ]
    if any(path in payload for path in admin_paths):
        return "Admin Panel Probe"

    return "Suspicious Request"


# ════════════════════════════════════════
#  REQUEST HANDLERS
# ════════════════════════════════════════

class BaseHandler(tornado.web.RequestHandler):
    """Shared GET + POST handling for all honeypot endpoints."""

    async def handle_request(self, endpoint_type="general"):
        source_ip = self.request.headers.get(
            "X-Forwarded-For",
            self.request.remote_ip
        ).split(",")[0].strip()

        uri = self.request.uri
        ua = self.request.headers.get("User-Agent", "Unknown")
        method = self.request.method

        # Extract POST body if present
        post_body = None
        if method == "POST":
            try:
                post_body = self.request.body.decode("utf-8", errors="replace")[:2000]
            except Exception:
                post_body = "<binary>"

        event = classify_attack(uri, ua, post_body or "")
        geo   = await log_event(ip, event, uri, ua, method, post_body)

        # Throttled alert
        if should_send_alert(ip):
            send_alert(ip, uri, ua, geo, method, post_body)

        return event

    async def get(self):
        raise NotImplementedError

    async def post(self):
        raise NotImplementedError


class AttackHandler(BaseHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    
    async def get(self):
        event = await self.handle_request()
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "Attack Detected", "type": event}))

    async def post(self):
        event = await self.handle_request()
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "Attack Detected", "type": event}))


class FakeElasticsearchHandler(BaseHandler):
    
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    
    async def get(self):
        ip = self.request.headers.get(
            "X-Forwarded-For",
            self.request.remote_ip
        ).split(",")[0].strip()
        uri = self.request.uri
        ua  = self.request.headers.get("User-Agent", "Unknown")
        event = classify_attack(uri, ua)
        if event == "Suspicious Request":
            event = "Recon"
        geo = await log_event(ip, event, uri, ua, "GET")
        if should_send_alert(ip):
            send_alert(ip, uri, ua, geo)
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({
            "name": "elastic-prod-node-1",
            "cluster_name": "production-es-cluster",
            "cluster_uuid": "kJ8d9slPQr2xYz",
            "version": {
                "number": "7.10.0",
                "build_flavor": "default",
                "build_type": "docker"
            },
            "tagline": "You Know, for Search"
        }))

    async def post(self):
        await self.get()


# ── Fake Login / Credential Harvesting ──
class FakeLoginHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    
    """
    Serves a convincing Kibana-style login page.
    Any credentials submitted are captured and stored.
    """

    def get(self):
        ip = self.request.headers.get(
            "X-Forwarded-For",
            self.request.remote_ip
        ).split(",")[0].strip()
        ua = self.request.headers.get("User-Agent", "Unknown")
        # Log the probe
        tornado.ioloop.IOLoop.current().add_callback(
            log_event, ip, "Admin Panel Probe", self.request.uri, ua, "GET"
        )
        self.set_header("Content-Type", "text/html")
        self.write(FAKE_LOGIN_HTML)

    async def post(self):
        ip = self.request.headers.get(
            "X-Forwarded-For",
            self.request.remote_ip
        ).split(",")[0].strip()
        ua = self.request.headers.get("User-Agent", "Unknown")

        # Parse submitted credentials
        username = (self.get_body_argument("username", None)
                    or self.get_body_argument("user", None)
                    or self.get_body_argument("email", None)
                    or "<not provided>")
        password = (self.get_body_argument("password", None)
                    or self.get_body_argument("pass", None)
                    or self.get_body_argument("passwd", None)
                    or "<not provided>")

        geo = await geolocate_ip(ip)
        timestamp = datetime.datetime.now().isoformat()

        db_cursor.execute("""
            INSERT INTO harvested_credentials
            (timestamp, source_ip, username, password, endpoint, user_agent, country, city)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            timestamp, ip, username, password,
            self.request.uri, ua,
            geo.get("country") if geo else None,
            geo.get("city")    if geo else None,
        ))
        db_conn.commit()

        # Also log as an event
        await log_event(ip, "Credential Submission", self.request.uri, ua,
                        "POST", f"user={username}")

        print(f"🔑 Credentials harvested from {ip}: {username} / {password}")

        if should_send_alert(ip):
            send_alert(ip, self.request.uri, ua, geo, "POST",
                       f"username={username}&password={password}")

        # Return a fake "invalid credentials" response to keep attacker guessing
        self.set_header("Content-Type", "text/html")
        self.write(FAKE_LOGIN_HTML.replace(
            "<!--ERROR-->",
            '<div style="color:#ff4136;margin-bottom:12px;">Invalid username or password.</div>'
        ))


# ── Fake Login HTML (Kibana-style) ──
FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Kibana — Log in</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #1a1a2e; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px;
            padding: 40px 36px; width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
    .logo { text-align: center; margin-bottom: 28px; }
    .logo svg { width: 48px; height: 48px; }
    .logo h1 { color: #00b5d8; font-size: 22px; margin-top: 10px; letter-spacing: 1px; }
    label { display: block; color: #a0aec0; font-size: 12px; margin-bottom: 6px;
            text-transform: uppercase; letter-spacing: 1px; }
    input { width: 100%; background: #0f3460; border: 1px solid #2d4a7a; color: #e2e8f0;
            padding: 10px 14px; border-radius: 4px; font-size: 14px; margin-bottom: 18px; outline: none; }
    input:focus { border-color: #00b5d8; }
    button { width: 100%; background: #00b5d8; color: #fff; border: none;
             padding: 12px; border-radius: 4px; font-size: 15px; font-weight: 600;
             cursor: pointer; letter-spacing: 0.5px; }
    button:hover { background: #0097b5; }
    .footer { text-align: center; color: #4a5568; font-size: 11px; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="16" cy="16" r="15" stroke="#00b5d8" stroke-width="2"/>
        <path d="M8 16 Q16 8 24 16 Q16 24 8 16Z" fill="#00b5d8" opacity="0.6"/>
      </svg>
      <h1>Kibana</h1>
    </div>
    <!--ERROR-->
    <form method="POST">
      <label>Username</label>
      <input type="text" name="username" placeholder="elastic" autocomplete="off"/>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••"/>
      <button type="submit">Log in</button>
    </form>
    <div class="footer">Elastic Stack 7.10.0 &nbsp;·&nbsp; Kibana</div>
  </div>
</body>
</html>"""

class HealthHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"status": "ok"})

def make_app():
    return tornado.web.Application([
        (r"/health",        HealthHandler),
        (r"/",              FakeElasticsearchHandler),
        (r"/_cat/indices",  FakeElasticsearchHandler),
        (r"/_cluster/health",FakeElasticsearchHandler),
        (r"/_nodes",        FakeElasticsearchHandler),
        (r"/_mapping",      FakeElasticsearchHandler),
        (r"/_search",       AttackHandler),
        (r"/login",         FakeLoginHandler),
        (r"/kibana",        FakeLoginHandler),
        (r"/kibana/login",  FakeLoginHandler),
        (r"/app/kibana",    FakeLoginHandler),
        (r"/.*",            AttackHandler),   # catch-all
    ])

class FaviconHandler(tornado.web.RequestHandler):

    def get(self):
        self.set_status(204)
        self.finish()

if __name__ == "__main__":

    from monitor import DashboardHandler, StatsHandler, ExportHandler

    app = tornado.web.Application([

        # Health
        (r"/health", HealthHandler),

        # Honeypot
        (r"/", FakeElasticsearchHandler),
        (r"/_cat/indices", FakeElasticsearchHandler),
        (r"/_cluster/health", FakeElasticsearchHandler),
        (r"/_nodes", FakeElasticsearchHandler),
        (r"/_mapping", FakeElasticsearchHandler),
        (r"/_search", AttackHandler),

        # Fake logins
        (r"/login", FakeLoginHandler),
        (r"/kibana", FakeLoginHandler),
        (r"/kibana/login", FakeLoginHandler),
        (r"/app/kibana", FakeLoginHandler),

        # Dashboard
        (r"/dashboard", DashboardHandler),
        (r"/stats", StatsHandler),
        (r"/export", ExportHandler),
        
        (r"/favicon.ico", FaviconHandler),
        # Catch all
        (r"/.*", AttackHandler),
    ])

    app.listen(HONEYPOT_PORT)

    print(f"🍯 Delilah running on port {HONEYPOT_PORT}")

    tornado.ioloop.IOLoop.current().start()
