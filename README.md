# CachingProxyServer
## Overview
A multithreaded HTTP/HTTPS proxy server with content caching, blacklisting, and an admin web interface.  
## Team Members & Contributions
| Member | Requirements |
|--------|--------------|
| **Aya** | Multithreading (D), Blacklist/Whitelist (G), Admin Interface (I), testing |
| **Talia** | Logging (E), Content Caching (F), HTTPS Tunnel (H) |
| **Malak** | Basic forwarding (A), Socket programming (B), Request parsing (C), testing |
## Features – Complete (A–I, including bonuses)
| ID | Requirement | Implemented |
|----|-------------|--------------|
| A  | Forward HTTP & HTTPS (CONNECT) requests | ✅ |
| B  | Socket programming (`socket`, `select`) | ✅ |
| C  | Parse request line, headers, body, chunked encoding | ✅ |
| D  | Multithreading – one thread per client | ✅ |
| E  | Structured JSON logging to file | ✅ |
| F  | In‑memory cache with expiry (Cache‑Control, Expires, TTL) | ✅ |
| G  | Blacklist – block domains with 403 error | ✅ |
| H  | HTTPS tunnel (CONNECT, no decryption) – **bonus** | ✅ |
| I  | Admin web interface – **bonus** | ✅ |
## Getting Started

### Prerequisites
- Python 3.8 or higher
- No external libraries required (uses only standard library)
### Installation
1. Clone or download all files into a folder:
   - `proxy_server.py` (main server)
   - `proxy_logger.py`
   - `proxy_cache.py`
   - `https_tunnel.py`
2. (Optional) Create an empty `logs/` folder – the logger will create it automatically.
### Running the Proxy
Open a terminal in the project folder and run:
python proxy_server.py
You should see:
[*] LAU Proxy LIVE on 127.0.0.1:8888
[*] Admin Dashboard: http://proxy.admin
Configuring Your Browser
Set your browser’s HTTP/HTTPS proxy to:
Address: 127.0.0.1
Port: 8888
Important: After testing, disable the proxy to restore normal internet access.
Testing the Features
1. Basic Proxy & Multithreading (A, D)
Open two browser tabs (or two terminals with curl).
In each, load http://httpbin.org/delay/3 (delayed response).
Expected: Both tabs finish loading at the same time (~3 seconds), not one after the other.
2. Admin Interface (I)
While the proxy is running, visit http://proxy.admin in your browser (proxy must be enabled).
You will see a dashboard with:
Uptime, active threads, total requests, blocked requests, cache entries.
List of blacklisted domains (with delete links).
Live logs showing recent events.
3. Blacklist / Whitelist (G)
Block a domain:
Visit http://proxy.admin/add?site=test-block.com (or use the dashboard).
Then try to open http://test-block.com – you should get a 403 Access Denied page.
Unblock a domain:
Click the [Delete] link next to the domain on the dashboard, or visit http://proxy.admin/remove?site=test-block.com.
Check stats:
After each blocked request, the “Blocked” counter on the dashboard increases.
4. Content Caching (F)
Make the same HTTP GET request twice (e.g., http://example.com).
First request: logs show cache_miss, then cache_store.
Second request: logs show cache_hit. Dashboard “Cache Entries” increases.
5. Logging (E)
All events are written to logs/proxy.log.jsonl as one JSON object per line.
You can view the last 10 logs directly on the admin dashboard.
6. HTTPS Tunnel (H)
Visit any HTTPS website (e.g., https://google.com).
The proxy will establish a CONNECT tunnel and relay encrypted bytes.
Logs show https_tunnel_started and https_tunnel_closed.
