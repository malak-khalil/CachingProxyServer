import socket
import select
import threading
import datetime
import json
from urllib.parse import urlsplit


from proxy_logger import ProxyLogger   # Talia's logging module
from proxy_cache import ProxyCache      # Talia's caching module
from https_tunnel import handle_https_connect  # Talia's HTTPS tunnel module


#  CONFIGURATION 
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 10

# PART G: BLACKLIST (Aya)
# List of domains to block. The proxy will return 403 Forbidden for any request
# whose target host contains any of these strings (case‑insensitive check is not performed here,
# but the comparison uses "site in host" which is case‑sensitive. For simplicity we keep
# lowercase entries. In a production system we would normalise case.)
BLACKLIST = ["example.com", "facebook.com", "bad-website.com"]

# PART I: ADMIN STATS (Aya)
stats = {
    "start_time": datetime.datetime.now(),
    "total_requests": 0,    # total HTTP + CONNECT requests processed
    "blocked_requests": 0   # requests blocked by blacklist
}

# Initialise Talia's modules
logger = ProxyLogger("logs/proxy.log.jsonl")  # Part E: structured logging
cache = ProxyCache(default_ttl=60, max_entries=256) # Part F: in‑memory cache

# Malak's part: Sends a simple HTTP error response back to the client.
# It builds the response with status line, headers, and body, then sends it through the client socket.
def send_error_response(client_socket, status_code, reason, body_text):
    body = body_text.encode("utf-8")
    response = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body
    try:
        client_socket.sendall(response)
    except Exception: pass


# Malak's part: Reads data from the socket until the end of the HTTP headers is reached.
# This is used to separate the request/response headers from the message body.
def recv_until_header_end(sock):
    """
    Receives data from a socket until the end of HTTP headers (\r\n\r\n) is found.
    Returns the raw bytes received (including the final \r\n\r\n).
    """
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk: break
            data += chunk
            if len(data) > 65536: break  # safety limit for header size
        except: break
    return data

# Malak's part: Reads an exact number of bytes from the socket.
# It is used when the HTTP body size is known from the Content-Length header.
def read_exact_bytes(sock, initial_data, num_bytes):
    """
    Reads exactly `num_bytes` bytes from a socket, starting with `initial_data`.
    Returns None if the socket closes prematurely.
    """
    data = initial_data
    while len(data) < num_bytes:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk: return None
        data += chunk
    return data[:num_bytes]

# Malak's part: Reads data from the socket until the other side closes the connection.
# This is useful when a response body ends by connection close instead of a length header.
def read_until_socket_close(sock, initial_data):
    """
    Reads all remaining data from a socket until the peer closes the connection.
    Used when no Content-Length or Transfer-Encoding is present (response body ends on close).
    """
    data = initial_data
    while True:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk: break
        data += chunk
    return data

# Malak's part: Reads and decodes a chunked HTTP body.
# It processes each chunk size, reads the chunk data, and rebuilds the full body correctly.
def read_chunked_body(sock, body_part):
    """
    Parses and reads a chunked HTTP body from a socket.
    `body_part` is the initial data already read. Returns the complete decoded body as bytes.
    """
    full_body = body_part
    decoded_body = b""
    while True:
        # Ensure we have a full line for chunk size
        while b"\r\n" not in full_body:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk: return None
            full_body += chunk
        line, full_body = full_body.split(b"\r\n", 1)
        try:
            chunk_size = int(line.decode("iso-8859-1").strip(), 16)
        except ValueError: return None
        # last chunk (size 0)
        if chunk_size == 0:
             # read any trailing headers until final CRLF
            while b"\r\n\r\n" not in full_body and full_body != b"\r\n":
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk: break
                full_body += chunk
            return decoded_body
        needed = chunk_size + 2  # chunk data + trailing CRLF
        while len(full_body) < needed:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk: return None
            full_body += chunk
        decoded_body += full_body[:chunk_size]
        full_body = full_body[chunk_size + 2:]

# Malak's part: Reads a complete HTTP request from the client socket.
# It parses the request line, headers, and body, supporting both Content-Length and chunked encoding.
def read_http_request(client_socket):
    """
    Reads a complete HTTP request from the client socket.
    Returns (request_line, headers_dict, body_bytes) or None if error.
    Handles chunked encoding and Content-Length.
    """
    initial_data = recv_until_header_end(client_socket)
    if not initial_data: return None
    header_end_index = initial_data.find(b"\r\n\r\n")
    if header_end_index == -1: return None
    headers_part = initial_data[:header_end_index + 4]
    body_part = initial_data[header_end_index + 4:]
    try:
        headers_text = headers_part.decode("iso-8859-1")
    except: return None
    lines = headers_text.split("\r\n")
    if len(lines) < 1 or not lines[0]: return None
    request_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = read_chunked_body(client_socket, body_part)
        if body is None: return None
        return request_line, headers, body

    content_length_value = headers.get("content-length", "0")
    try:
        content_length = int(content_length_value)
    except ValueError:
        return None

    if content_length < 0:
        return None

    body = read_exact_bytes(client_socket, body_part, content_length)
    if body is None: return None
    return request_line, headers, body

# Malak's part: Splits a host:port string into host and port values.
# If no port is given, it uses the provided default port.
def parse_host_port(authority, default_port):
    """
    Parses a string like "example.com:80" into (host, port).
    If no port is present, returns default_port.
    """
    authority = authority.strip()
    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return None, None
        if port < 1 or port > 65535:
            return None, None
        return host, port
    return authority, default_port


# Malak's part: Parses the HTTP request line into method, target, and version.
# This helps the proxy understand what the client is requesting.
def parse_request_line(request_line):
    """
    Splits a request line into (method, target, version).
    Example: "GET http://example.com/ HTTP/1.1" -> ("GET", "http://example.com/", "HTTP/1.1")
    """
    parts = request_line.split(" ", 2)
    if len(parts) != 3: return None, None, None
    return parts[0].upper(), parts[1], parts[2]

# Malak's part: Determines the destination server and path for a normal HTTP request.
# It supports both absolute URLs and origin-form requests that rely on the Host header.
def get_destination_for_http(target, headers):
    """
    Determines the origin server (host, port) and the path to forward.
    Supports absolute-URL (http://...) and origin-form (using Host header).
    Returns (host, port, path) or (None, None, None) if invalid.
    """
    if target.startswith("https://"): return None, None, None  # HTTPS must use CONNECT
    if target.startswith("http://"):
        parsed = urlsplit(target)
        host = parsed.hostname
        if not host: return None, None, None
        port = parsed.port if parsed.port is not None else 80
        path = (parsed.path if parsed.path else "/") + (f"?{parsed.query}" if parsed.query else "")
        return host, port, path
    # origin-form: path only, host comes from Host header
    host_header = headers.get("host")
    if not host_header: return None, None, None
    host, port = parse_host_port(host_header, 80)
    if host is None or port is None: return None, None, None
    return host, port, target


# Malak's part: Checks whether the client wants a persistent HTTP connection.
# It uses the HTTP version and Connection header to decide if the socket should stay open.
def should_keep_alive_request(version, headers):
    """Determines if the client requested a persistent connection."""
    connection_value = headers.get("connection", "").lower()
    return connection_value != "close" if version == "HTTP/1.1" else connection_value == "keep-alive"

# Malak's part: Checks whether the origin server wants to keep the connection alive.
# This helps the proxy decide whether it can reuse the server-side socket.
def should_keep_alive_response(version, headers):
    """Determines if the origin server wants a persistent connection."""
    connection_value = headers.get("connection", "").lower()
    return connection_value != "close" if version == "HTTP/1.1" else connection_value == "keep-alive"

# Malak's part: Rebuilds the HTTP request before forwarding it to the origin server.
# It removes proxy-specific headers and adds the correct Host and Connection headers.
def build_forward_request(method, path, version, headers, body, host, port):
    """
    Rebuilds the HTTP request to be sent to the origin server.
    Removes proxy-specific headers and adds a proper Host header.
    """
    new_headers = dict(headers)
    # Remove headers that should not be forwarded
    for h in ["proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"]:
        if h in new_headers: del new_headers[h]
    new_headers["connection"] = "keep-alive"
    new_headers["content-length"] = str(len(body))
    new_headers["host"] = host if port == 80 else f"{host}:{port}"
    raw = f"{method} {path} {version}\r\n"
    for name, value in new_headers.items(): raw += f"{name}: {value}\r\n"
    return (raw + "\r\n").encode("iso-8859-1") + body

# Malak's part: Decides whether an HTTP response is expected to contain a body.
# This depends on the request method and the response status code.
def response_has_body(request_method, status_code):
    """Returns True if the HTTP response is expected to have a body."""
    if request_method == "HEAD": return False
    if 100 <= status_code < 200 or status_code in (204, 304): return False
    return True

# Malak's part: Reads a full HTTP response from the origin server.
# It parses the status line, headers, and body, and also determines keep-alive behavior.
def read_http_response(remote_socket, request_method):
    """
    Reads a complete HTTP response from the origin server.
    Returns (status_line, headers_dict, body_bytes, keep_alive_flag, status_code)
    """
    initial_data = recv_until_header_end(remote_socket)
    if not initial_data: return None, None, None, False, None
    header_end_index = initial_data.find(b"\r\n\r\n")
    if header_end_index == -1: return None, None, None, False, None
    headers_part = initial_data[:header_end_index + 4]
    body_part = initial_data[header_end_index + 4:]

    try:
        headers_text = headers_part.decode("iso-8859-1")
    except:
        return None, None, None, False, None

    lines = headers_text.split("\r\n")
    if len(lines) < 1 or not lines[0]:
        return None, None, None, False, None

    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        return None, None, None, False, None

    response_version = parts[0]
    try:
        status_code = int(parts[1])
    except ValueError:
        return None, None, None, False, None

    body = b""
    body_ends_on_close = False
    if response_has_body(request_method, status_code):
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = read_chunked_body(remote_socket, body_part)
            if body is None: return None, None, None, False, None
        elif "content-length" in headers:
            try:
                response_length = int(headers["content-length"])
            except ValueError:
                return None, None, None, False, None
            if response_length < 0:
                return None, None, None, False, None
            body = read_exact_bytes(remote_socket, body_part, response_length)
            if body is None: return None, None, None, False, None
        else:
            body_ends_on_close = True
            body = read_until_socket_close(remote_socket, body_part)

    keep_alive = should_keep_alive_response(response_version, headers) and not body_ends_on_close
    return status_line, headers, body, keep_alive, status_code


# Malak's part: Builds the final HTTP response that will be sent back to the client.
# It adjusts headers like Content-Length and Connection before sending the response.
def build_client_response(status_line, headers, body, client_keep_alive, request_method, status_code):
    """
    Builds the HTTP response to send back to the client.
    Adjusts headers and ensures correct Content-Length.
    """
    new_headers = dict(headers)
    # Remove headers that are only meaningful for the proxy–origin connection
    for h in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade"]:
        if h in new_headers: del new_headers[h]
    new_headers["content-length"] = str(len(body))
    new_headers["connection"] = "keep-alive" if client_keep_alive else "close"
    res = status_line + "\r\n"
    for name, value in new_headers.items(): res += f"{name}: {value}\r\n"
    return (res + "\r\n").encode("iso-8859-1") + body


# Malak's part: Rebuilds a cached HTTP response so the Connection header matches the current client.
# This keeps cache hits correct for both keep-alive and close requests.
def adapt_cached_response_for_client(response_bytes, client_keep_alive):
    try:
        header_end_index = response_bytes.find(b"\r\n\r\n")
        if header_end_index == -1:
            return response_bytes

        headers_part = response_bytes[:header_end_index + 4]
        body = response_bytes[header_end_index + 4:]

        headers_text = headers_part.decode("iso-8859-1")
        lines = headers_text.split("\r\n")
        if len(lines) < 1 or not lines[0]:
            return response_bytes

        status_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        for h in ["connection", "keep-alive", "proxy-connection"]:
            if h in headers: del headers[h]

        headers["content-length"] = str(len(body))
        headers["connection"] = "keep-alive" if client_keep_alive else "close"

        res = status_line + "\r\n"
        for name, value in headers.items():
            res += f"{name}: {value}\r\n"
        return (res + "\r\n").encode("iso-8859-1") + body
    except Exception:
        return response_bytes
    

# Malak's part: Closes and removes one saved origin-server socket from the connection pool.
# This is used when the proxy can no longer reuse that server connection.
def close_origin_socket(origin_connections, key):
    sock = origin_connections.pop(key, None)
    if sock: sock.close()

# PART I: ADMIN INTERFACE (Aya)
def serve_admin_interface(client_socket, target_url):
    """
    Handles requests to the virtual domain proxy.admin.
    Displays statistics, cache info, live logs, and allows adding/removing blacklist entries.
    """
    global BLACKLIST
    # Parse add/remove commands from URL
    if "/add?site=" in target_url:
        new_site = target_url.split("site=")[1].split(" ")[0]
        if new_site not in BLACKLIST: BLACKLIST.append(new_site)
    elif "/remove?site=" in target_url:
        old_site = target_url.split("site=")[1].split(" ")[0]
        if old_site in BLACKLIST: BLACKLIST.remove(old_site)

    uptime = datetime.datetime.now() - stats["start_time"]
    c_stats = cache.stats()
    
    # Read last 10 log lines from the log file (Talia's logger)
    logs_display = ""
    try:
        with open("logs/proxy.log.jsonl", "r") as f:
            lines = f.readlines()
            for l in lines[-10:]:
                d = json.loads(l)
                logs_display += f"[{d.get('timestamp','')[-13:-7]}] {d.get('event')} -> {d.get('url','')[:50]}<br>"
    except: logs_display = "No logs yet."

    html = f"""
    <html><head><style>
        body {{ font-family: sans-serif; background: #f4f7f6; padding: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .stat-box {{ background: #003a70; color: white; padding: 10px; border-radius: 5px; display: inline-block; margin-right: 10px; }}
        .log-view {{ background: #2d2d2d; color: #00ff00; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 11px; }}
    </style></head><body>
    <div class="card"><h1>LAU Proxy Admin Dashboard</h1>
        <p>Uptime: {uptime} | Active Threads: {threading.active_count()}</p>
        <div class="stat-box">Total Req: {stats['total_requests']}</div>
        <div class="stat-box">Blocked: {stats['blocked_requests']}</div>
        <div class="stat-box">Cache Entries: {c_stats['entries']}</div>
    </div>
    <div class="card"><h3>Manage Blacklist</h3>
        <ul>{"".join([f"<li>{s} <a href='http://proxy.admin/remove?site={s}'>[Delete]</a></li>" for s in BLACKLIST])}</ul>
    </div>
    <div class="card"><h3>Live Logs </h3><div class="log-view">{logs_display}</div></div>
    </body></html>"""
    send_error_response(client_socket, 200, "OK", html)


# Malak's part (contains some integrations of Talia and Aya): Core HTTP proxy forwarding logic.
# This function gets the destination server, forwards the request, reads the response, and sends it back to the client.
def handle_http_request(client_socket, client_address, method, target, version, headers, body, origin_connections):
    """
    Processes a normal HTTP request (non-CONNECT).
    - Extracts destination.
    - Applies blacklist (Aya).
    - Attempts cache lookup (Talia).
    - Forwards request to origin (Malak).
    - Stores response in cache if cacheable.
    - Logs all actions (Talia).
    """
    host, port, path = get_destination_for_http(target, headers)
    client_ip, client_port = client_address
    client_keep_alive = should_keep_alive_request(version, headers)

    if not host:
        send_error_response(client_socket, 400, "Bad Request", "Invalid Host.")
        return True

    # Part G: Blacklist check (Aya)
    # Note: Simple substring match; can be made case-insensitive by converting to lower.
    if any(site in host.lower() for site in BLACKLIST):
        stats["blocked_requests"] += 1
        logger.log_error("Blocked by Blacklist", "Forbidden", client_ip, client_port, host, port, method, target)
        send_error_response(client_socket, 403, "Forbidden", "<h1>Access Denied</h1><p>Blacklisted site.</p>")
        return True

    # Part F: Cache lookup (Talia)
    cache_key = cache.build_cache_key(method, host, port, path)
    if cache.should_cache_request(method):
        entry = cache.get(cache_key)
        if entry:
            logger.log_cache_event("cache_hit", target, host, port, "Served from Cache")
            client_socket.sendall(adapt_cached_response_for_client(entry.response_bytes, client_keep_alive))
            return not client_keep_alive

    # Part E: Log the request (Talia)
    logger.log_request(client_ip, client_port, host, port, method, target)

     # Forward request to origin (Malak + Talia's helper functions)
    conn_key = (host, port)
    for attempt in range(2):  # one retry with a fresh socket
        remote_socket = origin_connections.get(conn_key)
        if remote_socket is None:
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(SOCKET_TIMEOUT)
                remote_socket.connect((host, port))
                origin_connections[conn_key] = remote_socket
            except:
                send_error_response(client_socket, 502, "Bad Gateway", "Host unreachable")
                return True
        try:
            remote_socket.sendall(build_forward_request(method, path, version, headers, body, host, port))
            status_line, res_headers, res_body, o_ka, status_code = read_http_response(remote_socket, method)
            if status_line is None:
                raise RuntimeError("Invalid response from origin server")

            res_bytes = build_client_response(status_line, res_headers, res_body, client_keep_alive, method, status_code)

            # Part F: Store in cache (Talia)
            if cache.should_cache_request(method):
                cache.put(cache_key, build_client_response(status_line, res_headers, res_body, True, method, status_code))

            client_socket.sendall(res_bytes)
            logger.log_response(client_ip, client_port, host, port, method, target, status_code)
            if not o_ka: close_origin_socket(origin_connections, conn_key)
            return not client_keep_alive
        except:
            close_origin_socket(origin_connections, conn_key)

    send_error_response(client_socket, 502, "Bad Gateway", "Host unreachable")
    return True

# Malak's part: Core client-connection handler for normal proxy operation.
# It reads requests in a loop, parses them, and dispatches normal HTTP requests to the forwarding function.
def handle_client(client_socket, client_address):
    """
    Handles one client connection.
    Reads requests in a loop, processing HTTP and CONNECT methods.
    Maintains a pool of persistent origin connections.
    """
    origin_connections = {}
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)
        while True:
            req = read_http_request(client_socket)
            if not req: break
            line, headers, body = req
            method, target, version = parse_request_line(line)

            # Part I: intercept admin interface requests (virtual domain)
            if "proxy.admin" in target:
                serve_admin_interface(client_socket, target)
                break
            
            stats["total_requests"] += 1

            if method == "CONNECT":
                # Part H: HTTPS tunnel (Talia)
                connect_host, connect_port = parse_host_port(target, 443)
                if connect_host is None or connect_port is None:
                    send_error_response(client_socket, 400, "Bad Request", "Invalid CONNECT target.")
                    break
                handle_https_connect(client_socket, client_address, connect_host, connect_port, logger=logger)
                break
            
            if handle_http_request(client_socket, client_address, method, target, version, headers, body, origin_connections):
                break
    except Exception:
        try:
            send_error_response(client_socket, 500, "Internal Server Error", "Proxy internal error.")
        except Exception:
            pass
    finally:
        for k in list(origin_connections.keys()): close_origin_socket(origin_connections, k)
        client_socket.close()

        
# PART B + D: MULTITHREADING SERVER (B: Malak, D: Aya)
def start_proxy():
    """
    Starts the proxy server, listening on LISTEN_HOST:LISTEN_PORT.
    Accepts connections and spawns a new thread for each client.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(100)
    print(f"[*] LAU Proxy LIVE on {LISTEN_HOST}:{LISTEN_PORT}")
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

if __name__ == "__main__":
    start_proxy()