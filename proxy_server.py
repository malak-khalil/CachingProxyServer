import socket
import select
from proxy_logger import ProxyLogger
from proxy_cache import ProxyCache
from urllib.parse import urlsplit

# Configuration constants
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 10
#Talia: Initialize the logger and cache instances at the module level so they can be used across all client handlers.
logger = ProxyLogger("logs/proxy.log.jsonl")
cache = ProxyCache(default_ttl=60, max_entries=256)


# Send a simple HTTP error response
def send_error_response(client_socket, status_code, reason, body_text):
    body = body_text.encode("utf-8")
    response = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1") + body

    try:
        client_socket.sendall(response)
    except Exception:
        pass


# Read from socket until the end of HTTP headers: \r\n\r\n
def recv_until_header_end(sock):
    data = b""

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk

        # Safety limit for headers
        if len(data) > 65536:
            break

    return data


# Read exactly num_bytes bytes from a socket
def read_exact_bytes(sock, initial_data, num_bytes):
    data = initial_data

    while len(data) < num_bytes:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            return None
        data += chunk

    return data[:num_bytes]


# Read until the other side closes the socket
def read_until_socket_close(sock, initial_data):
    data = initial_data

    while True:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk

    return data


def read_chunked_body(sock, body_part):
    full_body = body_part
    decoded_body = b""

    while True:
        # Read until we have a full chunk-size line
        while b"\r\n" not in full_body:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                return None
            full_body += chunk

        line, full_body = full_body.split(b"\r\n", 1)

        try:
            chunk_size = int(line.decode("iso-8859-1").strip(), 16)
        except ValueError:
            return None

        # Last chunk
        if chunk_size == 0:
            # Read the final CRLF and any trailers
            while b"\r\n\r\n" not in full_body and full_body != b"\r\n":
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                full_body += chunk
            return decoded_body

        # Read until the whole chunk + trailing CRLF is present
        needed = chunk_size + 2
        while len(full_body) < needed:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                return None
            full_body += chunk

        decoded_body += full_body[:chunk_size]
        full_body = full_body[chunk_size + 2:]


# Read one full HTTP request:
# headers + body (if Content-Length exists)
def read_http_request(client_socket):
    initial_data = recv_until_header_end(client_socket)

    if not initial_data:
        return None

    header_end_index = initial_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        return None

    headers_part = initial_data[:header_end_index + 4]
    body_part = initial_data[header_end_index + 4:]

    try:
        headers_text = headers_part.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None

    lines = headers_text.split("\r\n")
    if len(lines) < 1 or not lines[0]:
        return None

    request_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = read_chunked_body(client_socket, body_part)
        if body is None:
            return None
        return request_line, headers, body

    content_length = 0
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"])
        except ValueError:
            content_length = 0

    body = read_exact_bytes(client_socket, body_part, content_length)
    if body is None:
        return None

    return request_line, headers, body


# Parse "host:port" authority string
# Used for CONNECT and Host header parsing
def parse_host_port(authority, default_port):
    authority = authority.strip()

    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = default_port
        return host, port

    return authority, default_port


# Parse the request line:
# method target version
# Example:
# GET http://example.com/index.html HTTP/1.1
# CONNECT example.com:443 HTTP/1.1
def parse_request_line(request_line):
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        return None, None, None
    method, target, version = parts
    return method.upper(), target, version


# For normal HTTP methods, determine:
# - remote host
# - remote port
# - path to send to origin server
def get_destination_for_http(target, headers):
    # HTTPS should use CONNECT, not normal HTTP forwarding
    if target.startswith("https://"):
        return None, None, None

    # Absolute-form URL
    if target.startswith("http://"):
        parsed = urlsplit(target)

        host = parsed.hostname
        if not host:
            return None, None, None

        port = parsed.port if parsed.port is not None else 80

        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += "?" + parsed.query

        return host, port, path

    # Origin-form path, destination comes from Host header
    host_header = headers.get("host")
    if not host_header:
        return None, None, None

    host, port = parse_host_port(host_header, 80)
    path = target if target else "/"

    return host, port, path


# Decide whether the client wants to keep the connection alive
def should_keep_alive_request(version, headers):
    connection_value = headers.get("connection", "").lower()

    if version == "HTTP/1.1":
        return connection_value != "close"

    if version == "HTTP/1.0":
        return connection_value == "keep-alive"

    return False


# Decide whether the origin server wants to keep the connection alive
def should_keep_alive_response(version, headers):
    connection_value = headers.get("connection", "").lower()

    if version == "HTTP/1.1":
        return connection_value != "close"

    if version == "HTTP/1.0":
        return connection_value == "keep-alive"

    return False


# Rebuild an HTTP request before forwarding it
# Important:
# - origin server usually wants path only, not full URL
# - remove proxy-specific headers
# - keep Connection: keep-alive for persistent HTTP
def build_forward_request(method, path, version, headers, body, host, port):
    new_headers = dict(headers)

    if "proxy-connection" in new_headers:
        del new_headers["proxy-connection"]
    if "connection" in new_headers:
        del new_headers["connection"]
    if "keep-alive" in new_headers:
        del new_headers["keep-alive"]
    if "transfer-encoding" in new_headers:
        del new_headers["transfer-encoding"]
    if "te" in new_headers:
        del new_headers["te"]
    if "trailer" in new_headers:
        del new_headers["trailer"]
    if "upgrade" in new_headers:
        del new_headers["upgrade"]

    new_headers["connection"] = "keep-alive"
    new_headers["content-length"] = str(len(body))
    new_headers["host"] = host if port == 80 else f"{host}:{port}"

    request_line = f"{method} {path} {version}\r\n"

    header_lines = ""
    for name, value in new_headers.items():
        header_lines += f"{name}: {value}\r\n"

    raw_request = (request_line + header_lines + "\r\n").encode("iso-8859-1") + body
    return raw_request


# Determine whether an HTTP response is supposed to have a body
def response_has_body(request_method, status_code):
    if request_method == "HEAD":
        return False

    if 100 <= status_code < 200:
        return False

    if status_code in (204, 304):
        return False

    return True


# Read one full HTTP response from the origin server
def read_http_response(remote_socket, request_method):
    initial_data = recv_until_header_end(remote_socket)

    if not initial_data:
        return None, None, None, False, None

    header_end_index = initial_data.find(b"\r\n\r\n")
    if header_end_index == -1:
        return None, None, None, False, None

    headers_part = initial_data[:header_end_index + 4]
    body_part = initial_data[header_end_index + 4:]

    try:
        headers_text = headers_part.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None, None, None, False, None

    lines = headers_text.split("\r\n")
    if len(lines) < 1 or not lines[0]:
        return None, None, None, False, None

    status_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if line == "":
            break
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
        transfer_encoding = headers.get("transfer-encoding", "").lower()

        if "chunked" in transfer_encoding:
            body = read_chunked_body(remote_socket, body_part)
            if body is None:
                return None, None, None, False, None

        elif "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError:
                content_length = 0

            body = read_exact_bytes(remote_socket, body_part, content_length)
            if body is None:
                return None, None, None, False, None

        else:
            body_ends_on_close = True
            body = read_until_socket_close(remote_socket, body_part)

    origin_keep_alive = should_keep_alive_response(response_version, headers)
    if body_ends_on_close:
        origin_keep_alive = False

    return status_line, headers, body, origin_keep_alive, status_code


# Build the HTTP response that will be sent back to the client
def build_client_response(status_line, headers, body, client_keep_alive, request_method, status_code):
    new_headers = dict(headers)

    if "connection" in new_headers:
        del new_headers["connection"]
    if "keep-alive" in new_headers:
        del new_headers["keep-alive"]
    if "proxy-connection" in new_headers:
        del new_headers["proxy-connection"]
    if "transfer-encoding" in new_headers:
        del new_headers["transfer-encoding"]
    if "te" in new_headers:
        del new_headers["te"]
    if "trailer" in new_headers:
        del new_headers["trailer"]
    if "upgrade" in new_headers:
        del new_headers["upgrade"]

    if response_has_body(request_method, status_code):
        new_headers["content-length"] = str(len(body))
    else:
        if "content-length" not in new_headers:
            new_headers["content-length"] = str(len(body))

    if client_keep_alive:
        new_headers["connection"] = "keep-alive"
    else:
        new_headers["connection"] = "close"

    response_text = status_line + "\r\n"
    for name, value in new_headers.items():
        response_text += f"{name}: {value}\r\n"
    response_text += "\r\n"

    return response_text.encode("iso-8859-1") + body


# Close one origin socket from the connection table
def close_origin_socket(origin_connections, key):
    remote_socket = origin_connections.pop(key, None)
    if remote_socket:
        try:
            remote_socket.close()
        except Exception:
            pass


# Handle a normal HTTP request:
# browser -> proxy -> target server -> proxy -> browser
def handle_http_request(client_socket, client_address, method, target, version, headers, body, origin_connections):
    host, port, path = get_destination_for_http(target, headers)
    client_ip, client_port = client_address


    if not host:
        send_error_response(client_socket, 400, "Bad Request", "Could not determine target host.")
        return True
    
    #Talia: Log the incoming HTTP request before processing it
    logger.log_request(client_ip, client_port, host, port, method, target)

    client_keep_alive = should_keep_alive_request(version, headers)
    forward_request = build_forward_request(method, path, version, headers, body, host, port)

    #Talia: Check the cache for a valid entry before contacting the origin server.
    cache_status = "BYPASS"

    if cache.should_cache_request(method):
        cache_key = cache.build_cache_key(method, host, port, path)
        cache_entry = cache.get(cache_key)

        if cache_entry is not None:
            logger.log_cache_event("cache_hit", target, host, port, "Served from cache")

            client_socket.sendall(cache_entry.response_bytes)

            logger.log_response(
                client_ip,
                client_port,
                host,
                port,
                method,
                target,
                cache_entry.status_code,
                "HIT",
                "HTTP response sent from cache"
            )

            return not client_keep_alive
        else:
            cache_status = "MISS"
            logger.log_cache_event("cache_miss", target, host, port, "Fetching from origin")

    connection_key = (host, port)

    # Retry once with a fresh origin connection if a reused socket is stale
    for attempt in range(2):
        remote_socket = origin_connections.get(connection_key)

        if remote_socket is None:
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(SOCKET_TIMEOUT)
                remote_socket.connect((host, port))
                origin_connections[connection_key] = remote_socket
            except Exception:
                send_error_response(client_socket, 502, "Bad Gateway", f"Error contacting {host}:{port}")
                return True

        try:
            
            remote_socket.sendall(forward_request)

            status_line, response_headers, response_body, origin_keep_alive, status_code = read_http_response(
                remote_socket, method
            )

            if status_line is None:
                raise RuntimeError("Invalid response from origin server")

            response_bytes = build_client_response(
                status_line,
                response_headers,
                response_body,
                client_keep_alive,
                method,
                status_code
            )

           #Talia: If the response is cacheable, store it in the cache before sending it to the client. 
            if cache.should_cache_request(method):
                stored = cache.put(cache_key, response_bytes)
                if stored:
                    logger.log_cache_event("cache_store", target, host, port, "Stored response in cache")
                    
            client_socket.sendall(response_bytes)

            #Talia: Log the response status after sending it.
            logger.log_response(
                client_ip,
                client_port,
                host,
                port,
                method,
                target,
                status_code,
                cache_status,
                "HTTP response sent to client"
            )

            if not origin_keep_alive:
                close_origin_socket(origin_connections, connection_key)

            return not client_keep_alive

        except Exception as e:
            #Talia: Log any errors that occur during the HTTP handling process, including details about the client and target server.
            logger.log_error(
                message="HTTP handling failed",
                error=str(e),
                client_ip=client_ip,
                client_port=client_port,
                target_host=host,
                target_port=port,
                method=method,
                url=target
            )
            close_origin_socket(origin_connections, connection_key)

            if attempt == 1:
                send_error_response(client_socket, 502, "Bad Gateway", f"Error contacting {host}:{port}")
                return True

    return True


# Tunnel bytes in both directions
# Used for HTTPS CONNECT
# No decryption happens here.
def tunnel_data(client_socket, remote_socket):
    sockets = [client_socket, remote_socket]

    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, SOCKET_TIMEOUT)

        if exceptional:
            break

        if not readable:
            break

        for sock in readable:
            try:
                data = sock.recv(BUFFER_SIZE)
            except Exception:
                return

            if not data:
                return

            if sock is client_socket:
                remote_socket.sendall(data)
            else:
                client_socket.sendall(data)


# Handle CONNECT method for HTTPS
#
# Steps:
# 1) Parse host:port
# 2) Connect to remote server
# 3) Return 200 Connection Established
# 4) Tunnel raw bytes in both directions
def handle_connect_tunnel(client_socket, client_address, target):
    host, port = parse_host_port(target, 443)

    remote_socket = None
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(SOCKET_TIMEOUT)
        remote_socket.connect((host, port))

        response = (
            "HTTP/1.1 200 Connection Established\r\n"
            "\r\n"
        ).encode("iso-8859-1")
        client_socket.sendall(response)

        #Talia: Log the successful establishment of the HTTPS tunnel, including client and target details.
        logger.log_https_event(
            event="https_tunnel_started",
            client_ip=client_address[0],
            client_port=client_address[1],
            target_host=host,
            target_port=port,
            message="CONNECT tunnel established successfully"
        )

        # After this point TLS handshake is between browser and destination server.
        # Proxy only copies encrypted bytes.
        tunnel_data(client_socket, remote_socket)

    except Exception as e:
        #Talia: Log any errors that occur during the CONNECT handling process, including details about the client, target server, and the error message.
        logger.log_error(
            message="HTTPS tunnel failed",
            error=str(e),
            client_ip=client_address[0],
            client_port=client_address[1],
            target_host=host,
            target_port=port,
            method="CONNECT",
            url=target
        )
        send_error_response(client_socket, 502, "Bad Gateway", f"Could not open tunnel to {host}:{port}")
    finally:
        #Talia: Log the closure of the HTTPS tunnel, including client and target details.
        logger.log_https_event(
            event="https_tunnel_closed",
            client_ip=client_address[0],
            client_port=client_address[1],
            target_host=host,
            target_port=port,
            message="CONNECT tunnel closed"
        )

        if remote_socket:
            remote_socket.close()


# Handle one connected client
def handle_client(client_socket, client_address):
    origin_connections = {}

    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        while True:
            request = read_http_request(client_socket)
            if request is None:
                break

            request_line, headers, body = request
            method, target, version = parse_request_line(request_line)

            if not method or not target or not version:
                send_error_response(client_socket, 400, "Bad Request", "Invalid request line.")
                break

            # HTTPS in normal URL form should not be forwarded as plain HTTP
            if method != "CONNECT" and target.startswith("https://"):
                send_error_response(client_socket, 400, "Bad Request", "HTTPS requests must use CONNECT.")
                break

            if method == "CONNECT":
                handle_connect_tunnel(client_socket, client_address, target)
                break

            close_client = handle_http_request(
                client_socket,
                client_address,
                method,
                target,
                version,
                headers,
                body,
                origin_connections
            )

            if close_client:
                break

    except Exception as e:
        #Talia: Log any exceptions that occur during client handling, including details about the client and the error message.
        logger.log_error(
            message="Client handling failed",
            error=str(e),
            client_ip=client_address[0],
            client_port=client_address[1]
        )
        try:
            send_error_response(client_socket, 500, "Internal Server Error", "Proxy internal error.")
        except Exception:
            pass
    finally:
        for key in list(origin_connections.keys()):
            close_origin_socket(origin_connections, key)
        client_socket.close()


# Start proxy server
def start_proxy():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(50)

    while True:
        client_socket, client_address = server_socket.accept()
        handle_client(client_socket, client_address)


if __name__ == "__main__":
    start_proxy()