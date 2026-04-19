import socket
import select
from urllib.parse import urlsplit

# Configuration constants
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 10


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
            headers[name.strip()] = value.strip()

    content_length = 0
    if "Content-Length" in headers:
        try:
            content_length = int(headers["Content-Length"])
        except ValueError:
            content_length = 0

    # If body is incomplete, keep reading
    while len(body_part) < content_length:
        chunk = client_socket.recv(BUFFER_SIZE)
        if not chunk:
            break
        body_part += chunk

    return request_line, headers, body_part[:content_length]


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
    # Case 1: absolute-form URL from browser/proxy-aware client
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)

        host = parsed.hostname
        if not host:
            return None, None, None

        if parsed.port is not None:
            port = parsed.port
        else:
            port = 80 if parsed.scheme == "http" else 443

        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += "?" + parsed.query

        return host, port, path

    # Case 2: origin-form path, so Host header must tell us destination
    host_header = headers.get("Host")
    if not host_header:
        return None, None, None

    host, port = parse_host_port(host_header, 80)
    path = target if target else "/"

    return host, port, path



# Rebuild an HTTP request before forwarding it
# Important:
# - origin server usually wants path only, not full URL
# - remove proxy-specific headers
# - simplify with Connection: close
def build_forward_request(method, path, version, headers, body, host, port):
    new_headers = dict(headers)

    # Remove proxy-specific / connection-management headers
    if "Proxy-Connection" in new_headers:
        del new_headers["Proxy-Connection"]
    if "Connection" in new_headers:
        del new_headers["Connection"]
    if "Keep-Alive" in new_headers:
        del new_headers["Keep-Alive"]

    # Force a simpler one-request-per-connection behavior
    new_headers["Connection"] = "close"

    # Make sure Host header exists
    if port == 80:
        new_headers["Host"] = host
    else:
        new_headers["Host"] = f"{host}:{port}"

    request_line = f"{method} {path} {version}\r\n"

    header_lines = ""
    for name, value in new_headers.items():
        header_lines += f"{name}: {value}\r\n"

    raw_request = (request_line + header_lines + "\r\n").encode("iso-8859-1") + body
    return raw_request


# Relay all response bytes from remote server to client
# Used for normal HTTP
def relay_http_response(remote_socket, client_socket):
    while True:
        data = remote_socket.recv(BUFFER_SIZE)
        if not data:
            break
        client_socket.sendall(data)


# Handle a normal HTTP request:
# browser -> proxy -> target server -> proxy -> browser
def handle_http_request(client_socket, client_address, method, target, version, headers, body):
    host, port, path = get_destination_for_http(target, headers)

    if not host:
        send_error_response(client_socket, 400, "Bad Request", "Could not determine target host.")
        return

    forward_request = build_forward_request(method, path, version, headers, body, host, port)

    remote_socket = None
    try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(SOCKET_TIMEOUT)
        remote_socket.connect((host, port))
        remote_socket.sendall(forward_request)

        relay_http_response(remote_socket, client_socket)

    except Exception as e:
        send_error_response(client_socket, 502, "Bad Gateway", f"Error contacting {host}:{port}")
    finally:
        if remote_socket:
            remote_socket.close()


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

        # After this point TLS handshake is between browser and destination server.
        # Proxy only copies encrypted bytes.
        tunnel_data(client_socket, remote_socket)

    except Exception as e:
        send_error_response(client_socket, 502, "Bad Gateway", f"Could not open tunnel to {host}:{port}")
    finally:
        if remote_socket:
            remote_socket.close()



# Handle one connected client
def handle_client(client_socket, client_address):
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)

        request = read_http_request(client_socket)
        if request is None:
            return

        request_line, headers, body = request
        method, target, version = parse_request_line(request_line)

        if not method or not target or not version:
            send_error_response(client_socket, 400, "Bad Request", "Invalid request line.")
            return

        if method == "CONNECT":
            handle_connect_tunnel(client_socket, client_address, target)
        elif method in {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}:
            handle_http_request(client_socket, client_address, method, target, version, headers, body)
        else:
            send_error_response(client_socket, 501, "Not Implemented", f"Method {method} not supported.")

    except Exception as e:
        try:
            send_error_response(client_socket, 500, "Internal Server Error", "Proxy internal error.")
        except Exception:
            pass
    finally:
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