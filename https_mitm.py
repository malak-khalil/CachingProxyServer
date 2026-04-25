"""
https_mitm.py by Talia

Simple educational HTTPS MITM proxy support.

This decrypts HTTPS traffic by:
1. Receiving CONNECT host:443
2. Sending 200 Connection Established
3. Presenting a locally generated fake certificate to the client
4. Opening a real TLS connection to the target server
5. Reading decrypted HTTP data from the client
6. Forwarding it to the real server over TLS
7. Returning the real server response to the client

For local testing only.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CERT_DIR = Path("mitm_certs")
CA_CERT_PATH = CERT_DIR / "ca_cert.pem"
CA_KEY_PATH = CERT_DIR / "ca_key.pem"


def _write_private_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ensure_ca_exists():
    """
    Create a local Certificate Authority if it does not already exist.

    The client must trust ca_cert.pem for HTTPS interception to work without warnings.
    """
    CERT_DIR.mkdir(exist_ok=True)

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        return ca_cert, ca_key

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Talia Local MITM CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(CA_KEY_PATH, ca_key)
    _write_cert(CA_CERT_PATH, ca_cert)

    return ca_cert, ca_key


def create_host_certificate(host: str) -> tuple[Path, Path]:
    """
    Create or reuse a fake certificate for the requested HTTPS host.
    """
    ca_cert, ca_key = ensure_ca_exists()

    safe_host = host.replace("*", "_").replace(":", "_")
    cert_path = CERT_DIR / f"{safe_host}_cert.pem"
    key_path = CERT_DIR / f"{safe_host}_key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
    ])

    san_entries = []
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        san_entries.append(x509.DNSName(host))

    host_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(key_path, host_key)
    _write_cert(cert_path, host_cert)

    return cert_path, key_path


def recv_until_header_end(sock: ssl.SSLSocket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data


def read_https_request(tls_client: ssl.SSLSocket):
    """
    Read one decrypted HTTP request from the TLS-wrapped client socket.
    """
    data = recv_until_header_end(tls_client)
    if not data:
        return None

    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return None

    headers_part = data[:header_end + 4]
    body_part = data[header_end + 4:]

    text = headers_part.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    request_line = lines[0]

    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        return None

    method, path, version = parts

    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    content_length = int(headers.get("content-length", "0"))
    body = body_part

    while len(body) < content_length:
        chunk = tls_client.recv(8192)
        if not chunk:
            break
        body += chunk

    body = body[:content_length]

    return method, path, version, headers, body


def build_origin_request(method, path, version, headers, body, host):
    """
    Rebuild the decrypted request before forwarding it to the real HTTPS server.
    """
    new_headers = dict(headers)

    for h in [
        "proxy-connection",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    ]:
        new_headers.pop(h, None)

    new_headers["host"] = host
    new_headers["connection"] = "close"

    if body:
        new_headers["content-length"] = str(len(body))
    else:
        new_headers.pop("content-length", None)

    request = f"{method} {path} {version}\r\n"
    for name, value in new_headers.items():
        request += f"{name}: {value}\r\n"
    request += "\r\n"

    return request.encode("iso-8859-1") + body


def read_full_response(sock: ssl.SSLSocket) -> bytes:
    """
    Read the server response until the remote TLS server closes the connection.
    This is simple and works because we send Connection: close upstream.
    """
    chunks = []
    while True:
        data = sock.recv(8192)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def handle_https_mitm(client_sock, client_addr, target_host, target_port, logger=None, timeout=10):
    """
    Handle one CONNECT request using MITM decryption.
    """
    client_ip, client_port = client_addr

    try:
        cert_path, key_path = create_host_certificate(target_host)

        # Tell the client that the CONNECT tunnel is established.
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Wrap client side as if this proxy is the HTTPS server.
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        tls_client = server_context.wrap_socket(client_sock, server_side=True)

        if logger:
            logger.log_https_event(
                event="https_mitm_started",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message="MITM TLS session established with client",
            )

        request = read_https_request(tls_client)
        if request is None:
            return

        method, path, version, headers, body = request

        if logger:
            logger.log_https_event(
                event="https_mitm_decrypted_request",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message=f"Decrypted HTTPS request: {method} {path}",
            )

        origin_request = build_origin_request(method, path, version, headers, body, target_host)

        # Open real TLS connection to target server.
        client_context = ssl.create_default_context()
        with socket.create_connection((target_host, target_port), timeout=timeout) as raw_remote:
            with client_context.wrap_socket(raw_remote, server_hostname=target_host) as tls_remote:
                tls_remote.sendall(origin_request)
                response = read_full_response(tls_remote)

        tls_client.sendall(response)

        if logger:
            logger.log_https_event(
                event="https_mitm_response_sent",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message="Decrypted HTTPS response relayed to client",
            )

    except Exception as e:
        if logger:
            logger.log_error(
                message="HTTPS MITM failed",
                error=str(e),
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                method="CONNECT",
                url=f"{target_host}:{target_port}",
            )
        try:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass

    finally:
        if logger:
            logger.log_https_event(
                event="https_mitm_closed",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message="MITM HTTPS connection closed",
            )

        try:
            client_sock.close()
        except Exception:
            pass