"""
https_tunnel.py by Talia

Requirement H - HTTPS Proxy (Bonus)
This module implements HTTPS forwarding by tunneling CONNECT requests.

This module creates a TCP tunnel between the client and the target server.

How HTTPS via CONNECT works:
1. Browser sends:
       CONNECT example.com:443 HTTP/1.1
2. Proxy connects to example.com on port 443
3. Proxy replies:
       HTTP/1.1 200 Connection Established
4. Proxy relays encrypted bytes both directions
"""

from __future__ import annotations

import select
import socket
from typing import Optional

from proxy_logger import ProxyLogger


class HTTPSTunnelError(Exception):
    #Custom exception type for HTTPS tunnel setup/relay errors.
    pass


def parse_connect_target(target: str) -> tuple[str, int]:
    """
    Parse the CONNECT target string.

    Expected formats:
    - example.com:443
    - 93.184.216.34:443

    Returns:
        (host, port)

    Raises:
        ValueError if the format is invalid
    """
    if ":" not in target:
        raise ValueError("CONNECT target must be in host:port format")

    host, port_str = target.rsplit(":", 1)
    port = int(port_str)
    return host.strip(), port


def send_connection_established(client_sock: socket.socket) -> None:
    #Send the standard success response after a CONNECT tunnel is created.

    response = (
        b"HTTP/1.1 200 Connection Established\r\n"
        b"Proxy-Agent: PythonProxy/1.0\r\n"
        b"\r\n"
    )
    client_sock.sendall(response)


def relay_bidirectional(client_sock: socket.socket, remote_sock: socket.socket) -> None:
    """
    Relay bytes in both directions until one side closes.

    - We need to watch both sockets at the same time
    - Data can arrive from the client or the server at any moment
    - select() lets us react to whichever socket becomes readable

    Relay loop logic:
    1. Wait until either socket has data
    2. Read data from the ready socket
    3. Forward it to the other socket
    4. Stop when one side closes or read returns no bytes
    """
    sockets = [client_sock, remote_sock]

    while True:
        readable, _, exceptional = select.select(sockets, [], sockets)

        if exceptional:
            raise HTTPSTunnelError("Socket exception occurred during HTTPS relay")

        for sock in readable:
            try:
                data = sock.recv(8192)
            except OSError as e:
                raise HTTPSTunnelError(f"Socket receive failed: {e}") from e

            # Empty read means the peer has closed the connection.
            if not data:
                return

            if sock is client_sock:
                remote_sock.sendall(data)
            else:
                client_sock.sendall(data)


def handle_https_connect(
    client_sock: socket.socket,
    client_addr: tuple[str, int],
    target_host: str,
    target_port: int,
    logger: Optional[ProxyLogger] = None,
    connect_timeout: int = 10,
) -> None:
    """
    Create and run an HTTPS tunnel for one CONNECT request.

    Parameters:
        client_sock: socket connected to the browser/client
        client_addr: tuple (client_ip, client_port)
        target_host: remote host extracted from CONNECT
        target_port: remote port extracted from CONNECT
        logger: optional logger instance
        connect_timeout: timeout in seconds for connecting to remote host
    """
    remote_sock = None
    client_ip, client_port = client_addr

    try:
        # Step 1: create a TCP connection to the target HTTPS server.
        remote_sock = socket.create_connection((target_host, target_port), timeout=connect_timeout)

        # Step 2: tell the client that the tunnel is ready.
        send_connection_established(client_sock)

        if logger:
            logger.log_https_event(
                event="https_tunnel_started",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message="CONNECT tunnel established successfully",
            )

        # Step 3: relay encrypted bytes both directions.
        relay_bidirectional(client_sock, remote_sock)

    except Exception as e:
        if logger:
            logger.log_error(
                message="HTTPS tunnel failed",
                error=str(e),
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                method="CONNECT",
                url=f"{target_host}:{target_port}",
            )

        # Best effort error reply if tunnel setup fails before success response.
        try:
            client_sock.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 29\r\n"
                b"\r\n"
                b"Failed to establish tunnel"
            )
        except OSError:
            pass

    finally:
        if logger:
            logger.log_https_event(
                event="https_tunnel_closed",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message="CONNECT tunnel closed",
            )

        try:
            if remote_sock is not None:
                remote_sock.close()
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
