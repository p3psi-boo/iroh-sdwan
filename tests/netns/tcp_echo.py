#!/usr/bin/env python3
"""Small deterministic TCP fixture for network-namespace integration tests."""

import argparse
import socket


def serve(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        while True:
            connection, _ = listener.accept()
            with connection:
                while data := connection.recv(65536):
                    connection.sendall(data)


def exchange(host: str, port: int, byte_count: int) -> None:
    payload = bytes((index % 251 for index in range(byte_count)))
    received = bytearray()
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        while len(received) < byte_count:
            chunk = connection.recv(byte_count - len(received))
            if not chunk:
                break
            received.extend(chunk)
    if received != payload:
        raise SystemExit(f"echo mismatch: sent {byte_count}, received {len(received)}")


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)
server = subparsers.add_parser("server")
server.add_argument("host")
server.add_argument("port", type=int)
client = subparsers.add_parser("client")
client.add_argument("host")
client.add_argument("port", type=int)
client.add_argument("bytes", type=int)
arguments = parser.parse_args()

if arguments.command == "server":
    serve(arguments.host, arguments.port)
else:
    exchange(arguments.host, arguments.port, arguments.bytes)
