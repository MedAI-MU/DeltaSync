"""TCP server for fixed-block manifest requests."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import zlib
from pathlib import Path

from scripts.fixed_block_analysis import (
    DEFAULT_BLOCK_SIZE,
    build_manifest,
    recv_message,
    send_message,
)


def _send_error(client_socket: socket.socket, code: str) -> None:
    send_message(client_socket, json.dumps({"error": code}).encode("utf-8"))


def _resolve_file_path(base_dir: Path, filename: str) -> Path | None:
    file_path = (base_dir / filename).resolve()
    if base_dir not in file_path.parents and file_path != base_dir:
        return None
    return file_path


def _compute_file_hash(path: Path, block_size: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(block_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _handle_get_manifest(
    client_socket: socket.socket,
    base_dir: Path,
    block_size: int,
    payload: dict[str, object],
) -> None:
    filename = payload.get("filename")
    if not isinstance(filename, str):
        _send_error(client_socket, "INVALID_FILENAME")
        return

    file_path = _resolve_file_path(base_dir, filename)
    if file_path is None:
        _send_error(client_socket, "INVALID_PATH")
        return

    if not file_path.exists() or not file_path.is_file():
        _send_error(client_socket, "NOT_FOUND")
        return

    manifest = build_manifest(file_path, block_size=block_size)
    send_message(client_socket, json.dumps({"manifest": manifest}).encode("utf-8"))


def _apply_delta(
    client_socket: socket.socket,
    base_dir: Path,
    payload: dict[str, object],
    default_block_size: int,
    psk: str | None,
) -> None:
    filename = payload.get("filename")
    if not isinstance(filename, str):
        _send_error(client_socket, "INVALID_FILENAME")
        return

    block_size = payload.get("block_size", default_block_size)
    if not isinstance(block_size, int) or block_size <= 0:
        _send_error(client_socket, "INVALID_BLOCK_SIZE")
        return

    file_size = payload.get("file_size")
    if not isinstance(file_size, int) or file_size < 0:
        _send_error(client_socket, "INVALID_FILE_SIZE")
        return

    blocks_count = payload.get("blocks_count")
    if not isinstance(blocks_count, int) or blocks_count < 0:
        _send_error(client_socket, "INVALID_BLOCK_COUNT")
        return

    full_hash = payload.get("full_hash")
    if not isinstance(full_hash, str):
        _send_error(client_socket, "INVALID_FILE_HASH")
        return

    nonce = payload.get("nonce")
    if not isinstance(nonce, str):
        _send_error(client_socket, "INVALID_NONCE")
        return

    signature = payload.get("hmac")
    if not isinstance(signature, str):
        _send_error(client_socket, "INVALID_HMAC")
        return

    if not psk:
        _send_error(client_socket, "PSK_REQUIRED")
        return

    signing_payload = f"{nonce}:{filename}:{file_size}:{block_size}:{full_hash}".encode(
        "utf-8"
    )
    expected = hmac.new(
        psk.encode("utf-8"), signing_payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        _send_error(client_socket, "HMAC_MISMATCH")
        return

    file_path = _resolve_file_path(base_dir, filename)
    if file_path is None:
        _send_error(client_socket, "INVALID_PATH")
        return

    fd = os.open(file_path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+b") as handle:
        handle.truncate(file_size)
        for _ in range(blocks_count):
            block_message = recv_message(client_socket)
            if not block_message:
                _send_error(client_socket, "EMPTY_BLOCK")
                return
            if len(block_message) < 8:
                _send_error(client_socket, "INVALID_BLOCK_HEADER")
                return
            index, data_len = struct.unpack("!II", block_message[:8])
            compressed = block_message[8:]
            if data_len != len(compressed):
                _send_error(client_socket, "INVALID_BLOCK_LENGTH")
                return
            try:
                data = zlib.decompress(compressed)
            except zlib.error:
                _send_error(client_socket, "DECOMPRESSION_FAILED")
                return
            if len(data) > block_size:
                _send_error(client_socket, "INVALID_BLOCK_SIZE")
                return
            if index * block_size + len(data) > file_size:
                _send_error(client_socket, "INVALID_BLOCK_RANGE")
                return
            handle.seek(index * block_size)
            handle.write(data)

    computed_hash = _compute_file_hash(file_path, block_size)
    if not hmac.compare_digest(computed_hash, full_hash):
        _send_error(client_socket, "HASH_MISMATCH")
        return

    send_message(
        client_socket,
        json.dumps({"status": "OK", "applied_blocks": blocks_count}).encode("utf-8"),
    )


def _handle_client(
    client_socket: socket.socket, base_dir: Path, block_size: int, psk: str | None
) -> None:
    with client_socket:
        try:
            raw = recv_message(client_socket)
            if not raw:
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                _send_error(client_socket, "INVALID_JSON")
                return

            if not isinstance(payload, dict):
                _send_error(client_socket, "INVALID_PAYLOAD")
                return

            command = payload.get("command")
            if command == "GET_MANIFEST":
                _handle_get_manifest(client_socket, base_dir, block_size, payload)
                return
            if command == "APPLY_DELTA":
                _apply_delta(client_socket, base_dir, payload, block_size, psk)
                return

            _send_error(client_socket, "UNKNOWN_COMMAND")
        except ConnectionError:
            return


def start_server(
    host: str,
    port: int,
    base_dir: str | Path,
    block_size: int = DEFAULT_BLOCK_SIZE,
    psk: str | None = None,
) -> None:
    base_path = Path(base_dir).resolve()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Manifest server listening on {host}:{port}, base dir: {base_path}")
        while True:
            client_socket, _ = server_socket.accept()
            thread = threading.Thread(
                target=_handle_client,
                args=(client_socket, base_path, block_size, psk),
                daemon=True,
            )
            print(f"Accepted connection from {client_socket.getpeername()}")
            thread.start()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fixed-block manifest server")
    parser.add_argument("host", help="Host to bind")
    parser.add_argument("port", type=int, help="Port to bind")
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Base directory for file lookups",
    )
    parser.add_argument(
        "-b",
        "--block-size",
        type=int,
        default=DEFAULT_BLOCK_SIZE,
        help="Block size in bytes (default: 65536)",
    )
    parser.add_argument(
        "--psk",
        default=os.environ.get("DELTA_SYNC_PSK"),
        help="Pre-shared key for the security handshake (or set DELTA_SYNC_PSK)",
    )

    args = parser.parse_args()
    start_server(
        host=args.host,
        port=args.port,
        base_dir=args.base_dir,
        block_size=args.block_size,
        psk=args.psk,
    )
