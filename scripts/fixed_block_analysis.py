"""Fixed-block file analysis tool."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import zlib
from pathlib import Path
from typing import Generator, Iterable, TypedDict

from tqdm import tqdm

DEFAULT_BLOCK_SIZE = 64 * 1024  # 64KB


class ManifestEntry(TypedDict):
    index: int
    hash: str
    start_byte: int


def iter_file_chunks(
    file_path: str | Path, block_size: int = DEFAULT_BLOCK_SIZE
) -> Generator[bytes, None, None]:
    """Yield file contents in fixed-size chunks.

    Args:
        file_path: Path to the file to read.
        block_size: Chunk size in bytes (defaults to 64KB).

    Yields:
        Raw bytes for each chunk until EOF.
    """
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")

    path = Path(file_path)
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(block_size)
            if not chunk:
                break
            yield chunk


def build_manifest(
    file_path: str | Path, block_size: int = DEFAULT_BLOCK_SIZE
) -> list[ManifestEntry]:
    """Build a manifest of SHA-256 hashes for each fixed-size block.

    Each entry contains:
      - index: zero-based block index
      - hash: hex digest of the block
      - start_byte: starting byte offset of the block in the file
    """
    manifest: list[ManifestEntry] = []
    offset = 0

    for index, chunk in enumerate(iter_file_chunks(file_path, block_size=block_size)):
        digest = hashlib.sha256(chunk).hexdigest()
        manifest.append(
            {
                "index": index,
                "hash": digest,
                "start_byte": offset,
            }
        )
        offset += len(chunk)

    return manifest


def save_manifest(manifest: Iterable[ManifestEntry], manifest_path: str | Path) -> None:
    """Save a manifest as JSON to the provided path."""
    path = Path(manifest_path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(list(manifest), handle, indent=2)


def build_and_save_manifest(
    file_path: str | Path,
    manifest_path: str | Path | None = None,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> list[ManifestEntry]:
    """Build a manifest and persist it as a JSON file."""
    manifest = build_manifest(file_path, block_size=block_size)
    if manifest_path is None:
        manifest_path = f"{file_path}.manifest.json"
    save_manifest(manifest, manifest_path)
    return manifest


def load_manifest(manifest_path: str | Path) -> list[ManifestEntry]:
    """Load a manifest from disk."""
    path = Path(manifest_path)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return _coerce_manifest(data)


def _coerce_manifest(data: object) -> list[ManifestEntry]:
    if not isinstance(data, list):
        raise ValueError("Manifest data must be a list")

    manifest: list[ManifestEntry] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Manifest entry must be a dictionary")

        index = entry.get("index")
        digest = entry.get("hash")
        start_byte = entry.get("start_byte")

        if not isinstance(index, int):
            raise ValueError("Manifest entry 'index' must be an int")
        if not isinstance(digest, str):
            raise ValueError("Manifest entry 'hash' must be a str")
        if not isinstance(start_byte, int):
            raise ValueError("Manifest entry 'start_byte' must be an int")

        manifest.append({"index": index, "hash": digest, "start_byte": start_byte})

    return manifest


def compare_manifests(
    local_manifest: Iterable[ManifestEntry],
    remote_manifest: Iterable[ManifestEntry],
) -> list[int]:
    """Compare manifests and return block indices that are missing or mismatched.

    Any index present in one manifest but missing in the other, or present in both
    with different hashes, will be included in the result.
    """
    local_map = {entry["index"]: entry["hash"] for entry in local_manifest}
    remote_map = {entry["index"]: entry["hash"] for entry in remote_manifest}

    differing_indices = [
        index
        for index in sorted(set(local_map) | set(remote_map))
        if local_map.get(index) != remote_map.get(index)
    ]
    return differing_indices


def compute_file_hash(
    file_path: str | Path, block_size: int = DEFAULT_BLOCK_SIZE
) -> str:
    """Compute the SHA-256 hash for an entire file."""
    digest = hashlib.sha256()
    for chunk in iter_file_chunks(file_path, block_size=block_size):
        digest.update(chunk)
    return digest.hexdigest()


def iter_changed_blocks(
    file_path: str | Path,
    indices: Iterable[int],
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> Generator[tuple[int, bytes], None, None]:
    """Yield (index, data) for the requested block indices."""
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")

    path = Path(file_path)
    with path.open("rb") as handle:
        for index in indices:
            if index < 0:
                raise ValueError("Block index must be non-negative")
            handle.seek(index * block_size)
            data = handle.read(block_size)
            yield index, data


def send_delta_sync(
    host: str,
    port: int,
    file_path: str | Path,
    remote_filename: str | None = None,
    block_size: int = DEFAULT_BLOCK_SIZE,
    timeout: float = 10.0,
    psk: str | None = None,
    show_progress: bool = True,
) -> list[int]:
    """Send only changed blocks to the server and return synced indices."""
    path = Path(file_path)
    if remote_filename is None:
        remote_filename = path.name

    local_manifest = build_manifest(path, block_size=block_size)
    remote_manifest = request_manifest(
        host,
        port,
        remote_filename,
        timeout=timeout,
        allow_missing=True,
    )
    diff_indices = compare_manifests(local_manifest, remote_manifest)
    local_index_set = {entry["index"] for entry in local_manifest}
    send_indices = [index for index in diff_indices if index in local_index_set]

    file_size = path.stat().st_size
    full_hash = compute_file_hash(path, block_size=block_size)

    if not psk:
        psk = os.environ.get("DELTA_SYNC_PSK")
    if not psk:
        raise ValueError("PSK is required for delta sync")

    nonce = secrets.token_hex(16)
    signing_payload = (
        f"{nonce}:{remote_filename}:{file_size}:{block_size}:{full_hash}".encode(
            "utf-8"
        )
    )
    signature = hmac.new(
        psk.encode("utf-8"), signing_payload, hashlib.sha256
    ).hexdigest()

    payload = {
        "command": "APPLY_DELTA",
        "filename": remote_filename,
        "block_size": block_size,
        "file_size": file_size,
        "blocks_count": len(send_indices),
        "full_hash": full_hash,
        "nonce": nonce,
        "hmac": signature,
    }

    total_bytes = sum(
        max(0, min(block_size, file_size - index * block_size))
        for index in send_indices
    )

    progress = None
    if show_progress:
        progress = tqdm(
            total=total_bytes,
            unit="B",
            unit_scale=True,
            desc="Uploading",
        )

    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_message(sock, json.dumps(payload).encode("utf-8"))
        for index, data in iter_changed_blocks(
            path, send_indices, block_size=block_size
        ):
            compressed = zlib.compress(data)
            block_payload = struct.pack("!II", index, len(compressed)) + compressed
            send_message(sock, block_payload)
            if progress is not None:
                progress.update(len(data))
        response_raw = recv_message(sock)

    if progress is not None:
        progress.close()

    if not response_raw:
        raise ConnectionError("Empty response from server")

    response = json.loads(response_raw.decode("utf-8"))
    if not isinstance(response, dict):
        raise ValueError("Invalid response payload")
    if "error" in response:
        raise ValueError(f"Server error: {response['error']}")

    return send_indices


def _recv_exact(sock: "socket.socket", size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data.extend(chunk)
    return bytes(data)


def send_message(sock: "socket.socket", message: bytes) -> None:
    header = struct.pack("!I", len(message))
    sock.sendall(header + message)


def recv_message(sock: "socket.socket") -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def request_manifest(
    host: str,
    port: int,
    filename: str,
    timeout: float = 10.0,
    allow_missing: bool = False,
) -> list[ManifestEntry]:
    payload = {"command": "GET_MANIFEST", "filename": filename}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_message(sock, json.dumps(payload).encode("utf-8"))
        response_raw = recv_message(sock)

    if not response_raw:
        raise ConnectionError("Empty response from server")

    response = json.loads(response_raw.decode("utf-8"))
    if not isinstance(response, dict):
        raise ValueError("Invalid response payload")
    if "error" in response:
        error = response["error"]
        if allow_missing and error == "NOT_FOUND":
            return []
        raise ValueError(f"Server error: {error}")

    manifest = response.get("manifest")
    return _coerce_manifest(manifest)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fixed-block file analysis tool")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    sync_parser = subparsers.add_parser("sync", help="Delta-sync a file")
    sync_parser.add_argument("host", help="Server host")
    sync_parser.add_argument("port", type=int, help="Server port")
    sync_parser.add_argument("file", help="Local file path")
    sync_parser.add_argument(
        "--remote-name",
        help="Remote filename (defaults to the local file name)",
    )
    sync_parser.add_argument(
        "-b",
        "--block-size",
        type=int,
        default=DEFAULT_BLOCK_SIZE,
        help="Block size in bytes (default: 65536)",
    )
    sync_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Connection timeout in seconds",
    )
    sync_parser.add_argument(
        "--psk",
        help="Pre-shared key for the security handshake (or set DELTA_SYNC_PSK)",
    )
    sync_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the upload progress bar",
    )

    args = parser.parse_args()

    if args.mode == "sync":
        synced = send_delta_sync(
            host=args.host,
            port=args.port,
            file_path=args.file,
            remote_filename=args.remote_name,
            block_size=args.block_size,
            timeout=args.timeout,
            psk=args.psk,
            show_progress=not args.no_progress,
        )
        print(json.dumps({"synced_blocks": synced}, indent=2))
