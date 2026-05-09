"""DeltaSync application entry point."""

from __future__ import annotations

import argparse
import json

from scripts.fixed_block_analysis import DEFAULT_BLOCK_SIZE, send_delta_sync
from server.manifest_server import start_server


def main() -> None:
    parser = argparse.ArgumentParser(description="DeltaSync")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server", help="Start manifest server")
    server_parser.add_argument("host", help="Host to bind")
    server_parser.add_argument("port", type=int, help="Port to bind")
    server_parser.add_argument(
        "--base-dir",
        default=".",
        help="Base directory for file lookups",
    )
    server_parser.add_argument(
        "-b",
        "--block-size",
        type=int,
        default=DEFAULT_BLOCK_SIZE,
        help="Block size in bytes (default: 65536)",
    )
    server_parser.add_argument(
        "--psk",
        help="Pre-shared key for the security handshake (or set DELTA_SYNC_PSK)",
    )

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

    if args.mode == "server":
        start_server(
            host=args.host,
            port=args.port,
            base_dir=args.base_dir,
            block_size=args.block_size,
            psk=args.psk,
        )
    elif args.mode == "sync":
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


if __name__ == "__main__":
    main()
