# DeltaSync

DeltaSync updates remote files efficiently by sending only the changed blocks over TCP. It uses fixed-size block hashing, zlib compression, a PSK/HMAC handshake, and a full-file verification step after patching.

## Quick Start

Start Poetry environment and install dependencies:

```bash
eval $(poetry env activate)
poetry install
```

Start the server:
```bash
python ./main.py server 0.0.0.0 9000 --base-dir . --psk your_key
```

Sync a local file:
```bash
python ./main.py sync 127.0.0.1 9000 /path/to/data.bin --psk your_key
```

## Commands

### `server`
Starts the TCP server that serves manifests and applies deltas.

- **`host` (required)**: Interface/IP to bind.
- **`port` (required, int)**: Port to bind.
- **`--base-dir` (optional)**: Root directory for file access. Default: current directory (`.`).
- **`-b`, `--block-size` (optional)**: Block size in bytes. Default: `65536`.
- **`--psk` (optional)**: Pre‑shared key for handshake. If omitted, the server reads `DELTA_SYNC_PSK` from the environment.

### `sync`
Uploads only the changed blocks to the server.

- **`host` (required)**: Server host or IP address.
- **`port` (required, int)**: Server port.
- **`file` (required)**: Local file path to sync.
- **`--remote-name` (optional)**: Remote filename. Defaults to the local file’s name.
- **`-b`, `--block-size` (optional)**: Block size in bytes. Default: `65536`.
- **`--timeout` (optional, float)**: Connection timeout in seconds. Default: `10.0`.
- **`--psk` (optional)**: Pre‑shared key for handshake. If omitted, the client reads `DELTA_SYNC_PSK` from the environment.
- **`--no-progress` (optional flag)**: Disables the `tqdm` progress bar.

## Security, Integrity, and Performance

- **Handshake:** The client signs metadata with HMAC‑SHA256 and a PSK. The server verifies before accepting blocks.
- **Integrity:** After patching, the server re-hashes the full file and compares with the client’s hash.
- **Compression:** Blocks are compressed with zlib to reduce bandwidth.
- **Progress:** `sync` uses `tqdm` for upload progress. Install with `pip install tqdm`.
