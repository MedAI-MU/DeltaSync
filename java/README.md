# DeltaSync (Java)

A Java port of [MedAI-MU/DeltaSync](https://github.com/MedAI-MU/DeltaSync). DeltaSync updates remote files efficiently by sending only the changed blocks over TCP. It uses fixed-size block hashing, zlib compression, a PSK/HMAC handshake, and a full-file verification step after patching.

The wire protocol is preserved bit-for-bit, so this Java implementation interoperates with the Python one in either direction (Java client ↔ Python server, Python client ↔ Java server).

## Build

Requires JDK 17+ and Maven.

```bash
mvn -q package
```

Produces a single self-contained jar at `target/deltasync.jar`.

## Quick start

Start the server:

```bash
java -jar target/deltasync.jar server 0.0.0.0 9000 --base-dir . --psk your_key
```

Sync a local file:

```bash
java -jar target/deltasync.jar sync 127.0.0.1 9000 /path/to/data.bin --psk your_key
```

## Commands

### `server`

Starts the TCP server that serves manifests and applies deltas.

| Argument | Description |
| --- | --- |
| `host` *(required)* | Interface/IP to bind. |
| `port` *(required, int)* | Port to bind. |
| `--base-dir` | Root directory for file access. Default: current directory (`.`). |
| `-b`, `--block-size` | Block size in bytes. Default: `65536`. |
| `--psk` | Pre-shared key for the handshake. If omitted, the server reads `DELTA_SYNC_PSK` from the environment. |

### `sync`

Uploads only the changed blocks to the server.

| Argument | Description |
| --- | --- |
| `host` *(required)* | Server host or IP address. |
| `port` *(required, int)* | Server port. |
| `file` *(required)* | Local file path to sync. |
| `--remote-name` | Remote filename. Defaults to the local file's name. |
| `-b`, `--block-size` | Block size in bytes. Default: `65536`. |
| `--timeout` | Connection timeout in seconds. Default: `10.0`. |
| `--psk` | Pre-shared key for the handshake. If omitted, the client reads `DELTA_SYNC_PSK` from the environment. |
| `--no-progress` | Disables the upload progress bar. |

## Security, Integrity, and Performance

- **Handshake.** The client signs metadata with HMAC-SHA256 and a PSK. The server verifies before accepting blocks. Comparisons are constant-time.
- **Integrity.** After patching, the server re-hashes the full file and compares against the client's hash before responding `OK`.
- **Compression.** Blocks are compressed with zlib (RFC 1950) to reduce bandwidth.
- **Path traversal.** Filenames are resolved against `--base-dir` and rejected if they escape it.
- **Progress.** `sync` shows a stderr progress bar; suppress with `--no-progress`.

## Wire protocol

Identical to the Python implementation — every message is a 4-byte big-endian length prefix followed by that many payload bytes.

| Message | Direction | Payload |
| --- | --- | --- |
| Control message | C → S | UTF-8 JSON: `{"command": "GET_MANIFEST" \| "APPLY_DELTA", ...}` |
| Manifest response | S → C | UTF-8 JSON: `{"manifest": [{"index", "hash", "start_byte"}, ...]}` |
| Delta block frame | C → S | `!II` header (`index`, `compressed_len`, both big-endian uint32) + zlib-compressed block bytes |
| Final response | S → C | UTF-8 JSON: `{"status": "OK", "applied_blocks": N}` or `{"error": "<CODE>"}` |

The HMAC-SHA256 covers the UTF-8 string `"<nonce>:<filename>:<file_size>:<block_size>:<full_hash>"`.

## Project layout

```
src/main/java/com/medai/deltasync/
├── Main.java              CLI entry point + argparse-style command routing
├── ArgParser.java         Minimal positional/option/flag parser
├── ManifestServer.java    TCP server (GET_MANIFEST + APPLY_DELTA)
├── DeltaSyncClient.java   Client (build manifest, diff, upload changed blocks)
├── BlockAnalysis.java     Manifest building, file hashing, manifest diff
├── ManifestEntry.java     {index, hash, startByte} record
├── Protocol.java          4-byte length-prefixed framing
├── CryptoUtil.java        HMAC-SHA256 + secure nonces + constant-time compare
├── Zlib.java              Zlib compress/decompress (Python-compatible)
├── HexUtil.java           Lowercase hex encoder
└── ProgressBar.java       Stderr progress bar (replaces Python tqdm)
```

## Cross-protocol compatibility

Verified end-to-end across all four pairings on a 200 KB random file with full and partial syncs:

- Java client ↔ Java server
- Python client ↔ Python server
- Java client ↔ Python server
- Python client ↔ Java server

In every case the partial-sync path uploads only the modified blocks and the final SHA-256 of the server-side file matches the client.

## Notes on the port

- Java's `Deflater`/`Inflater` with `nowrap=false` (the default) produces and consumes the same zlib format Python's `zlib.compress`/`zlib.decompress` does — no byte-level adjustment was needed.
- Java's `DataOutputStream.writeInt` writes big-endian by spec, matching Python's `struct.pack("!I", ...)`.
- The Python `_resolve_file_path` walks `Path.parents`; the Java port uses `resolved.startsWith(baseDir)` after `normalize()`/`toAbsolutePath()` for the same effect.
- HMAC comparison uses a constant-time byte loop — equivalent to Python's `hmac.compare_digest`.
- The server uses a cached thread pool of daemon threads, mirroring Python's per-connection daemon `Thread`.

## Gotcha when talking to the upstream Python server

The upstream Python `main.py` server subcommand does **not** read the PSK from `DELTA_SYNC_PSK` — only from an explicit `--psk` flag. Running the upstream Python server with just the env var set (no `--psk`) causes it to reject every `APPLY_DELTA` with `PSK_REQUIRED`, which the client only learns about after streaming all of its blocks.

This Java client gracefully recovers in that situation: if the socket dies mid-upload, it tries to read any pending error response from the server and surfaces it as `Server error: PSK_REQUIRED` (or `HMAC_MISMATCH`, etc.) instead of the cryptic `Broken pipe`.

The Java server has no such gotcha — it reads `DELTA_SYNC_PSK` from the environment when `--psk` is omitted, like the docs imply.
