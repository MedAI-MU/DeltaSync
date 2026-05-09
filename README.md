# DeltaSync (Java)

DeltaSync updates remote files efficiently by sending only the changed blocks over TCP. It uses fixed-size block hashing, zlib compression, a PSK/HMAC handshake, and a full-file verification step after patching. This version is a complete rewrite in Java 21 using standard libraries and Gson.

## Quick Start

### Building from Source

Ensure you have Java 21 and Maven installed. Then compile and package the fat JAR:

```bash
mvn clean package
```

The resulting executable JAR will be located at `target/deltasync-1.0-SNAPSHOT.jar`.

### Start the Server

```bash
export DELTA_SYNC_PSK="your_key"
java -jar target/deltasync-1.0-SNAPSHOT.jar server 0.0.0.0 9000 --base-dir .
```

Alternatively, you can provide the PSK inline:

```bash
java -jar target/deltasync-1.0-SNAPSHOT.jar server 0.0.0.0 9000 --base-dir . --psk your_key
```

### Sync a Local File

```bash
export DELTA_SYNC_PSK="your_key"
java -jar target/deltasync-1.0-SNAPSHOT.jar sync 127.0.0.1 9000 /path/to/data.bin
```

Alternatively, you can provide the PSK inline:

```bash
java -jar target/deltasync-1.0-SNAPSHOT.jar sync 127.0.0.1 9000 /path/to/data.bin --psk your_key
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
- **`--no-progress` (optional flag)**: Disables the terminal progress bar.

## Security, Integrity, and Performance

- **Handshake:** The client signs metadata with HMAC‑SHA256 and a PSK. The server verifies before accepting blocks.
- **Integrity:** After patching, the server re-hashes the full file and compares with the client’s hash.
- **Compression:** Blocks are compressed with zlib to reduce bandwidth.
