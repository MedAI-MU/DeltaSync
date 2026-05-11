# DeltaSync Java Internals

This document provides a technical overview of the Java implementation of DeltaSync, a block-based file synchronization tool over TCP. It is designed to help developers and stakeholders with basic Java knowledge understand how the code is structured, the synchronization flow, and the role of key Java classes.

## How DeltaSync Works

DeltaSync is designed to efficiently sync files over a network. Instead of sending the entire file every time it is updated, DeltaSync breaks the file into chunks (blocks) and only transmits the blocks that have changed. It uses a client-server architecture.

### The Synchronization Flow

When a client wants to sync a file with the server, the following steps happen:

1. **Local Manifest Creation (`BlockAnalysis.java`)**: The client reads its local file block by block (default 64KB) and calculates a SHA-256 hash for each block. This list of hashes is the "local manifest."
2. **Remote Manifest Request (`DeltaSyncClient.java`)**: The client connects to the server and sends a `GET_MANIFEST` command. The server computes the manifest for its copy of the file and sends it back. If the server doesn't have the file yet, it returns an empty manifest.
3. **Difference Calculation (`BlockAnalysis.java`)**: The client compares its local manifest with the remote manifest. It identifies which blocks are missing or modified on the server side.
4. **Data Transmission (`DeltaSyncClient.java`)**: The client initiates an `APPLY_DELTA` request. It sends the total file size, full file hash, block count, and an HMAC-SHA256 signature (for security) to the server.
5. **Streaming Blocks (`DeltaSyncClient.java` & `Zlib.java`)**: For every changed block, the client reads the block from the disk, compresses it using Zlib, and sends it to the server in a custom binary frame format `[Index (4 bytes)][Length (4 bytes)][Compressed Data]`.
6. **Server Processing (`ManifestServer.java`)**: The server receives the `APPLY_DELTA` request, validates the HMAC signature using a Pre-Shared Key (PSK), and then reads the incoming block frames. It decompresses each block and writes it directly to the correct byte offset in its local file using `RandomAccessFile`.
7. **Integrity Check (`ManifestServer.java`)**: After writing all blocks, the server recalculates the SHA-256 hash of the complete file and verifies it against the hash sent by the client. If they match, the sync is successful.

## Key Java Components

The project is structured around standard Java APIs to keep it lightweight. The only external dependency is `org.json` for JSON parsing.

*   `Main.java`: The entry point. It parses the command-line arguments (like `server` vs `sync`, host, port, etc.) and routes execution to either `ManifestServer` or `DeltaSyncClient`.
*   `DeltaSyncClient.java`: Implements the client-side logic. It orchestrates building the local manifest, fetching the remote manifest, diffing them, performing the secure HMAC handshake, and uploading the modified, Zlib-compressed blocks over a TCP `Socket`.
*   `ManifestServer.java`: Implements the server. It uses a `ServerSocket` to listen for incoming connections and an `ExecutorService` (cached thread pool) to handle multiple clients concurrently. It processes `GET_MANIFEST` and `APPLY_DELTA` commands, strictly validating inputs and preventing path traversal attacks when writing to disk.
*   `BlockAnalysis.java`: Contains the core logic for reading files into fixed-size blocks (`InputStream`), calculating SHA-256 hashes (`java.security.MessageDigest`), and comparing the manifests.
*   `Protocol.java`: Handles the low-level TCP communication. It implements a simple framing protocol where every message is prefixed with a 4-byte big-endian integer representing the length of the payload, ensuring messages are read completely from the TCP stream.
*   `CryptoUtil.java`: Provides cryptographic utility functions. It implements the HMAC-SHA256 signature generation and, crucially, a constant-time string comparison (`constantTimeEquals`) to prevent timing attacks when verifying signatures.
*   `Zlib.java`: A simple wrapper around Java's built-in `java.util.zip.Deflater` and `Inflater` classes to compress and decompress the individual file blocks before they are sent over the network.
*   `ProgressBar.java`: A terminal-based progress bar used by the client to show upload progress.

## Why this Architecture?

- **Network Efficiency**: By hashing blocks and only sending diffs, the system minimizes network bandwidth usage. Zlib compression further reduces payload size.
- **Low Memory Footprint**: Files are read, hashed, compressed, and written block-by-block. The application never loads the entire file into memory, allowing it to sync massive files efficiently.
- **Concurrency**: The server handles each connection in a separate thread, allowing it to serve manifests to some clients while applying data blocks from others simultaneously.
- **Security**: The HMAC handshake ensures that only clients who possess the Pre-Shared Key (PSK) can write data to the server. The server also guarantees file integrity by verifying the whole-file hash after applying updates.
