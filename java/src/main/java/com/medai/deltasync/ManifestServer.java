package com.medai.deltasync;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Java port of {@code server/manifest_server.py}.
 *
 * <p>Accepts TCP connections and handles two commands:
 * <ul>
 *   <li>{@code GET_MANIFEST} — returns the SHA-256 manifest of a file</li>
 *   <li>{@code APPLY_DELTA}  — receives changed blocks, patches the file in
 *       place, then re-hashes the full file to verify integrity</li>
 * </ul>
 *
 * <p>Path traversal is blocked: every requested filename is resolved relative
 * to {@code baseDir} and rejected if it escapes that directory.
 */
public final class ManifestServer {

    private ManifestServer() { }

    public static void start(String host, int port, Path baseDir, int blockSize, String psk) throws IOException {
        Path basePath = realOrAbsolute(baseDir);

        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "deltasync-worker");
            t.setDaemon(true);
            return t;
        });

        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(host, port));
            System.out.println("Manifest server listening on " + host + ":" + port
                    + ", base dir: " + basePath);

            while (!Thread.currentThread().isInterrupted()) {
                Socket client = serverSocket.accept();
                System.out.println("Accepted connection from " + client.getRemoteSocketAddress());
                pool.submit(() -> handleClient(client, basePath, blockSize, psk));
            }
        }
    }

    /**
     * Resolve {@code base} to an absolute, normalized path. Prefers
     * {@code toRealPath()} (which also resolves symlinks, like Python's
     * {@code Path.resolve()}) but falls back to a normalized absolute path
     * if the directory doesn't exist yet.
     */
    private static Path realOrAbsolute(Path base) {
        try {
            return base.toRealPath();
        } catch (IOException e) {
            return base.toAbsolutePath().normalize();
        }
    }

    private static void handleClient(Socket client, Path baseDir, int blockSize, String psk) {
        try (Socket c = client) {
            byte[] raw;
            try {
                raw = Protocol.recvMessage(c);
            } catch (IOException eof) {
                return;     // peer closed before sending anything
            }
            if (raw.length == 0) return;

            JSONObject payload;
            try {
                payload = new JSONObject(new String(raw, StandardCharsets.UTF_8));
            } catch (JSONException e) {
                sendError(c, "INVALID_JSON");
                return;
            }

            Object cmd = payload.opt("command");
            if (!(cmd instanceof String command)) {
                sendError(c, "UNKNOWN_COMMAND");
                return;
            }

            switch (command) {
                case "GET_MANIFEST" -> handleGetManifest(c, baseDir, blockSize, payload);
                case "APPLY_DELTA"  -> applyDelta(c, baseDir, payload, blockSize, psk);
                default             -> sendError(c, "UNKNOWN_COMMAND");
            }
        } catch (IOException ignored) {
            // connection torn down; nothing else we can do
        }
    }

    private static void handleGetManifest(Socket sock, Path baseDir, int blockSize, JSONObject payload)
            throws IOException {
        Object filenameObj = payload.opt("filename");
        if (!(filenameObj instanceof String filename)) {
            sendError(sock, "INVALID_FILENAME");
            return;
        }
        Path filePath = resolveFilePath(baseDir, filename);
        if (filePath == null) {
            sendError(sock, "INVALID_PATH");
            return;
        }
        if (!Files.exists(filePath) || !Files.isRegularFile(filePath)) {
            sendError(sock, "NOT_FOUND");
            return;
        }

        List<ManifestEntry> manifest = BlockAnalysis.buildManifest(filePath, blockSize);
        JSONArray arr = new JSONArray();
        for (ManifestEntry e : manifest) {
            arr.put(new JSONObject()
                    .put("index",      e.index())
                    .put("hash",       e.hash())
                    .put("start_byte", e.startByte()));
        }
        Protocol.sendMessage(sock,
                new JSONObject().put("manifest", arr).toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void applyDelta(Socket sock,
                                   Path baseDir,
                                   JSONObject payload,
                                   int defaultBlockSize,
                                   String psk) throws IOException {
        Object filenameObj = payload.opt("filename");
        if (!(filenameObj instanceof String filename)) {
            sendError(sock, "INVALID_FILENAME");
            return;
        }

        // block_size: must be a positive int
        Object blockSizeObj = payload.opt("block_size");
        int blockSize = defaultBlockSize;
        if (blockSizeObj instanceof Number bn) {
            blockSize = bn.intValue();
        } else if (blockSizeObj != null) {
            sendError(sock, "INVALID_BLOCK_SIZE");
            return;
        }
        if (blockSize <= 0) {
            sendError(sock, "INVALID_BLOCK_SIZE");
            return;
        }

        // file_size: must be a non-negative long
        Object fileSizeObj = payload.opt("file_size");
        if (!(fileSizeObj instanceof Number fsn)) {
            sendError(sock, "INVALID_FILE_SIZE");
            return;
        }
        long fileSize = fsn.longValue();
        if (fileSize < 0) {
            sendError(sock, "INVALID_FILE_SIZE");
            return;
        }

        // blocks_count: must be a non-negative int
        Object blocksCountObj = payload.opt("blocks_count");
        if (!(blocksCountObj instanceof Number bcn)) {
            sendError(sock, "INVALID_BLOCK_COUNT");
            return;
        }
        int blocksCount = bcn.intValue();
        if (blocksCount < 0) {
            sendError(sock, "INVALID_BLOCK_COUNT");
            return;
        }

        if (!(payload.opt("full_hash") instanceof String fullHash)) {
            sendError(sock, "INVALID_FILE_HASH");
            return;
        }
        if (!(payload.opt("nonce") instanceof String nonce)) {
            sendError(sock, "INVALID_NONCE");
            return;
        }
        if (!(payload.opt("hmac") instanceof String signature)) {
            sendError(sock, "INVALID_HMAC");
            return;
        }

        if (psk == null || psk.isEmpty()) {
            sendError(sock, "PSK_REQUIRED");
            return;
        }

        String signingPayload = nonce + ":" + filename + ":" + fileSize + ":"
                              + blockSize + ":" + fullHash;
        String expected = CryptoUtil.hmacSha256Hex(psk, signingPayload);
        if (!CryptoUtil.constantTimeEquals(expected, signature)) {
            sendError(sock, "HMAC_MISMATCH");
            return;
        }

        Path filePath = resolveFilePath(baseDir, filename);
        if (filePath == null) {
            sendError(sock, "INVALID_PATH");
            return;
        }
        Path parent = filePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "rw")) {
            raf.setLength(fileSize);

            for (int i = 0; i < blocksCount; i++) {
                byte[] frame = Protocol.recvMessage(sock);
                if (frame.length == 0)  { sendError(sock, "EMPTY_BLOCK");           return; }
                if (frame.length < 8)   { sendError(sock, "INVALID_BLOCK_HEADER");  return; }

                ByteBuffer bb = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN);
                int index   = bb.getInt();
                int dataLen = bb.getInt();
                int compLen = frame.length - 8;
                if (dataLen != compLen) { sendError(sock, "INVALID_BLOCK_LENGTH");  return; }

                byte[] compressed = new byte[compLen];
                bb.get(compressed);

                byte[] data;
                try {
                    data = Zlib.decompress(compressed);
                } catch (IOException e) {
                    sendError(sock, "DECOMPRESSION_FAILED");
                    return;
                }
                if (data.length > blockSize) {
                    sendError(sock, "INVALID_BLOCK_SIZE");
                    return;
                }
                if ((long) index * blockSize + data.length > fileSize) {
                    sendError(sock, "INVALID_BLOCK_RANGE");
                    return;
                }

                raf.seek((long) index * blockSize);
                raf.write(data);
            }
        }

        String computedHash = BlockAnalysis.computeFileHash(filePath, blockSize);
        if (!CryptoUtil.constantTimeEquals(computedHash, fullHash)) {
            sendError(sock, "HASH_MISMATCH");
            return;
        }

        JSONObject ok = new JSONObject().put("status", "OK").put("applied_blocks", blocksCount);
        Protocol.sendMessage(sock, ok.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Resolve {@code filename} relative to {@code baseDir} and reject any
     * path that escapes the base directory.
     */
    private static Path resolveFilePath(Path baseDir, String filename) {
        Path resolved = baseDir.resolve(filename).toAbsolutePath().normalize();
        if (!resolved.startsWith(baseDir)) {
            return null;
        }
        return resolved;
    }

    private static void sendError(Socket sock, String code) throws IOException {
        Protocol.sendMessage(sock,
                new JSONObject().put("error", code).toString().getBytes(StandardCharsets.UTF_8));
    }
}
