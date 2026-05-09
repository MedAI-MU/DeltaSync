package com.medai.deltasync;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Java port of the client half of {@code scripts/fixed_block_analysis.py}.
 *
 * <p>Computes a local manifest, asks the server for its manifest, diffs
 * them, and uploads only the blocks that differ — guarded by an HMAC-SHA256
 * handshake and verified by a whole-file hash comparison on the server.
 */
public final class DeltaSyncClient {

    private DeltaSyncClient() { }

    /**
     * Sync {@code filePath} to the remote server. Returns the list of block
     * indices that were actually uploaded.
     */
    public static List<Integer> sendDeltaSync(String host,
                                              int    port,
                                              Path   filePath,
                                              String remoteFilename,
                                              int    blockSize,
                                              double timeoutSeconds,
                                              String psk,
                                              boolean showProgress) throws IOException {

        if (remoteFilename == null || remoteFilename.isEmpty()) {
            remoteFilename = filePath.getFileName().toString();
        }

        // Build local manifest, fetch remote, compute the upload set.
        List<ManifestEntry> localManifest  = BlockAnalysis.buildManifest(filePath, blockSize);
        List<ManifestEntry> remoteManifest = requestManifest(host, port, remoteFilename, timeoutSeconds, true);
        List<Integer> diffIndices = BlockAnalysis.compareManifests(localManifest, remoteManifest);

        Set<Integer> localIndexSet = new HashSet<>();
        for (ManifestEntry e : localManifest) localIndexSet.add(e.index());

        List<Integer> sendIndices = new ArrayList<>();
        for (Integer idx : diffIndices) {
            if (localIndexSet.contains(idx)) sendIndices.add(idx);
        }

        long   fileSize = Files.size(filePath);
        String fullHash = BlockAnalysis.computeFileHash(filePath, blockSize);

        // PSK: explicit arg, else env var.
        String resolvedPsk = (psk != null && !psk.isEmpty()) ? psk : System.getenv("DELTA_SYNC_PSK");
        if (resolvedPsk == null || resolvedPsk.isEmpty()) {
            throw new IllegalStateException("PSK is required for delta sync");
        }

        // HMAC handshake — exact wire format: nonce:filename:fileSize:blockSize:fullHash
        String nonce          = CryptoUtil.tokenHex(16);
        String signingPayload = nonce + ":" + remoteFilename + ":" + fileSize + ":"
                              + blockSize + ":" + fullHash;
        String signature      = CryptoUtil.hmacSha256Hex(resolvedPsk, signingPayload);

        JSONObject payload = new JSONObject()
                .put("command",      "APPLY_DELTA")
                .put("filename",     remoteFilename)
                .put("block_size",   blockSize)
                .put("file_size",    fileSize)
                .put("blocks_count", sendIndices.size())
                .put("full_hash",    fullHash)
                .put("nonce",        nonce)
                .put("hmac",         signature);

        long totalBytes = 0L;
        for (int idx : sendIndices) {
            long remaining = fileSize - (long) idx * blockSize;
            totalBytes += Math.max(0, Math.min(blockSize, remaining));
        }

        int timeoutMs = (int) (timeoutSeconds * 1000);
        try (Socket sock = new Socket();
             ProgressBar bar = showProgress ? new ProgressBar(totalBytes, "Uploading") : null) {

            sock.connect(new InetSocketAddress(host, port), timeoutMs);
            sock.setSoTimeout(timeoutMs);

            try {
                Protocol.sendMessage(sock, payload.toString().getBytes(StandardCharsets.UTF_8));

                try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "r")) {
                    byte[] buf = new byte[blockSize];
                    for (int idx : sendIndices) {
                        if (idx < 0) {
                            throw new IllegalArgumentException("Block index must be non-negative");
                        }
                        raf.seek((long) idx * blockSize);
                        int n = raf.read(buf);
                        if (n < 0) n = 0;

                        byte[] data = new byte[n];
                        System.arraycopy(buf, 0, data, 0, n);
                        byte[] compressed = Zlib.compress(data);

                        // Block frame: !II header (index, len(compressed)) + compressed bytes
                        ByteBuffer bb = ByteBuffer.allocate(8 + compressed.length).order(ByteOrder.BIG_ENDIAN);
                        bb.putInt(idx);
                        bb.putInt(compressed.length);
                        bb.put(compressed);
                        Protocol.sendMessage(sock, bb.array());

                        if (bar != null) bar.update(n);
                    }
                }
            } catch (IOException writeFailure) {
                // The peer rejected the request early (e.g. PSK_REQUIRED, HMAC_MISMATCH)
                // and closed the socket while we were still streaming blocks, leaving us
                // with a useless "Broken pipe" / "Connection reset" message. Try to read
                // any error response that arrived before the close so we can surface the
                // real reason instead.
                String earlyError = tryReadEarlyError(sock);
                if (earlyError != null) {
                    throw new IOException("Server error: " + earlyError, writeFailure);
                }
                throw writeFailure;
            }

            byte[] responseRaw = Protocol.recvMessage(sock);
            if (responseRaw.length == 0) {
                throw new IOException("Empty response from server");
            }
            JSONObject response = new JSONObject(new String(responseRaw, StandardCharsets.UTF_8));
            if (response.has("error")) {
                throw new IOException("Server error: " + response.getString("error"));
            }
        }

        return sendIndices;
    }

    /**
     * Best-effort read of an error response the server may have sent before
     * closing the socket on us. Returns the error code on success, or
     * {@code null} if no decodable error response is available.
     */
    private static String tryReadEarlyError(Socket sock) {
        try {
            sock.setSoTimeout(500);
            byte[] resp = Protocol.recvMessage(sock);
            if (resp.length == 0) return null;
            JSONObject obj = new JSONObject(new String(resp, StandardCharsets.UTF_8));
            return obj.optString("error", null);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Request the manifest of {@code filename} from the server.
     *
     * @param allowMissing when {@code true}, a {@code NOT_FOUND} response
     *                     becomes an empty manifest instead of an exception
     *                     (this is what we want for the first-ever sync).
     */
    public static List<ManifestEntry> requestManifest(String host,
                                                      int    port,
                                                      String filename,
                                                      double timeoutSeconds,
                                                      boolean allowMissing) throws IOException {
        JSONObject payload = new JSONObject()
                .put("command",  "GET_MANIFEST")
                .put("filename", filename);

        int timeoutMs = (int) (timeoutSeconds * 1000);
        byte[] responseRaw;

        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(host, port), timeoutMs);
            sock.setSoTimeout(timeoutMs);
            Protocol.sendMessage(sock, payload.toString().getBytes(StandardCharsets.UTF_8));
            responseRaw = Protocol.recvMessage(sock);
        }

        if (responseRaw.length == 0) {
            throw new IOException("Empty response from server");
        }

        JSONObject response = new JSONObject(new String(responseRaw, StandardCharsets.UTF_8));
        if (response.has("error")) {
            String err = response.getString("error");
            if (allowMissing && "NOT_FOUND".equals(err)) {
                return new ArrayList<>();
            }
            throw new IOException("Server error: " + err);
        }

        JSONArray manifestArr = response.getJSONArray("manifest");
        return coerceManifest(manifestArr);
    }

    /** Convert a manifest JSON array into typed entries, validating shape. */
    static List<ManifestEntry> coerceManifest(JSONArray arr) {
        List<ManifestEntry> out = new ArrayList<>(arr.length());
        for (int i = 0; i < arr.length(); i++) {
            JSONObject e = arr.getJSONObject(i);
            int   idx       = e.getInt("index");
            String hash     = e.getString("hash");
            long  startByte = e.getLong("start_byte");
            out.add(new ManifestEntry(idx, hash, startByte));
        }
        return out;
    }
}
