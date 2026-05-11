package com.medai.deltasync;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Fixed-block file analysis — Java port of {@code scripts/fixed_block_analysis.py}.
 *
 * <p>Builds SHA-256 manifests over fixed-size blocks, computes whole-file
 * hashes, and diffs two manifests by index.
 */
public final class BlockAnalysis {

    /** Default block size (64 KiB) — matches Python {@code DEFAULT_BLOCK_SIZE}. */
    public static final int DEFAULT_BLOCK_SIZE = 64 * 1024;

    private BlockAnalysis() {}

    /**
     * Build a manifest of SHA-256 hashes, one entry per fixed-size block.
     *
     * <p>The final block may be shorter than {@code blockSize} — this matches
     * the Python implementation's behavior of yielding whatever
     * {@code file.read(blockSize)} returns.
     */
    public static List<ManifestEntry> buildManifest(
        Path filePath,
        int blockSize
    ) throws IOException {
        if (blockSize <= 0) {
            throw new IllegalArgumentException(
                "blockSize must be a positive integer"
            );
        }

        List<ManifestEntry> manifest = new ArrayList<>();
        byte[] buf = new byte[blockSize];
        long offset = 0;
        int index = 0;

        try (InputStream in = Files.newInputStream(filePath)) {
            while (true) {
                int n = readBlock(in, buf);
                if (n <= 0) break;
                String digest = sha256Hex(buf, 0, n);
                manifest.add(new ManifestEntry(index, digest, offset));
                offset += n;
                index++;
            }
        }
        return manifest;
    }

    /** Compute the SHA-256 of an entire file (hex). */
    public static String computeFileHash(Path filePath, int blockSize)
        throws IOException {
        MessageDigest md = sha256();
        byte[] buf = new byte[blockSize];
        try (InputStream in = Files.newInputStream(filePath)) {
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        return HexUtil.toHex(md.digest());
    }

    /**
     * Return the sorted list of block indices that differ between two manifests.
     * An index appearing in only one manifest, or in both with different hashes,
     * is considered changed.
     */
    public static List<Integer> compareManifests(
        List<ManifestEntry> local,
        List<ManifestEntry> remote
    ) {
        Map<Integer, String> localMap = new HashMap<>();
        Map<Integer, String> remoteMap = new HashMap<>();
        for (ManifestEntry e : local) localMap.put(e.index(), e.hash());
        for (ManifestEntry e : remote) remoteMap.put(e.index(), e.hash());

        TreeSet<Integer> all = new TreeSet<>();
        all.addAll(localMap.keySet());
        all.addAll(remoteMap.keySet());

        List<Integer> diff = new ArrayList<>();
        for (Integer i : all) {
            String l = localMap.get(i);
            String r = remoteMap.get(i);
            if (l == null || r == null || !l.equals(r)) {
                diff.add(i);
            }
        }
        return diff;
    }

    /**
     * Read up to {@code buf.length} bytes from {@code in}, retrying on short
     * reads — equivalent to a single Python {@code file.read(blockSize)}
     * which collapses any underlying short reads.
     */
    private static int readBlock(InputStream in, byte[] buf)
        throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) break;
            total += n;
        }
        return total;
    }

    public static String sha256Hex(byte[] data, int offset, int length) {
        MessageDigest md = sha256();
        md.update(data, offset, length);
        return HexUtil.toHex(md.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
