package com.medai.deltasync;

/**
 * One entry of a fixed-block manifest.
 *
 * <p>Mirrors the Python {@code ManifestEntry} TypedDict — JSON shape
 * {@code {"index": ..., "hash": ..., "start_byte": ...}} is preserved
 * exactly so a Java client can talk to a Python server (and vice-versa).
 *
 * @param index      zero-based block index
 * @param hash       hex SHA-256 digest of the block
 * @param startByte  starting byte offset of the block within the file
 */
public record ManifestEntry(int index, String hash, long startByte) {}
