package com.medai.deltasync;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Zlib-format compression — wire-compatible with Python's
 * {@code zlib.compress(data)} and {@code zlib.decompress(data)}.
 *
 * <p>Both Java's {@link Deflater}/{@link Inflater} (with {@code nowrap=false},
 * the default) and Python's {@code zlib} module produce/consume the
 * RFC&nbsp;1950 zlib format (2-byte header + Adler-32 trailer).
 */
public final class Zlib {
    private Zlib() { }

    /** Compress {@code data} with default zlib settings. */
    public static byte[] compress(byte[] data) {
        Deflater deflater = new Deflater();
        try {
            deflater.setInput(data);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 2));
            byte[] buf = new byte[8192];
            while (!deflater.finished()) {
                int n = deflater.deflate(buf);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    /**
     * Decompress {@code data}.
     *
     * @throws IOException if the input is not valid zlib data
     */
    public static byte[] decompress(byte[] data) throws IOException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length * 2));
            byte[] buf = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    // 0 means: finished, needs more input, or needs dictionary.
                    // We supplied all input up-front and don't use dictionaries,
                    // so anything other than "finished" is malformed input.
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        throw new IOException("zlib: truncated or malformed stream");
                    }
                    break;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("zlib decompression failed", e);
        } finally {
            inflater.end();
        }
    }
}
