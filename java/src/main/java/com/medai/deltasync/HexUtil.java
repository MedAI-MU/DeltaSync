package com.medai.deltasync;

/** Lowercase hex encoding — matches Python {@code hashlib.sha256(...).hexdigest()}. */
public final class HexUtil {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HexUtil() { }

    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2]     = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0f];
        }
        return new String(out);
    }
}
