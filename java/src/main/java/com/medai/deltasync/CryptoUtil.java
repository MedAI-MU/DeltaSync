package com.medai.deltasync;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Crypto helpers used by the handshake. */
public final class CryptoUtil {

    private static final SecureRandom RNG = new SecureRandom();

    private CryptoUtil() {}

    /** HMAC-SHA256 over UTF-8 bytes, returned as lowercase hex. */
    public static String hmacSha256Hex(String key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(
                new SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
                )
            );
            byte[] out = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return HexUtil.toHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** Generate a hex nonce equivalent to Python's {@code secrets.token_hex(n)}. */
    public static String tokenHex(int numBytes) {
        byte[] buf = new byte[numBytes];
        RNG.nextBytes(buf);
        return HexUtil.toHex(buf);
    }

    /**
     * Constant-time comparison of two strings — equivalent to Python's
     * {@code hmac.compare_digest}. Always compares all bytes when lengths
     * match; returns {@code false} immediately only on length mismatch.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] ab = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        if (ab.length != bb.length) return false;
        int diff = 0;
        for (int i = 0; i < ab.length; i++) {
            diff |= ab[i] ^ bb[i];
        }
        return diff == 0;
    }
}
