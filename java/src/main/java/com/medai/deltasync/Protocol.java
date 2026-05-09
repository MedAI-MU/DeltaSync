package com.medai.deltasync;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;

/**
 * Length-prefixed message framing — wire-compatible with the Python implementation.
 *
 * <p>Each message is a 4-byte big-endian unsigned length followed by exactly
 * that many bytes of payload. A length of zero means an empty payload (which
 * the Python {@code recv_message} represents as {@code b""}).
 */
public final class Protocol {
    private Protocol() { }

    /** Send {@code message} prefixed with a 4-byte big-endian length. */
    public static void sendMessage(Socket sock, byte[] message) throws IOException {
        DataOutputStream out = new DataOutputStream(sock.getOutputStream());
        out.writeInt(message.length);   // big-endian by spec of writeInt
        out.write(message);
        out.flush();
    }

    /**
     * Receive a single length-prefixed message.
     *
     * @return the payload bytes (possibly empty if the length was 0)
     * @throws EOFException if the peer closed the socket before the full
     *                      message could be read
     */
    public static byte[] recvMessage(Socket sock) throws IOException {
        DataInputStream in = new DataInputStream(sock.getInputStream());
        int length = in.readInt();      // throws EOFException on clean close
        if (length == 0) {
            return new byte[0];
        }
        if (length < 0) {
            throw new IOException("Negative message length: " + length);
        }
        byte[] buf = new byte[length];
        in.readFully(buf);
        return buf;
    }
}
