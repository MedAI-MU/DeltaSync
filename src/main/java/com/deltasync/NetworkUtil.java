package com.deltasync;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class NetworkUtil {

    public static void sendMessage(DataOutputStream dos, byte[] message) throws IOException {
        dos.writeInt(message.length);
        dos.write(message);
        dos.flush();
    }

    public static byte[] recvMessage(DataInputStream dis) throws IOException {
        int length = dis.readInt();
        if (length == 0) {
            return new byte[0];
        }
        byte[] data = new byte[length];
        dis.readFully(data);
        return data;
    }
}
