package com.deltasync;

import com.google.gson.Gson;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class Client {

    private static final Gson GSON = new Gson();

    public static void sync(String[] args) {
        String host = null;
        int port = -1;
        Path file = null;
        String remoteName = null;
        int blockSize = Core.DEFAULT_BLOCK_SIZE;
        int timeout = 10000;
        String psk = System.getenv("DELTA_SYNC_PSK");
        boolean noProgress = false;

        for (int i = 1; i < args.length; i++) {
            if ("--remote-name".equals(args[i]) && i + 1 < args.length) {
                remoteName = args[++i];
            } else if (("-b".equals(args[i]) || "--block-size".equals(args[i])) && i + 1 < args.length) {
                blockSize = Integer.parseInt(args[++i]);
            } else if ("--timeout".equals(args[i]) && i + 1 < args.length) {
                timeout = (int) (Double.parseDouble(args[++i]) * 1000);
            } else if ("--psk".equals(args[i]) && i + 1 < args.length) {
                psk = args[++i];
            } else if ("--no-progress".equals(args[i])) {
                noProgress = true;
            } else if (host == null) {
                host = args[i];
            } else if (port == -1) {
                port = Integer.parseInt(args[i]);
            } else if (file == null) {
                file = Paths.get(args[i]);
            }
        }

        if (host == null || port == -1 || file == null) {
            System.err.println("Usage: java -jar deltasync.jar sync <host> <port> <file> [options]");
            System.exit(1);
        }

        if (remoteName == null) {
            remoteName = file.getFileName().toString();
        }

        if (psk == null) {
            System.err.println("PSK is required for delta sync");
            System.exit(1);
        }

        try {
            List<Integer> synced = sendDeltaSync(host, port, file, remoteName, blockSize, timeout, psk, !noProgress);
            System.out.println("{\n  \"synced_blocks\": " + GSON.toJson(synced) + "\n}");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static List<Integer> sendDeltaSync(String host, int port, Path filePath, String remoteFilename, int blockSize, int timeout, String psk, boolean showProgress) throws Exception {
        List<ManifestEntry> localManifest = Core.buildManifest(filePath, blockSize);
        List<ManifestEntry> remoteManifest = requestManifest(host, port, remoteFilename, timeout);

        List<Integer> diffIndices = compareManifests(localManifest, remoteManifest);
        Set<Integer> localIndexSet = localManifest.stream().map(e -> e.index).collect(Collectors.toSet());
        List<Integer> sendIndices = diffIndices.stream().filter(localIndexSet::contains).collect(Collectors.toList());

        long fileSize = filePath.toFile().length();
        String fullHash = Core.computeFileHash(filePath, blockSize);
        String nonce = UUID.randomUUID().toString().replace("-", "");

        String signingPayload = nonce + ":" + remoteFilename + ":" + fileSize + ":" + blockSize + ":" + fullHash;
        String signature = Core.computeHMAC(psk, signingPayload);

        Payloads.Request request = new Payloads.Request();
        request.command = "APPLY_DELTA";
        request.filename = remoteFilename;
        request.block_size = blockSize;
        request.file_size = fileSize;
        request.blocks_count = sendIndices.size();
        request.full_hash = fullHash;
        request.nonce = nonce;
        request.hmac = signature;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream())) {

                NetworkUtil.sendMessage(dos, GSON.toJson(request).getBytes("UTF-8"));

                long totalBytes = 0;
                for (int index : sendIndices) {
                    long remaining = fileSize - (long) index * blockSize;
                    totalBytes += Math.max(0, Math.min(blockSize, remaining));
                }

                long uploaded = 0;
                try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "r")) {
                    for (int index : sendIndices) {
                        raf.seek((long) index * blockSize);
                        long remaining = fileSize - (long) index * blockSize;
                        int toRead = (int) Math.min(blockSize, remaining);
                        byte[] data = new byte[toRead];
                        raf.readFully(data);

                        byte[] compressed = Core.compressZlib(data);
                        byte[] blockPayload = new byte[8 + compressed.length];

                        blockPayload[0] = (byte) (index >> 24);
                        blockPayload[1] = (byte) (index >> 16);
                        blockPayload[2] = (byte) (index >> 8);
                        blockPayload[3] = (byte) index;

                        int cLen = compressed.length;
                        blockPayload[4] = (byte) (cLen >> 24);
                        blockPayload[5] = (byte) (cLen >> 16);
                        blockPayload[6] = (byte) (cLen >> 8);
                        blockPayload[7] = (byte) cLen;

                        System.arraycopy(compressed, 0, blockPayload, 8, compressed.length);
                        NetworkUtil.sendMessage(dos, blockPayload);

                        uploaded += toRead;
                        if (showProgress) {
                            System.out.print("\rUploading: " + uploaded + " / " + totalBytes + " B");
                        }
                    }
                }
                if (showProgress) System.out.println();

                byte[] responseRaw = NetworkUtil.recvMessage(dis);
                if (responseRaw.length == 0) {
                    throw new RuntimeException("Empty response from server");
                }

                Payloads.Response response = GSON.fromJson(new String(responseRaw, "UTF-8"), Payloads.Response.class);
                if (response.error != null) {
                    throw new RuntimeException("Server error: " + response.error);
                }
            }
        }
        return sendIndices;
    }

    private static List<ManifestEntry> requestManifest(String host, int port, String filename, int timeout) throws Exception {
        Payloads.Request request = new Payloads.Request();
        request.command = "GET_MANIFEST";
        request.filename = filename;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            try (DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream())) {

                NetworkUtil.sendMessage(dos, GSON.toJson(request).getBytes("UTF-8"));
                byte[] responseRaw = NetworkUtil.recvMessage(dis);
                if (responseRaw.length == 0) {
                    throw new RuntimeException("Empty response from server");
                }

                Payloads.Response response = GSON.fromJson(new String(responseRaw, "UTF-8"), Payloads.Response.class);
                if (response.error != null) {
                    if ("NOT_FOUND".equals(response.error)) {
                        return new ArrayList<>();
                    }
                    throw new RuntimeException("Server error: " + response.error);
                }
                return response.manifest != null ? response.manifest : new ArrayList<>();
            }
        }
    }

    private static List<Integer> compareManifests(List<ManifestEntry> localManifest, List<ManifestEntry> remoteManifest) {
        Map<Integer, String> localMap = localManifest.stream().collect(Collectors.toMap(e -> e.index, e -> e.hash));
        Map<Integer, String> remoteMap = remoteManifest.stream().collect(Collectors.toMap(e -> e.index, e -> e.hash));

        Set<Integer> allIndices = new HashSet<>(localMap.keySet());
        allIndices.addAll(remoteMap.keySet());

        return allIndices.stream()
                .filter(index -> {
                    String localHash = localMap.get(index);
                    String remoteHash = remoteMap.get(index);
                    return localHash == null || !localHash.equals(remoteHash);
                })
                .sorted()
                .collect(Collectors.toList());
    }
}
