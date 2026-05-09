package com.deltasync;

import com.google.gson.Gson;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Server {

    private static final Gson GSON = new Gson();

    public static void start(String[] args) {
        String host = null;
        int port = -1;
        Path baseDir = Paths.get(".");
        int blockSize = Core.DEFAULT_BLOCK_SIZE;
        String psk = System.getenv("DELTA_SYNC_PSK");

        for (int i = 1; i < args.length; i++) {
            if ("--base-dir".equals(args[i]) && i + 1 < args.length) {
                baseDir = Paths.get(args[++i]);
            } else if (("-b".equals(args[i]) || "--block-size".equals(args[i])) && i + 1 < args.length) {
                blockSize = Integer.parseInt(args[++i]);
            } else if ("--psk".equals(args[i]) && i + 1 < args.length) {
                psk = args[++i];
            } else if (host == null) {
                host = args[i];
            } else if (port == -1) {
                port = Integer.parseInt(args[i]);
            }
        }

        if (host == null || port == -1) {
            System.err.println("Usage: java -jar deltasync.jar server <host> <port> [options]");
            System.exit(1);
        }

        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.bind(new java.net.InetSocketAddress(host, port));
            System.out.println("Manifest server listening on " + host + ":" + port + ", base dir: " + baseDir.toAbsolutePath());
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Accepted connection from " + clientSocket.getRemoteSocketAddress());
                final Path finalBaseDir = baseDir;
                final int finalBlockSize = blockSize;
                final String finalPsk = psk;
                new Thread(() -> handleClient(clientSocket, finalBaseDir, finalBlockSize, finalPsk)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket, Path baseDir, int blockSize, String psk) {
        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            byte[] raw = NetworkUtil.recvMessage(dis);
            if (raw.length == 0) return;

            String json = new String(raw, "UTF-8");
            Payloads.Request request;
            try {
                request = GSON.fromJson(json, Payloads.Request.class);
            } catch (Exception e) {
                sendError(dos, "INVALID_JSON");
                return;
            }

            if (request == null || request.command == null) {
                sendError(dos, "UNKNOWN_COMMAND");
                return;
            }

            if ("GET_MANIFEST".equals(request.command)) {
                handleGetManifest(dos, request, baseDir, blockSize);
            } else if ("APPLY_DELTA".equals(request.command)) {
                handleApplyDelta(dis, dos, request, baseDir, blockSize, psk);
            } else {
                sendError(dos, "UNKNOWN_COMMAND");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static void handleGetManifest(DataOutputStream dos, Payloads.Request request, Path baseDir, int blockSize) throws IOException {
        if (request.filename == null) {
            sendError(dos, "INVALID_FILENAME");
            return;
        }

        Path filePath = resolveFilePath(baseDir, request.filename);
        if (filePath == null) {
            sendError(dos, "INVALID_PATH");
            return;
        }

        if (!filePath.toFile().exists() || !filePath.toFile().isFile()) {
            sendError(dos, "NOT_FOUND");
            return;
        }

        List<ManifestEntry> manifest = Core.buildManifest(filePath, blockSize);
        Payloads.Response response = new Payloads.Response();
        response.manifest = manifest;
        NetworkUtil.sendMessage(dos, GSON.toJson(response).getBytes("UTF-8"));
    }

    private static void handleApplyDelta(DataInputStream dis, DataOutputStream dos, Payloads.Request request, Path baseDir, int defaultBlockSize, String psk) throws Exception {
        if (request.filename == null) {
            sendError(dos, "INVALID_FILENAME");
            return;
        }
        int blockSize = request.block_size != null ? request.block_size : defaultBlockSize;
        if (blockSize <= 0) {
            sendError(dos, "INVALID_BLOCK_SIZE");
            return;
        }
        if (request.file_size == null || request.file_size < 0) {
            sendError(dos, "INVALID_FILE_SIZE");
            return;
        }
        if (request.blocks_count == null || request.blocks_count < 0) {
            sendError(dos, "INVALID_BLOCK_COUNT");
            return;
        }
        if (request.full_hash == null) {
            sendError(dos, "INVALID_FILE_HASH");
            return;
        }
        if (request.nonce == null) {
            sendError(dos, "INVALID_NONCE");
            return;
        }
        if (request.hmac == null) {
            sendError(dos, "INVALID_HMAC");
            return;
        }
        if (psk == null) {
            sendError(dos, "PSK_REQUIRED");
            return;
        }

        String signingPayload = request.nonce + ":" + request.filename + ":" + request.file_size + ":" + blockSize + ":" + request.full_hash;
        String expectedHmac = Core.computeHMAC(psk, signingPayload);
        if (!java.security.MessageDigest.isEqual(expectedHmac.getBytes("UTF-8"), request.hmac.getBytes("UTF-8"))) {
            sendError(dos, "HMAC_MISMATCH");
            return;
        }

        Path filePath = resolveFilePath(baseDir, request.filename);
        if (filePath == null) {
            sendError(dos, "INVALID_PATH");
            return;
        }

        filePath.toFile().getParentFile().mkdirs();
        try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "rw")) {
            raf.setLength(request.file_size);
            for (int i = 0; i < request.blocks_count; i++) {
                byte[] blockMessage = NetworkUtil.recvMessage(dis);
                if (blockMessage.length == 0) {
                    sendError(dos, "EMPTY_BLOCK");
                    return;
                }
                if (blockMessage.length < 8) {
                    sendError(dos, "INVALID_BLOCK_HEADER");
                    return;
                }

                int index = (blockMessage[0] << 24) | ((blockMessage[1] & 0xFF) << 16) | ((blockMessage[2] & 0xFF) << 8) | (blockMessage[3] & 0xFF);
                int dataLen = (blockMessage[4] << 24) | ((blockMessage[5] & 0xFF) << 16) | ((blockMessage[6] & 0xFF) << 8) | (blockMessage[7] & 0xFF);

                byte[] compressed = new byte[blockMessage.length - 8];
                System.arraycopy(blockMessage, 8, compressed, 0, compressed.length);

                if (dataLen != compressed.length) {
                    sendError(dos, "INVALID_BLOCK_LENGTH");
                    return;
                }

                byte[] data;
                try {
                    data = Core.decompressZlib(compressed);
                } catch (Exception e) {
                    sendError(dos, "DECOMPRESSION_FAILED");
                    return;
                }

                if (data.length > blockSize) {
                    sendError(dos, "INVALID_BLOCK_SIZE");
                    return;
                }
                if ((long) index * blockSize + data.length > request.file_size) {
                    sendError(dos, "INVALID_BLOCK_RANGE");
                    return;
                }

                raf.seek((long) index * blockSize);
                raf.write(data);
            }
        }

        String computedHash = Core.computeFileHash(filePath, blockSize);
        if (!computedHash.equals(request.full_hash)) {
            sendError(dos, "HASH_MISMATCH");
            return;
        }

        Payloads.Response response = new Payloads.Response();
        response.status = "OK";
        response.applied_blocks = request.blocks_count;
        NetworkUtil.sendMessage(dos, GSON.toJson(response).getBytes("UTF-8"));
    }

    private static void sendError(DataOutputStream dos, String error) throws IOException {
        Payloads.Response response = new Payloads.Response();
        response.error = error;
        NetworkUtil.sendMessage(dos, GSON.toJson(response).getBytes("UTF-8"));
    }

    private static Path resolveFilePath(Path baseDir, String filename) {
        Path resolved = baseDir.resolve(filename).normalize();
        if (!resolved.startsWith(baseDir.normalize())) {
            return null;
        }
        return resolved;
    }
}
