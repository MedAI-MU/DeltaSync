package com.medai.deltasync;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * DeltaSync command-line entry point — mirrors the Python {@code main.py}.
 *
 * <pre>
 *   deltasync server &lt;host&gt; &lt;port&gt; [--base-dir DIR] [-b N] [--psk KEY]
 *   deltasync sync   &lt;host&gt; &lt;port&gt; &lt;file&gt; [--remote-name NAME] [-b N]
 *                                          [--timeout SECS] [--psk KEY] [--no-progress]
 * </pre>
 */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        String mode = args[0];
        String[] rest = new String[args.length - 1];
        System.arraycopy(args, 1, rest, 0, rest.length);

        try {
            switch (mode) {
                case "server" -> runServer(rest);
                case "sync" -> runSync(rest);
                case "-h", "--help", "help" -> usage();
                default -> {
                    System.err.println("Unknown mode: " + mode);
                    usage();
                    System.exit(2);
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            usage();
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void runServer(String[] args) throws Exception {
        ArgParser p = new ArgParser(args, List.of("host", "port"), Set.of());

        String host = p.positional(0);
        int port = parsePort(p.positional(1));
        String baseDir = p.opt("--base-dir", ".");
        int blockSz = parsePositiveInt(
            p.opt(
                List.of("-b", "--block-size"),
                String.valueOf(BlockAnalysis.DEFAULT_BLOCK_SIZE)
            ),
            "--block-size"
        );
        String psk = p.opt("--psk", System.getenv("DELTA_SYNC_PSK"));

        ManifestServer.start(host, port, Paths.get(baseDir), blockSz, psk);
    }

    private static void runSync(String[] args) throws Exception {
        ArgParser p = new ArgParser(
            args,
            List.of("host", "port", "file"),
            Set.of("--no-progress")
        );

        String host = p.positional(0);
        int port = parsePort(p.positional(1));
        Path file = Paths.get(p.positional(2));
        String remoteName = p.opt("--remote-name", null);
        int blockSz = parsePositiveInt(
            p.opt(
                List.of("-b", "--block-size"),
                String.valueOf(BlockAnalysis.DEFAULT_BLOCK_SIZE)
            ),
            "--block-size"
        );
        double timeout = Double.parseDouble(p.opt("--timeout", "10.0"));
        String psk = p.opt("--psk", null);
        boolean noBar = p.flag("--no-progress");

        List<Integer> synced = DeltaSyncClient.sendDeltaSync(
            host,
            port,
            file,
            remoteName,
            blockSz,
            timeout,
            psk,
            !noBar
        );

        JSONArray arr = new JSONArray();
        for (Integer i : synced) arr.put(i.intValue());
        System.out.println(
            new JSONObject().put("synced_blocks", arr).toString(2)
        );
    }

    private static int parsePort(String s) {
        int port = Integer.parseInt(s);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException(
                "Port must be in 1..65535: " + s
            );
        }
        return port;
    }

    private static int parsePositiveInt(String s, String name) {
        int v = Integer.parseInt(s);
        if (v <= 0) throw new IllegalArgumentException(
            name + " must be positive: " + s
        );
        return v;
    }

    private static void usage() {
        System.err.println(
            """
            DeltaSync — block-level file sync over TCP

            Usage:
              deltasync server <host> <port> [--base-dir DIR] [-b|--block-size N] [--psk KEY]
              deltasync sync   <host> <port> <file>
                               [--remote-name NAME] [-b|--block-size N]
                               [--timeout SECS] [--psk KEY] [--no-progress]

            Defaults:
              --block-size  65536
              --timeout     10.0
              --base-dir    .
              --psk         falls back to DELTA_SYNC_PSK environment variable
            """
        );
    }
}
