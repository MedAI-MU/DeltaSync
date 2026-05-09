package com.deltasync;

public class Main {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar deltasync.jar <server|sync> [args...]");
            System.exit(1);
        }

        String mode = args[0];
        if ("server".equals(mode)) {
            Server.start(args);
        } else if ("sync".equals(mode)) {
            Client.sync(args);
        } else {
            System.err.println("Unknown mode: " + mode);
            System.exit(1);
        }
    }
}
