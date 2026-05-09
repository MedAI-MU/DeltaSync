package com.deltasync;

import java.util.List;

public class Payloads {

    public static class Request {
        public String command;
        public String filename;
        public Integer block_size;
        public Long file_size;
        public Integer blocks_count;
        public String full_hash;
        public String nonce;
        public String hmac;
    }

    public static class Response {
        public String error;
        public List<ManifestEntry> manifest;
        public String status;
        public Integer applied_blocks;
    }
}
