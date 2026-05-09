package com.deltasync;

public class ManifestEntry {
    public int index;
    public String hash;
    public int start_byte;

    public ManifestEntry() {}

    public ManifestEntry(int index, String hash, int start_byte) {
        this.index = index;
        this.hash = hash;
        this.start_byte = start_byte;
    }
}
