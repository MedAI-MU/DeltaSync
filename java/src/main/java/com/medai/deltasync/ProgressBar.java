package com.medai.deltasync;

import java.io.PrintStream;

/**
 * Minimal stderr progress bar — replaces Python's {@code tqdm} dependency.
 *
 * <p>Updates throttle to ~10 redraws per second to keep output readable
 * on slow terminals.
 */
public final class ProgressBar implements AutoCloseable {

    private static final int    BAR_WIDTH       = 30;
    private static final long   MIN_REDRAW_NS   = 100_000_000L;  // ~10 fps

    private final long  total;
    private final String desc;
    private final PrintStream out;

    private long  current;
    private long  lastRenderNs;
    private boolean closed;

    public ProgressBar(long total, String desc) {
        this.total = total;
        this.desc  = desc;
        this.out   = System.err;
        render(true);
    }

    public void update(long delta) {
        current += delta;
        long now = System.nanoTime();
        if (now - lastRenderNs >= MIN_REDRAW_NS || current >= total) {
            render(false);
            lastRenderNs = now;
        }
    }

    private void render(boolean force) {
        double frac = total <= 0 ? 1.0 : Math.min(1.0, (double) current / total);
        int filled  = (int) (frac * BAR_WIDTH);

        StringBuilder sb = new StringBuilder(96);
        sb.append('\r').append(desc).append(": [");
        for (int i = 0; i < BAR_WIDTH; i++) sb.append(i < filled ? '#' : '-');
        sb.append("] ")
          .append(humanBytes(current)).append('/').append(humanBytes(total))
          .append(String.format(" (%.1f%%)", frac * 100.0));
        out.print(sb);
    }

    private static String humanBytes(long n) {
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        double v = n;
        int u = 0;
        while (v >= 1024 && u < units.length - 1) {
            v /= 1024;
            u++;
        }
        return u == 0 ? n + " " + units[0] : String.format("%.2f %s", v, units[u]);
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        render(true);
        out.println();
    }
}
