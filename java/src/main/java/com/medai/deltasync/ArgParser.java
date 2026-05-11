package com.medai.deltasync;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Minimal argparse-style parser — just enough to mirror the Python CLI:
 * positional args, {@code --long}/{@code -s} options that take a value, and
 * a configurable set of boolean flags.
 */
final class ArgParser {

    private final List<String> positionals = new ArrayList<>();
    private final Map<String, String> options = new HashMap<>();
    private final Set<String> seenFlags = new HashSet<>();

    /**
     * @param args            raw argv (sub-command already stripped)
     * @param positionalNames names of expected positional args, in order
     * @param booleanFlags    options that take no value (e.g. {@code --no-progress})
     */
    ArgParser(
        String[] args,
        List<String> positionalNames,
        Set<String> booleanFlags
    ) {
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("--")) {
                // everything after is positional
                for (int j = i + 1; j < args.length; j++) positionals.add(
                    args[j]
                );
                break;
            }
            boolean looksLikeOpt =
                a.startsWith("--") || (a.startsWith("-") && a.length() == 2);
            if (looksLikeOpt) {
                if (booleanFlags.contains(a)) {
                    seenFlags.add(a);
                    continue;
                }
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException(
                        "Missing value for option " + a
                    );
                }
                options.put(a, args[++i]);
            } else {
                positionals.add(a);
            }
        }
        if (positionals.size() < positionalNames.size()) {
            throw new IllegalArgumentException(
                "Missing positional argument: " +
                    positionalNames.get(positionals.size())
            );
        }
    }

    String positional(int idx) {
        return positionals.get(idx);
    }

    /** First name to match wins; {@code def} returned if none present. */
    String opt(List<String> names, String def) {
        for (String n : names) {
            if (options.containsKey(n)) return options.get(n);
        }
        return def;
    }

    String opt(String name, String def) {
        return options.getOrDefault(name, def);
    }

    boolean flag(String name) {
        return seenFlags.contains(name);
    }
}
