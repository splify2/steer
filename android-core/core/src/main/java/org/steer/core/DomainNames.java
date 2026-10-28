package org.steer.core;

import java.net.IDN;
import java.util.Locale;

/** Strict ASCII normalization shared by proxy and DNS boundaries. */
public final class DomainNames {
    private DomainNames() {}

    public static String normalize(String text) {
        if (text == null) throw new IllegalArgumentException("Domain required");
        String value = text.endsWith(".") ? text.substring(0, text.length() - 1) : text;
        value = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (value.isEmpty() || value.length() > 253) throw new IllegalArgumentException("Invalid domain");
        for (String part : value.split("\\.", -1))
            if (part.isEmpty() || part.length() > 63) throw new IllegalArgumentException("Invalid domain");
        return value;
    }
}
