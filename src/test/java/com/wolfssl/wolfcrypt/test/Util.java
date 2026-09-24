/* Util.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.wolfcrypt.test;

import java.security.CodeSource;

public class Util {

    public static byte[] h2b(String s) {

        int len = s.length();

        if ((len % 2) != 0) {
            throw new IllegalArgumentException("odd length hex string");
        }
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException(
                    "invalid hex character at index " + i);
            }
            data[i / 2] = (byte) ((hi << 4) + lo);
        }

        return data;
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String b2h(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];

        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }

    /* True when cls was loaded from a JAR rather than a class directory.
     * Multi-release (META-INF/versions) resolution only applies to JARs. */
    public static boolean isLoadedFromJar(Class<?> cls) {
        CodeSource cs = cls.getProtectionDomain().getCodeSource();
        return cs != null && cs.getLocation() != null &&
            cs.getLocation().getPath().toLowerCase().endsWith(".jar");
    }

    /* True when cls comes from a JAR that also ships the given versioned
     * entry, i.e. the multi-release overlay is really in effect. */
    public static boolean multiReleaseEntryActive(Class<?> cls,
        String entry) {
        ClassLoader cl = cls.getClassLoader();
        if (cl == null) {
            /* bootstrap loaded class */
            cl = ClassLoader.getSystemClassLoader();
        }
        return isLoadedFromJar(cls) && cl.getResource(entry) != null;
    }

    /* ASN.1 tags, copies of the package-private set in WolfCryptSpkiUtil */
    public static final int TAG_SEQUENCE     = 0x30;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_NULL         = 0x05;
    /* RFC 5958 OneAsymmetricKey context-specific tags */
    public static final int TAG_ATTRIBUTES   = 0xa0; /* attributes [0] */
    public static final int TAG_PUBLIC_KEY   = 0x81; /* publicKey [1] */

}
