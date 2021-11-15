/* FeatureDetect.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt;

/**
 * Native feature detection class
 * Used to expose native preprocessor values to Java
 */
public class FeatureDetect {

    /**
     * Tests if MD5 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Md5Enabled();

    /**
     * Tests if SHA-1 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean ShaEnabled();

    /**
     * Tests if SHA-256 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha256Enabled();

    /**
     * Tests if SHA-384 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha384Enabled();

    /**
     * Tests if SHA-512 is compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha512Enabled();

    static {
        System.loadLibrary("wolfcryptjni");
    }
}

