/* WolfCrypt.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Main wrapper for the native WolfCrypt implementation
 */
public class WolfCrypt extends WolfObject {

    /** wolfCrypt SUCCESS code */
    public static final int SUCCESS = 0;
    /** wolfCrypt FAILURE code */
    public static final int FAILURE = -1;

    /** Size of 128 bits in bytes */
    public static final int SIZE_OF_128_BITS = 16;
    /** Size of 160 bits in bytes */
    public static final int SIZE_OF_160_BITS = 20;
    /** Size of 192 bits in bytes */
    public static final int SIZE_OF_192_BITS = 24;
    /** Size of 256 bits in bytes */
    public static final int SIZE_OF_256_BITS = 32;
    /** Size of 384 bits in bytes */
    public static final int SIZE_OF_384_BITS = 48;
    /** Size of 512 bits in bytes */
    public static final int SIZE_OF_512_BITS = 64;
    /** Size of 1024 bits in bytes */
    public static final int SIZE_OF_1024_BITS = 128;
    /** Size of 2048 bits in bytes */
    public static final int SIZE_OF_2048_BITS = 256;

    private WolfCrypt() {
    }
}
