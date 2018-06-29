/* WolfCrypt.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
 * Main wrapper for the native WolfCrypt implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class WolfCrypt extends WolfObject {

    public static final int SUCCESS = 0;
    public static final int FAILURE = -1;

    public static final int SIZE_OF_128_BITS = 16;
    public static final int SIZE_OF_160_BITS = 20;
    public static final int SIZE_OF_192_BITS = 24;
    public static final int SIZE_OF_256_BITS = 32;
    public static final int SIZE_OF_384_BITS = 48;
    public static final int SIZE_OF_512_BITS = 64;
    public static final int SIZE_OF_1024_BITS = 128;
    public static final int SIZE_OF_2048_BITS = 256;

    private WolfCrypt() {
    }
}
