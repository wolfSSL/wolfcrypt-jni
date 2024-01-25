/* WolfCrypt.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
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

    /** wolfSSL SUCCESS code */
    public static final int WOLFSSL_SUCCESS = 1;

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

    /*
     * Native wolfCrypt hash types, from wolfssl/wolfcrypt/types.h
     * wc_HashType enum.
     */

    /** wolfSSL hash type: None */
    public static int WC_HASH_TYPE_NONE =
        WolfCrypt.getWC_HASH_TYPE_NONE();

    /** wolfSSL hash type: MD2 */
    public static int WC_HASH_TYPE_MD2 =
        WolfCrypt.getWC_HASH_TYPE_MD2();

    /** wolfSSL hash type: MD4 */
    public static int WC_HASH_TYPE_MD4 =
        WolfCrypt.getWC_HASH_TYPE_MD4();

    /** wolfSSL hash type: MD5 */
    public static int WC_HASH_TYPE_MD5 =
        WolfCrypt.getWC_HASH_TYPE_MD5();

    /** wolfSSL hash type: SHA-1 */
    public static int WC_HASH_TYPE_SHA =
        WolfCrypt.getWC_HASH_TYPE_SHA();

    /** wolfSSL hash type: SHA-224 */
    public static int WC_HASH_TYPE_SHA224 =
        WolfCrypt.getWC_HASH_TYPE_SHA224();

    /** wolfSSL hash type: SHA-256 */
    public static int WC_HASH_TYPE_SHA256 =
        WolfCrypt.getWC_HASH_TYPE_SHA256();

    /** wolfSSL hash type: SHA-384 */
    public static int WC_HASH_TYPE_SHA384 =
        WolfCrypt.getWC_HASH_TYPE_SHA384();

    /** wolfSSL hash type: SHA-512 */
    public static int WC_HASH_TYPE_SHA512 =
        WolfCrypt.getWC_HASH_TYPE_SHA512();

    /** wolfSSL hash type: MD5-SHA */
    public static int WC_HASH_TYPE_MD5_SHA =
        WolfCrypt.getWC_HASH_TYPE_MD5_SHA();

    /** wolfSSL hash type: SHA3-224 */
    public static int WC_HASH_TYPE_SHA3_224 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_224();

    /** wolfSSL hash type: SHA3-256 */
    public static int WC_HASH_TYPE_SHA3_256 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_256();

    /** wolfSSL hash type: SHA3-384 */
    public static int WC_HASH_TYPE_SHA3_384 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_384();

    /** wolfSSL hash type: SHA3-512 */
    public static int WC_HASH_TYPE_SHA3_512 =
        WolfCrypt.getWC_HASH_TYPE_SHA3_512();

    private static native int getWC_HASH_TYPE_NONE();
    private static native int getWC_HASH_TYPE_MD2();
    private static native int getWC_HASH_TYPE_MD4();
    private static native int getWC_HASH_TYPE_MD5();
    private static native int getWC_HASH_TYPE_SHA();
    private static native int getWC_HASH_TYPE_SHA224();
    private static native int getWC_HASH_TYPE_SHA256();
    private static native int getWC_HASH_TYPE_SHA384();
    private static native int getWC_HASH_TYPE_SHA512();
    private static native int getWC_HASH_TYPE_MD5_SHA();
    private static native int getWC_HASH_TYPE_SHA3_224();
    private static native int getWC_HASH_TYPE_SHA3_256();
    private static native int getWC_HASH_TYPE_SHA3_384();
    private static native int getWC_HASH_TYPE_SHA3_512();

    /* Public mappings of some SSL/TLS level enums/defines */
    /** wolfSSL file type: PEM */
    public static int SSL_FILETYPE_PEM  = 1;
    /** wolfSSL file type: ASN.1/DER */
    public static int SSL_FILETYPE_ASN1 = 2;

    /**
     * CRL option, will perform CRL checking on each certificate in the
     * chain. Checking only leaf certificate is the default behavior.
     */
    public static int WOLFSSL_CRL_CHECKALL = 1;
    /**
     * CRL option, will enable CRL checking on leaf certificate.
     */
    public static int WOLFSSL_CRL_CHECK    = 2;

    /**
     * Tests if CRL (HAVE_CRL) has been enabled in native wolfCrypt.
     *
     * @return true if enabled, otherwise false if not compiled in
     */
    public static native boolean CrlEnabled();

    /**
     * Constant time byte array comparison.
     *
     * If arrays are of different lengths, return false right away. Apart
     * from length check, this matches native wolfSSL ConstantCompare()
     * logic in misc.c.
     *
     * @param a first byte array for comparison
     * @param b second byte array for comparison
     *
     * @return true if equal, otherwise false
     */
    public static boolean ConstantCompare(byte[] a, byte[] b) {

        int i;
        int compareSum = 0;

        if (a.length != b.length) {
            return false;
        }

        for (i = 0; i < a.length; i++) {
            compareSum |= a[i] ^ b[i];
        }

        return (compareSum == 0);
    }

    private WolfCrypt() {
    }
}
