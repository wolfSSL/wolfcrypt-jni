/* Sha512.java
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt SHA2-512 implementation
 */
public class Sha512 extends MessageDigest {

    /** SHA2-512 hash type */
    public static final int TYPE = 4; /* hash type unique */
    /** SHA2-512 digest size */
    public static final int DIGEST_SIZE = 64;

    /**
     * Malloc native JNI Sha512 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Initialize Sha512 object
     */
    protected native void native_init();

    /**
     * Native SHA2-512 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_update(ByteBuffer data, int offset, int len);

    /**
     * Native SHA2-512 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_update(byte[] data, int offset, int len);

    /**
     * Native SHA2-512 final, calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_final(ByteBuffer hash, int offset);

    /**
     * Native SHA2-512 final, calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_final(byte[] hash);

    /**
     * Create new SHA2-512 object
     */
    public Sha512() {
        init();
    }

    /**
     * Create new SHA2-512 object
     *
     * @param data input data to hash
     */
    public Sha512(byte[] data) {
        init();
        update(data);
    }

    /**
     * Get SHA2-512 digest size
     *
     * @return SHA2-512 digest size
     */
    public int digestSize() {
        return DIGEST_SIZE;
    }
}

