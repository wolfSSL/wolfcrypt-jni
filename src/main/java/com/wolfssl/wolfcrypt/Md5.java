/* Md5.java
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt Md5 implementation
 */
public class Md5 extends MessageDigest {

    /** MD5 hash type */
    public static final int TYPE = 0; /* hash type unique */
    /** MD5 digest size */
    public static final int DIGEST_SIZE = 16;

    /**
     * Malloc native JNI Md5 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Initialize Md5 object
     */
    protected native void native_init();

    /**
     * Copy existing native WC_MD5 struct (Md5 object) into this one.
     * Copies structure state using wc_Md5Copy().
     *
     * @param toBeCopied initialized Md5 object to be copied.
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_copy(Md5 toBeCopied);

    /**
     * Native Md5 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_update(ByteBuffer data, int offset, int len);

    /**
     * Native Md5 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_update(byte[] data, int offset, int len);

    /**
     * Native Md5 final, calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_final(ByteBuffer hash, int offset);

    /**
     * Native Md5 final, calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected native void native_final(byte[] hash);

    /**
     * Create new Md5 object
     */
    public Md5() {
        init();
    }

    /**
     * Create new Md5 object by making a copy of the one given.
     *
     * @param md5 Initialized/created Md5 object to be copied
     *
     * @throws WolfCryptException if native operation fails
     */
    public Md5(Md5 md5) {
        init();
        native_copy(md5);
    }

    /**
     * Create new Md5 object
     *
     * @param data input data to hash
     */
    public Md5(byte[] data) {
        init();
        update(data);
    }

    /**
     * Get MD5 digest size
     *
     * @return MD5 digest size
     */
    public int digestSize() {
        return DIGEST_SIZE;
    }
}

