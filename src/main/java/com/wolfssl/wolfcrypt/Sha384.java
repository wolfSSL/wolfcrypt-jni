/* Sha384.java
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
 * Wrapper for the native WolfCrypt SHA2-384 implementation
 */
public class Sha384 extends MessageDigest {

    /** SHA2-384 hash type */
    public static final int TYPE = 5; /* hash type unique */
    /** SHA2-384 digest size */
    public static final int DIGEST_SIZE = 48;

    /* native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_init_internal();
    private native void native_copy_internal(Sha384 toBeCopied);
    private native void native_update_internal(ByteBuffer data, int offset,
        int len);
    private native void native_update_internal(byte[] data, int offset,
        int len);
    private native void native_final_internal(ByteBuffer hash, int offset);
    private native void native_final_internal(byte[] hash);

    /**
     * Malloc native JNI Sha384 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        synchronized (pointerLock) {
            return mallocNativeStruct_internal();
        }
    }

    /**
     * Initialize Sha384 object
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_init()
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_init_internal();
        }
    }

    /**
     * Copy existing native WC_SHA384 struct (Sha384 object) into this one.
     * Copies structure state using wc_Sha384Copy().
     *
     * @param toBeCopied initialized Sha384 object to be copied.
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_copy(Sha384 toBeCopied)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_copy_internal(toBeCopied);
        }
    }

    /**
     * Native SHA2-384 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_update(ByteBuffer data, int offset, int len)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_update_internal(data, offset, len);
        }
    }

    /**
     * Native SHA2-384 update
     *
     * @param data input data
     * @param offset offset into input data
     * @param len length of input data
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_update(byte[] data, int offset, int len)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_update_internal(data, offset, len);
        }
    }

    /**
     * Native SHA2-384 final, calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(ByteBuffer hash, int offset)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash, offset);
        }
    }

    /**
     * Native SHA2-384 final, calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(byte[] hash)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash);
        }
    }

    /**
     * Create new SHA2-384 object
     */
    public Sha384() {
        init();
    }

    /**
     * Create new SHA2-384 object by making a copy of the one given.
     *
     * @param sha384 Initialized/created Sha384 object to be copied
     *
     * @throws WolfCryptException if native operation fails
     */
    public Sha384(Sha384 sha384) {
        init();
        native_copy(sha384);
    }

    /**
     * Create new SHA2-384 object
     *
     * @param data input data to hash
     */
    public Sha384(byte[] data) {
        init();
        update(data);
    }

    /**
     * Get SHA2-384 digest size
     *
     * @return SHA2-384 digest size
     */
    public int digestSize() {
        return DIGEST_SIZE;
    }
}

