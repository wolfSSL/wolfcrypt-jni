/* Sha224.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt SHA2-224 implementation
 */
public class Sha224 extends MessageDigest implements Cloneable {

    /** SHA2-224 hash type */
    public static final int TYPE = 5; /* hash type unique */
    /** SHA2-224 digest size */
    public static final int DIGEST_SIZE = 28;

    /** Array to init Sha224 with, will be reset to null once initialized */
    private byte[] initialData = null;

    /* native JNI methods, internally reach back and grab/use pointer
     * from NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_init_internal();
    private native void native_copy_internal(Sha224 toBeCopied);
    private native void native_update_internal(ByteBuffer data, int offset,
        int len);
    private native void native_update_internal(byte[] data, int offset,
        int len);
    private native void native_final_internal(ByteBuffer hash, int offset);
    private native void native_final_internal(byte[] hash);

    /**
     * Malloc native JNI Sha224 structure
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
     * Initialize Sha224 object
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_init()
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_init_internal();

            /* Check if we need to init with passed in data */
            if (this.initialData != null) {
                update(this.initialData);
                this.initialData = null;
            }
        }
    }

    /**
     * Copy existing native WC_SHA224 struct (Sha224 object) into this one.
     * Copies structure state using wc_Sha224Copy().
     *
     * @param toBeCopied initialized Sha224 object to be copied.
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_copy(Sha224 toBeCopied)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_copy_internal(toBeCopied);
        }
    }

    /**
     * Native SHA2-224 update
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
     * Native SHA2-224 update
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
     * Native SHA2-224 final, calculate final digest
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
     * Native SHA2-224 final, calculate final digest
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
     * Create new SHA2-224 object.
     *
     * @throws WolfCryptException if SHA-224 has not been compiled into native
     *         wolfCrypt library.
     */
    public Sha224() {
        if (!FeatureDetect.Sha224Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    /**
     * Create new SHA2-224 object by making a copy of the one given.
     *
     * @param sha224 Initialized/created Sha224 object to be copied
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of a second Sha224 object inside this Sha224 object, and to
     *             avoid potential incomplete object creation issues between
     *             subclass/superclasses. Please refactor existing code to
     *             call Sha224.clone() to get a copy of an existing Sha224
     *             object.
     */
    @Deprecated
    public Sha224(Sha224 sha224) {
        throw new WolfCryptException(
            "Constructor deprecated, use Sha224.clone() to duplicate " +
            "Sha224 object");
    }

    /**
     * Create new SHA2-224 object.
     *
     * @param data input data to hash
     *
     * @throws WolfCryptException if SHA-224 has not been compiled into native
     *         wolfCrypt library.
     */
    public Sha224(byte[] data) {
        if (!FeatureDetect.Sha224Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
        this.initialData = data.clone();
    }

    /**
     * Get SHA2-224 digest size
     *
     * @return SHA2-224 digest size
     */
    public int digestSize() {
        return DIGEST_SIZE;
    }

    @Override
    public Object clone() {

        Sha224 shaCopy = new Sha224();
        /* Initialize NativeStruct, since is done on first use */
        shaCopy.checkStateAndInitialize();
        shaCopy.native_copy(this);

        return shaCopy;
    }
}
