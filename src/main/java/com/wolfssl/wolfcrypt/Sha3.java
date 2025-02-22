/* Sha3.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Wrapper for the native WolfCrypt SHA3 implementation
 */
public class Sha3 extends MessageDigest implements Cloneable {

    /** SHA3-224 hash type */
    public static final int TYPE_SHA3_224 = 10;
    /** SHA3-256 hash type */
    public static final int TYPE_SHA3_256 = 11;
    /** SHA3-384 hash type */
    public static final int TYPE_SHA3_384 = 12;
    /** SHA3-512 hash type */
    public static final int TYPE_SHA3_512 = 13;

    /** SHA3-224 digest size */
    public static final int DIGEST_SIZE_224 = 28;
    /** SHA3-256 digest size */
    public static final int DIGEST_SIZE_256 = 32;
    /** SHA3-384 digest size */
    public static final int DIGEST_SIZE_384 = 48;
    /** SHA3-512 digest size */
    public static final int DIGEST_SIZE_512 = 64;

    /** Array to init Sha3 with, will be reset to null once initialized */
    private byte[] initialData = null;

    /** Hash type of this current object */
    private int hashType = 0;

    /** Digest size of this current object */
    private int digestSize = 0;

    /* Native JNI methods, internally reach back and grab/use pointer
     * from NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal()
        throws OutOfMemoryError;
    private native void native_init_internal(int hashType);
    private native void native_copy_internal(Sha3 toBeCopied, int hashType);
    private native void native_update_internal(ByteBuffer data, int offset,
        int len, int hashType);
    private native void native_update_internal(byte[] data, int offset,
        int len, int hashType);
    private native void native_final_internal(ByteBuffer hash, int offset,
        int hashType);
    private native void native_final_internal(byte[] hash, int hashType);

    /**
     * Get the hash type of this Sha3 object
     *
     * @return the hash type of this Sha3 object. One of TYPE_SHA3_224,
     *         TYPE_SHA3_256, TYPE_SHA3_384, or TYPE_SHA3_512.
     */
    public int getHashType() {
        return this.hashType;
    }

    /**
     * Sanitize and set the hash type of this Sha3 object.
     *
     * @param hashType hash type of the Sha3 object
     *
     * @throws WolfCryptException if the hash type is invalid
     */
    private void sanitizeAndSetHashType(int hashType) {
        if (hashType != TYPE_SHA3_224 && hashType != TYPE_SHA3_256 &&
            hashType != TYPE_SHA3_384 && hashType != TYPE_SHA3_512) {
            throw new WolfCryptException(
                "Invalid hash type: " + hashType + ". " +
                "Must be one of TYPE_SHA3_224, TYPE_SHA3_256, " +
                "TYPE_SHA3_384, or TYPE_SHA3_512.");
        }
        this.hashType = hashType;

        switch (hashType) {
            case TYPE_SHA3_224:
                this.digestSize = DIGEST_SIZE_224;
                break;
            case TYPE_SHA3_256:
                this.digestSize = DIGEST_SIZE_256;
                break;
            case TYPE_SHA3_384:
                this.digestSize = DIGEST_SIZE_384;
                break;
            case TYPE_SHA3_512:
                this.digestSize = DIGEST_SIZE_512;
                break;
        }
    }

    /**
     * Malloc native JNI Sha3 structure
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
     * Initialize Sha3 object
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_init()
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_init_internal(this.hashType);

            /* Check if we need to init with passed in data */
            if (this.initialData != null) {
                update(this.initialData);
                this.initialData = null;
            }
        }
    }

    /**
     * Copy existing native wc_Sha3 struct (Sha3 object) into this one.
     * Copies structure state using wc_Sha3_XXX_Copy().
     *
     * @param toBeCopied initialized Sha3 object to be copied.
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_copy(Sha3 toBeCopied)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_copy_internal(toBeCopied, toBeCopied.getHashType());
        }
    }

    /**
     * Native SHA-3 update
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
            native_update_internal(data, offset, len, this.hashType);
        }
    }

    /**
     * Native SHA-3 update
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
            native_update_internal(data, offset, len, this.hashType);
        }
    }

    /**
     * Native SHA-3 final, calculate final digest
     *
     * @param hash output buffer to place digest
     * @param offset offset into output buffer to write digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(ByteBuffer hash, int offset)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash, offset, this.hashType);
        }
    }

    /**
     * Native SHA-3 final, calculate final digest
     *
     * @param hash output buffer to place digest
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(byte[] hash)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash, this.hashType);
        }
    }

    /**
     * Create new Sha3 object.
     *
     * @param hashType SHA3 hash type: one of TYPE_SHA3_224, TYPE_SHA3_256,
     *        TYPE_SHA3_384, or TYPE_SHA3_512.
     *
     * @throws WolfCryptException if SHA-3 has not been compiled into native
     *         wolfCrypt library.
     */
    public Sha3(int hashType) {
        if (!FeatureDetect.Sha3Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
        sanitizeAndSetHashType(hashType);
    }

    /**
     * Create new Sha3 object by making a copy of the one given.
     *
     * @param sha3 Initialized/created Sha3 object to be copied
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of a second Sha3 object inside this Sha3 object, and to
     *             avoid potential incomplete object creation issues between
     *             subclass/superclasses. Please refactor existing code to
     *             call Sha3.clone() to get a copy of an existing Sha3
     *             object.
     */
    @Deprecated
    public Sha3(Sha3 sha3) {
        throw new WolfCryptException(
            "Constructor deprecated, use Sha3.clone() to duplicate " +
            "Sha3 object");
    }

    /**
     * Create new Sha3 object.
     *
     * @param data input data to hash
     * @param hashType hash type of the Sha3 object
     *
     * @throws WolfCryptException if SHA-3 has not been compiled into native
     *         wolfCrypt library.
     */
    public Sha3(byte[] data, int hashType) {
        if (!FeatureDetect.Sha3Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
        this.initialData = data.clone();
        sanitizeAndSetHashType(hashType);
    }

    /**
     * Get SHA3 digest size
     *
     * @return SHA3 digest size
     */
    public int digestSize() {
        return this.digestSize;
    }

    @Override
    public Object clone() {

        Sha3 shaCopy = new Sha3(this.hashType);
        /* Initialize NativeStruct, since is done on first use */
        shaCopy.checkStateAndInitialize();
        shaCopy.native_copy(this);

        return shaCopy;
    }
}
