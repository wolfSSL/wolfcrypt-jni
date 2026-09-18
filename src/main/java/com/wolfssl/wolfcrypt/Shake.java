/* Shake.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt SHAKE-128 and SHAKE-256 (FIPS 202 XOF)
 * implementation.
 *
 * XOF output length is set per object at creation and defaults to 32 bytes
 * (SHAKE-128) or 64 bytes (SHAKE-256).
 */
public class Shake extends MessageDigest implements Cloneable {

    /** SHAKE-128 hash type */
    public static final int TYPE_SHAKE_128 = WolfCrypt.WC_HASH_TYPE_SHAKE128;
    /** SHAKE-256 hash type */
    public static final int TYPE_SHAKE_256 = WolfCrypt.WC_HASH_TYPE_SHAKE256;

    /** SHAKE-128 default digest size */
    public static final int DIGEST_SIZE_128 = 32;
    /** SHAKE-256 default digest size */
    public static final int DIGEST_SIZE_256 = 64;

    /** Array to init Shake with, will be reset to null after init */
    private byte[] initialData = null;

    /** Hash type of this current object */
    private volatile int hashType = 0;

    /** Output (digest) size in bytes of this current object */
    private volatile int digestSize = 0;

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to synchronize
     * access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_init_internal(int hashType);
    private native void native_copy_internal(Shake toBeCopied, int hashType);
    private native void native_update_internal(ByteBuffer data, int offset,
        int len, int hashType);
    private native void native_update_internal(byte[] data, int offset, int len,
        int hashType);
    private native void native_final_internal(ByteBuffer hash, int offset,
        int hashType, int outLen);
    private native void native_final_internal(byte[] hash, int hashType,
        int outLen);
    private native void native_free_internal(int hashType);

    /**
     * Get hash type of this Shake object
     *
     * @return hash type of this object: TYPE_SHAKE_128 or TYPE_SHAKE_256.
     */
    public int getHashType() {
        return this.hashType;
    }

    /**
     * Sanitize and set the hash type of this object, setting the default
     * output length for the type. Also verifies the SHAKE variant is compiled
     * into native wolfCrypt.
     *
     * @param hashType hash type of the Shake object
     *
     * @throws WolfCryptException if the hash type is invalid, or if the
     *         SHAKE variant is not compiled into native wolfCrypt.
     */
    private void sanitizeAndSetHashType(int hashType) {

        if (hashType == TYPE_SHAKE_128) {
            if (!FeatureDetect.Shake128Enabled()) {
                throw new WolfCryptException(
                    WolfCryptError.NOT_COMPILED_IN.getCode());
            }
            this.digestSize = DIGEST_SIZE_128;
        }
        else if (hashType == TYPE_SHAKE_256) {
            if (!FeatureDetect.Shake256Enabled()) {
                throw new WolfCryptException(
                    WolfCryptError.NOT_COMPILED_IN.getCode());
            }
            this.digestSize = DIGEST_SIZE_256;
        }
        else {
            throw new WolfCryptException(
                "Invalid hash type: " + hashType + ". " +
                "Must be one of TYPE_SHAKE_128 or TYPE_SHAKE_256.");
        }
        this.hashType = hashType;
    }

    /**
     * Malloc native JNI Shake structure
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
     * Initialize Shake object
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_init()
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_init_internal(this.hashType);

            if (this.initialData != null) {
                native_update(this.initialData, 0, this.initialData.length);
                this.initialData = null;
            }
        }
    }

    /**
     * Copy existing native wc_Shake struct (Shake object) into this one.
     * Copies structure state using wc_Shake128/256_Copy().
     *
     * @param toBeCopied initialized Shake object to be copied.
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_copy(Shake toBeCopied)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_copy_internal(toBeCopied, toBeCopied.getHashType());
        }
    }

    /**
     * Native SHAKE update
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
     * Native SHAKE update
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
     * Native SHAKE final
     *
     * @param hash output buffer to place XOF output
     * @param offset offset into output buffer to write output
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(ByteBuffer hash, int offset)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash, offset, this.hashType, this.digestSize);
        }
    }

    /**
     * Native SHAKE final
     *
     * @param hash output buffer to place XOF output
     *
     * @throws WolfCryptException if native operation fails
     */
    protected void native_final(byte[] hash)
        throws WolfCryptException {

        synchronized (pointerLock) {
            native_final_internal(hash, this.hashType, this.digestSize);
        }
    }

    /**
     * Create new Shake object using the default output length for the
     * hash type: 32 bytes for TYPE_SHAKE_128, 64 bytes for TYPE_SHAKE_256.
     *
     * @param hashType SHAKE hash type: TYPE_SHAKE_128 or TYPE_SHAKE_256.
     *
     * @throws WolfCryptException if hashType is invalid or if the SHAKE
     *         variant has not been compiled into native wolfCrypt.
     */
    public Shake(int hashType) {
        /* Internal state is initialized on first use */
        sanitizeAndSetHashType(hashType);
    }

    /**
     * Create new Shake object with a custom XOF output length.
     *
     * @param hashType SHAKE hash type: TYPE_SHAKE_128 or TYPE_SHAKE_256.
     * @param outLen XOF output (digest) length in bytes this object
     *        will produce, must be one or greater
     *
     * @throws WolfCryptException if hashType or outLen are invalid, or
     *         if the SHAKE variant has not been compiled into native wolfCrypt.
     */
    public Shake(int hashType, int outLen) {
        this(hashType);

        if (outLen < 1) {
            throw new WolfCryptException(
                "Invalid output length: " + outLen + ". " +
                "Must be one or greater.");
        }
        this.digestSize = outLen;
    }

    /**
     * Create new Shake object using default output length for the given
     * hash type.
     *
     * @param data input data to hash
     * @param hashType hash type of the Shake object, TYPE_SHAKE_128 or
     *        TYPE_SHAKE_256.
     *
     * @throws WolfCryptException if hashType is invalid or if the SHAKE
     *         variant has not been compiled into native wolfCrypt.
     */
    public Shake(byte[] data, int hashType) {
        this(hashType);

        /* Internal state is initialized on first use */
        this.initialData = data.clone();
    }

    /**
     * Get SHAKE XOF output (digest) size in bytes for this object.
     *
     * @return SHAKE output size in bytes
     */
    public int digestSize() {
        return this.digestSize;
    }

    @Override
    public synchronized void releaseNativeStruct() {

        synchronized (pointerLock) {
            /* Zeroize native state, may hold sensitive absorbed data */
            if (getNativeStruct() != NativeStruct.NULL) {
                native_free_internal(this.hashType);
            }

            super.releaseNativeStruct();
        }
    }

    /* synchronized so a concurrent releaseNativeStruct() cannot free
     * the source native struct while native_copy() reads from it */
    @Override
    public synchronized Object clone() {

        /* Init native state if not yet done */
        checkStateAndInitialize();

        Shake shakeCopy = new Shake(this.hashType, this.digestSize);
        /* Initialize NativeStruct, since is done on first use */
        shakeCopy.checkStateAndInitialize();
        shakeCopy.native_copy(this);

        return shakeCopy;
    }
}
