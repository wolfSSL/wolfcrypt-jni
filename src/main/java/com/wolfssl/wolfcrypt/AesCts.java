/* AesCts.java
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
 * Wrapper for the native WolfCrypt AES-CTS implementation.
 *
 * AES-CTS (Ciphertext Stealing mode) is a block cipher mode of operation
 * for AES that allows encryption of messages that are not a multiple of
 * the block size without padding. CTS requires at least one block (16 bytes)
 * of input. Per RFC 3962/8009, for exactly 16 bytes, CTS reduces to plain CBC.
 *
 * The native JNI for this wraps AES-CTS functions in the OpenSSL compatibility
 * layer to maintain compatibility with wolfCrypt FIPS library builds. Using
 * AES-CTS proper APIs from wolfssl/wolfcrypt/aes.h would require a change
 * in aes.o and would affect the boundary.
 *
 * @author wolfSSL Inc.
 */
public class AesCts extends NativeStruct {

    /** AES-128 key size */
    public static final int KEY_SIZE_128 = 16;
    /** AES-192 key size */
    public static final int KEY_SIZE_192 = 24;
    /** AES-256 key size */
    public static final int KEY_SIZE_256 = 32;
    /** AES block size */
    public static final int BLOCK_SIZE = 16;

    /** AES encrypt mode */
    public static final int ENCRYPT_MODE = 0;
    /** AES decrypt mode */
    public static final int DECRYPT_MODE = 1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /** Current operation mode */
    private int opmode;

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_set_key_internal(byte[] key, byte[] iv,
        int opmode);
    private native int native_update_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_update_internal(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Malloc native AesCts structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        return mallocNativeStruct_internal();
    }

    /**
     * Set native AES-CTS key and IV
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES initialization vector
     * @param opmode operation mode (ENCRYPT_MODE or DECRYPT_MODE)
     */
    protected void native_set_key(byte[] key, byte[] iv, int opmode) {

        synchronized (pointerLock) {
            native_set_key_internal(key, iv, opmode);
        }
    }

    /**
     * Native AES-CTS encrypt/decrypt update operation
     *
     * @param opmode operation mode (ENCRYPT_MODE or DECRYPT_MODE)
     * @param input input data for AES-CTS update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_update(int opmode, byte[] input, int offset,
        int length, byte[] output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Native AES-CTS encrypt/decrypt update operation
     *
     * @param opmode operation mode (ENCRYPT_MODE or DECRYPT_MODE)
     * @param input input data for AES-CTS update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_update(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset);
        }
    }

    private void checkStateAndInitialize() {
        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED ||
                state == WolfCryptState.RELEASED) {
                initNativeStruct();
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    /**
     * Throw exception if key has been loaded already.
     *
     * @throws IllegalStateException if key has been loaded already
     */
    private void throwIfKeyExists() throws IllegalStateException {
        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                throw new IllegalStateException("Object already has a key");
            }
        }
    }

    /**
     * Throw exception if key has not been loaded.
     *
     * @throws IllegalStateException if key has not been loaded
     */
    private void throwIfKeyNotLoaded() throws IllegalStateException {
        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException(
                    "No key available to perform the operation");
            }
        }
    }

    /**
     * Create new AesCts object.
     *
     * @throws WolfCryptException if AES-CTS has not been compiled into
     *         native wolfCrypt library.
     */
    public AesCts() {
        if (!FeatureDetect.AesCtsEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Set AES-CTS key and initialization vector for encryption or
     * decryption.
     *
     * @param key AES key byte array
     * @param iv AES initialization vector byte array
     * @param opmode operation mode (ENCRYPT_MODE or DECRYPT_MODE)
     *
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void setKey(byte[] key, byte[] iv, int opmode)
        throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        native_set_key(key, iv, opmode);

        this.opmode = opmode;
        state = WolfCryptState.READY;
    }

    /**
     * AES-CTS encrypt/decrypt operation.
     *
     * Note: AES-CTS requires input length to be at least one block (16 bytes).
     * Per RFC 3962/8009, for exactly 16 bytes, CTS reduces to plain CBC.
     *
     * @param input input data for encrypt/decrypt
     *
     * @return output data array from operation
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     * @throws WolfCryptException if input length is not valid for CTS mode
     */
    public synchronized byte[] update(byte[] input)
        throws IllegalStateException {

        return update(input, 0, input.length);
    }

    /**
     * AES-CTS encrypt/decrypt operation.
     *
     * Note: AES-CTS requires input length to be at least one block (16 bytes).
     * Per RFC 3962/8009, for exactly 16 bytes, CTS reduces to plain CBC.
     *
     * @param input input data for encrypt/decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output data array from operation
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     * @throws WolfCryptException if input length is not valid for CTS mode
     */
    public synchronized byte[] update(byte[] input, int offset, int length)
        throws IllegalStateException {

        int outputLength;
        byte[] output = new byte[length];

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        /* CTS requires at least one block (16 bytes). For exactly 16 bytes,
         * CTS reduces to plain CBC per RFC 3962/8009. */
        if (length < BLOCK_SIZE) {
            throw new WolfCryptException(
                "AES-CTS requires input length >= " + BLOCK_SIZE +
                " bytes, got " + length);
        }

        outputLength = native_update(opmode, input, offset, length, output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-CTS encrypt/decrypt operation.
     *
     * Note: AES-CTS requires input length to be at least one block (16 bytes).
     * Per RFC 3962/8009, for exactly 16 bytes, CTS reduces to plain CBC.
     *
     * @param input input data for encrypt/decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     * @param output output array to place data
     * @param outputOffset offset into output array to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     * @throws WolfCryptException if input length is not valid for CTS mode
     *         or if output buffer is null
     */
    public synchronized int update(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        if (output == null) {
            throw new WolfCryptException("output buffer cannot be null");
        }

        /* CTS requires at least one block (16 bytes). For exactly 16 bytes,
         * CTS reduces to plain CBC per RFC 3962/8009. */
        if (length < BLOCK_SIZE) {
            throw new WolfCryptException(
                "AES-CTS requires input length >= " + BLOCK_SIZE +
                " bytes, got " + length);
        }

        return native_update(opmode, input, offset, length, output,
            outputOffset);
    }

    /**
     * AES-CTS encrypt/decrypt operation using ByteBuffers.
     *
     * Note: AES-CTS requires input length to be at least one block (16 bytes).
     * Per RFC 3962/8009, for exactly 16 bytes, CTS reduces to plain CBC.
     *
     * @param input input ByteBuffer for encrypt/decrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     * @throws WolfCryptException if input length is not valid for CTS mode
     */
    public synchronized int update(ByteBuffer input, ByteBuffer output)
        throws IllegalStateException {

        int ret;
        int inputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        inputLength = input.remaining();

        /* CTS requires at least one block (16 bytes). For exactly 16 bytes,
         * CTS reduces to plain CBC per RFC 3962/8009. */
        if (inputLength < BLOCK_SIZE) {
            throw new WolfCryptException(
                "AES-CTS requires input length >= " + BLOCK_SIZE +
                " bytes, got " + inputLength);
        }

        ret = native_update(opmode, input, input.position(), inputLength,
            output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * Release native AES-CTS structure.
     * Object cannot be used again after calling this method.
     */
    @Override
    public synchronized void releaseNativeStruct() {
        synchronized (stateLock) {
            if (state != WolfCryptState.RELEASED) {
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }
}

