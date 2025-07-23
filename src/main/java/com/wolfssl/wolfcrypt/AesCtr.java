/* AesCtr.java
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
 * Wrapper for the native WolfCrypt AES-CTR implementation.
 *
 * AES-CTR (Counter mode) is a stream cipher mode of operation for AES.
 * It uses the same function for both encryption and decryption.
 *
 * @author wolfSSL Inc.
 */
public class AesCtr extends NativeStruct {

    /** AES-128 key size */
    public static final int KEY_SIZE_128 = 16;
    /** AES-192 key size */
    public static final int KEY_SIZE_192 = 24;
    /** AES-256 key size */
    public static final int KEY_SIZE_256 = 32;
    /** AES block size */
    public static final int BLOCK_SIZE = 16;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_set_key_internal(byte[] key, byte[] iv);
    private native int native_update_internal(byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_update_internal(ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Malloc native AesCtr structure
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
     * Set native AES-CTR key and IV
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES initialization vector (counter)
     */
    protected void native_set_key(byte[] key, byte[] iv) {

        synchronized (pointerLock) {
            native_set_key_internal(key, iv);
        }
    }

    /**
     * Native AES-CTR encrypt/decrypt update operation
     *
     * @param input input data for AES-CTR update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_update(byte[] input, int offset,
            int length, byte[] output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Native AES-CTR encrypt/decrypt update operation
     *
     * @param input input data for AES-CTR update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_update(ByteBuffer input,
            int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(input, offset, length,
                output, outputOffset);
        }
    }

    private synchronized void checkStateAndInitialize() {
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
     * Create new AesCtr object.
     *
     * @throws WolfCryptException if AES-CTR has not been compiled into native
     *         wolfCrypt library.
     */
    public AesCtr() {
        if (!FeatureDetect.AesCtrEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Set AES-CTR key and initialization vector (counter).
     *
     * @param key AES key byte array
     * @param iv AES initialization vector (counter) byte array
     *
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void setKey(byte[] key, byte[] iv)
        throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        native_set_key(key, iv);

        state = WolfCryptState.READY;
    }

    /**
     * AES-CTR encrypt/decrypt operation. Since CTR mode is a stream cipher,
     * the same operation is used for both encryption and decryption.
     *
     * @param input input data for encrypt/decrypt
     *
     * @return output data array from operation
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] update(byte[] input)
        throws IllegalStateException {

        return update(input, 0, input.length);
    }

    /**
     * AES-CTR encrypt/decrypt operation. Since CTR mode is a stream cipher,
     * the same operation is used for both encryption and decryption.
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
     */
    public synchronized byte[] update(byte[] input, int offset, int length)
        throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

        int outputLength = native_update(input, offset, length, output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-CTR encrypt/decrypt operation. Since CTR mode is a stream cipher,
     * the same operation is used for both encryption and decryption.
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
     */
    public synchronized int update(byte[] input, int offset, int length,
            byte[] output, int outputOffset)
            throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        if (output == null) {
            throw new WolfCryptException("output buffer cannot be null");
        }

        return native_update(input, offset, length, output, outputOffset);
    }

    /**
     * AES-CTR encrypt/decrypt operation using ByteBuffers. Since CTR mode is
     * a stream cipher, the same operation is used for both encryption and
     * decryption.
     *
     * @param input input ByteBuffer for encrypt/decrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized int update(ByteBuffer input, ByteBuffer output)
            throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        int inputLength = input.remaining();

        int ret = native_update(input, input.position(), inputLength,
                               output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * Release native AES-CTR structure.
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

