/* AesOfb.java
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
 * Wrapper for the native WolfCrypt AES-OFB implementation.
 *
 * AES-OFB (Output Feedback mode) is a stream cipher mode of operation for AES.
 * It uses the same function for both encryption and decryption.
 *
 * @author wolfSSL Inc.
 */
public class AesOfb extends NativeStruct {

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

    private int opmode;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_set_key_internal(byte[] key, byte[] iv,
        int opmode);
    private native int native_update_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_update_internal(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);
    private native int native_encrypt_internal(byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_encrypt_internal(ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);
    private native int native_decrypt_internal(byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_decrypt_internal(ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Malloc native AesOfb structure
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
     * Set native AES-OFB key and IV
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES initialization vector
     * @param opmode AES mode, either AesOfb.ENCRYPT_MODE or
     *        AesOfb.DECRYPT_MODE
     */
    protected void native_set_key(byte[] key, byte[] iv, int opmode) {

        synchronized (pointerLock) {
            native_set_key_internal(key, iv, opmode);
        }
    }

    /**
     * Native AES-OFB encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: AesOfb.ENCRYPT_MODE or
     *        AesOfb.DECRYPT_MODE
     * @param input input data for AES-OFB update
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
     * Native AES-OFB encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: AesOfb.ENCRYPT_MODE or
     *        AesOfb.DECRYPT_MODE
     * @param input input data for AES-OFB update
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

    /**
     * Native AES-OFB encrypt operation
     *
     * @param input input data for AES-OFB encrypt
     * @param offset offset into input array to start encrypt
     * @param length length of data in input to encrypt
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_encrypt(byte[] input, int offset,
            int length, byte[] output, int outputOffset) {

        synchronized (pointerLock) {
            return native_encrypt_internal(input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Native AES-OFB encrypt operation
     *
     * @param input input data for AES-OFB encrypt
     * @param offset offset into input array to start encrypt
     * @param length length of data in input to encrypt
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_encrypt(ByteBuffer input,
            int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_encrypt_internal(input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Native AES-OFB decrypt operation
     *
     * @param input input data for AES-OFB decrypt
     * @param offset offset into input array to start decrypt
     * @param length length of data in input to decrypt
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_decrypt(byte[] input, int offset,
            int length, byte[] output, int outputOffset) {

        synchronized (pointerLock) {
            return native_decrypt_internal(input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Native AES-OFB decrypt operation
     *
     * @param input input data for AES-OFB decrypt
     * @param offset offset into input array to start decrypt
     * @param length length of data in input to decrypt
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_decrypt(ByteBuffer input,
            int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_decrypt_internal(input, offset, length,
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
     * Create new AesOfb object.
     *
     * @throws WolfCryptException if AES-OFB has not been compiled into native
     *         wolfCrypt library.
     */
    public AesOfb() {
        if (!FeatureDetect.AesOfbEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Set AES-OFB key and initialization vector.
     *
     * @param key AES key byte array
     * @param iv AES initialization vector byte array
     * @param opmode AES mode, either AesOfb.ENCRYPT_MODE or
     *        AesOfb.DECRYPT_MODE
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
     * Set AES-OFB key and initialization vector for encryption.
     *
     * @param key AES key byte array
     * @param iv AES initialization vector byte array
     *
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void setKey(byte[] key, byte[] iv)
        throws IllegalStateException {

        setKey(key, iv, ENCRYPT_MODE);
    }

    /**
     * AES-OFB encrypt operation.
     *
     * @param input input data for encrypt
     *
     * @return output encrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] encrypt(byte[] input)
        throws IllegalStateException {

        return encrypt(input, 0, input.length);
    }

    /**
     * AES-OFB decrypt operation.
     *
     * @param input input data for decrypt
     *
     * @return output decrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] decrypt(byte[] input)
        throws IllegalStateException {

        return decrypt(input, 0, input.length);
    }

    /**
     * AES-OFB encrypt/decrypt operation. Uses the operation mode set
     * with setKey() to determine encrypt or decrypt.
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
     * AES-OFB encrypt operation.
     *
     * @param input input data for encrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output encrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] encrypt(byte[] input, int offset, int length)
        throws IllegalStateException {

        int outputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

        outputLength = native_update(ENCRYPT_MODE, input, offset,
            length, output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-OFB decrypt operation.
     *
     * @param input input data for decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output decrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] decrypt(byte[] input, int offset, int length)
        throws IllegalStateException {

        int outputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

        outputLength = native_update(DECRYPT_MODE, input, offset,
            length, output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-OFB encrypt/decrypt operation. Uses the operation mode set
     * with setKey() to determine encrypt or decrypt.
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

        int outputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

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
     * AES-OFB encrypt operation.
     *
     * @param input input data for encrypt
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
    public synchronized int encrypt(byte[] input, int offset, int length,
            byte[] output, int outputOffset)
            throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        return native_update(ENCRYPT_MODE, input, offset, length,
            output, outputOffset);
    }

    /**
     * AES-OFB decrypt operation.
     *
     * @param input input data for decrypt
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
    public synchronized int decrypt(byte[] input, int offset, int length,
            byte[] output, int outputOffset)
            throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        return native_update(DECRYPT_MODE, input, offset, length,
            output, outputOffset);
    }

    /**
     * AES-OFB encrypt/decrypt operation. Uses the operation mode set
     * with setKey() to determine encrypt or decrypt.
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

        return native_update(opmode, input, offset, length,
            output, outputOffset);
    }

    /**
     * AES-OFB encrypt operation using ByteBuffers.
     *
     * @param input input ByteBuffer for encrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized int encrypt(ByteBuffer input, ByteBuffer output)
            throws IllegalStateException {

        int ret;
        int inputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        inputLength = input.remaining();

        ret = native_update(ENCRYPT_MODE, input, input.position(),
            inputLength, output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * AES-OFB decrypt operation using ByteBuffers.
     *
     * @param input input ByteBuffer for decrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized int decrypt(ByteBuffer input, ByteBuffer output)
            throws IllegalStateException {

        int ret;
        int inputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        inputLength = input.remaining();

        ret = native_update(DECRYPT_MODE, input, input.position(), inputLength,
            output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * AES-OFB encrypt/decrypt operation using ByteBuffers. Uses the operation
     * mode set with setKey() to determine encrypt or decrypt.
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

        int ret;
        int inputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        inputLength = input.remaining();

        ret = native_update(opmode, input, input.position(), inputLength,
            output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * Release native AES-OFB structure.
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

