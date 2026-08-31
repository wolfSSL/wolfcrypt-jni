/* AesCfb.java
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
 * Wrapper for the native WolfCrypt AES-CFB implementation.
 *
 * AES-CFB (NIST SP 800-38A) is a stream cipher mode of operation. Supported
 * segment sizes are CFB_MODE_128, CFB_MODE_8, and CFB_MODE_1, selected at
 * construction. CFB1 is byte oriented, each byte is processed as 8 bits MSB
 * first.
 *
 * Both directions use the forward AES transform.
 *
 * @author wolfSSL Inc.
 */
public class AesCfb extends NativeStruct {

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
    /** CFB segment size of 128 bits (full block feedback) */
    public static final int CFB_MODE_128 = 128;
    /** CFB segment size of 8 bits */
    public static final int CFB_MODE_8 = 8;
    /** CFB segment size of 1 bit */
    public static final int CFB_MODE_1 = 1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    private int opmode;

    private final int cfbMode;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to synchronize
     * access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void wc_AesInit();
    private native void wc_AesFree();
    private native void native_set_key_internal(byte[] key, byte[] iv);
    private native int native_update_internal(int cfbMode, int opmode,
        byte[] input, int offset, int length, byte[] output, int outputOffset);
    private native int native_update_internal(int cfbMode, int opmode,
        ByteBuffer input, int offset, int length, ByteBuffer output,
        int outputOffset);

    /**
     * Malloc native AesCfb structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        synchronized (pointerLock) {
            return mallocNativeStruct_internal();
        }
    }

    /**
     * Set native AES-CFB key and IV. The key schedule is always set up
     * for encryption, CFB uses forward AES transform both ways.
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES initialization vector
     */
    protected void native_set_key(byte[] key, byte[] iv) {

        synchronized (pointerLock) {
            native_set_key_internal(key, iv);
        }
    }

    /**
     * Native AES-CFB encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: AesCfb.ENCRYPT_MODE or
     *        AesCfb.DECRYPT_MODE
     * @param input input data for AES-CFB update
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
            return native_update_internal(this.cfbMode, opmode, input,
                offset, length, output, outputOffset);
        }
    }

    /**
     * Native AES-CFB encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: AesCfb.ENCRYPT_MODE or
     *        AesCfb.DECRYPT_MODE
     * @param input input data for AES-CFB update
     * @param offset offset into input buffer to start update
     * @param length length of data in input to update
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
    protected int native_update(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(this.cfbMode, opmode, input,
                offset, length, output, outputOffset);
        }
    }

    private void checkStateAndInitialize() throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                synchronized (pointerLock) {
                    initNativeStruct();
                    try {
                        wc_AesInit();
                    } catch (WolfCryptException e) {
                        /* Free here, releaseNativeStruct() skips
                         * UNINITIALIZED state */
                        super.releaseNativeStruct();
                        throw e;
                    }
                }
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
     * Create new AesCfb object using 128-bit (full block) feedback.
     *
     * @throws WolfCryptException if AES-CFB has not been compiled into native
     *         wolfCrypt library.
     */
    public AesCfb() {
        this(CFB_MODE_128);
    }

    /**
     * Create new AesCfb object with the given CFB segment size.
     *
     * @param cfbMode CFB segment size: AesCfb.CFB_MODE_128,
     *        AesCfb.CFB_MODE_8, or AesCfb.CFB_MODE_1
     *
     * @throws IllegalArgumentException if cfbMode is not a supported
     *         CFB segment size
     * @throws WolfCryptException if the requested AES-CFB mode has not
     *         been compiled into the native wolfCrypt library.
     */
    public AesCfb(int cfbMode) {

        if (cfbMode != CFB_MODE_128 && cfbMode != CFB_MODE_8 &&
            cfbMode != CFB_MODE_1) {
            throw new IllegalArgumentException(
                "Invalid CFB segment size: " + cfbMode);
        }

        if (!FeatureDetect.AesCfbEnabled() ||
            (cfbMode == CFB_MODE_8 && !FeatureDetect.AesCfb8Enabled()) ||
            (cfbMode == CFB_MODE_1 && !FeatureDetect.AesCfb1Enabled())) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        this.cfbMode = cfbMode;
    }

    /**
     * Get the CFB segment size configured for this object.
     *
     * @return AesCfb.CFB_MODE_128, AesCfb.CFB_MODE_8, or AesCfb.CFB_MODE_1
     */
    public int getCfbMode() {
        return this.cfbMode;
    }

    /**
     * Set AES-CFB key and initialization vector.
     *
     * @param key AES key byte array
     * @param iv AES IV byte array, must be 16 bytes for all CFB segment sizes
     * @param opmode AES mode: AesCfb.ENCRYPT_MODE or AesCfb.DECRYPT_MODE.
     *        Selects the operation used by update(), the native key schedule
     *        is always set up for encryption internally.
     *
     * @throws IllegalArgumentException if opmode is not AesCfb.ENCRYPT_MODE or
     *         AesCfb.DECRYPT_MODE
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void setKey(byte[] key, byte[] iv, int opmode)
        throws IllegalStateException {

        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
            throw new IllegalArgumentException(
                "Invalid opmode: " + opmode);
        }

        checkStateAndInitialize();
        throwIfKeyExists();

        native_set_key(key, iv);
        this.opmode = opmode;

        state = WolfCryptState.READY;
    }

    /**
     * Set AES-CFB key and initialization vector for encryption.
     *
     * @param key AES key byte array
     * @param iv AES IV byte array, must be 16 bytes for all CFB segment sizes
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
     * AES-CFB encrypt operation.
     *
     * @param input input data for encrypt
     *
     * @return output encrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized byte[] encrypt(byte[] input)
        throws IllegalStateException {

        return encrypt(input, 0, input.length);
    }

    /**
     * AES-CFB decrypt operation.
     *
     * @param input input data for decrypt
     *
     * @return output decrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized byte[] decrypt(byte[] input)
        throws IllegalStateException {

        return decrypt(input, 0, input.length);
    }

    /**
     * AES-CFB encrypt/decrypt operation. Uses the operation mode set with
     * setKey() to determine encrypt or decrypt.
     *
     * @param input input data for encrypt/decrypt
     *
     * @return output data array from operation
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized byte[] update(byte[] input)
        throws IllegalStateException {

        return update(input, 0, input.length);
    }

    /**
     * AES-CFB encrypt operation.
     *
     * @param input input data for encrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output encrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized byte[] encrypt(byte[] input, int offset, int length)
        throws IllegalStateException {

        int outputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

        outputLength = native_update(ENCRYPT_MODE, input, offset, length,
            output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-CFB decrypt operation.
     *
     * @param input input data for decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output decrypted data array
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized byte[] decrypt(byte[] input, int offset, int length)
        throws IllegalStateException {

        int outputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        byte[] output = new byte[length];

        outputLength = native_update(DECRYPT_MODE, input, offset, length,
            output, 0);

        if (outputLength != length) {
            /* resize array to match actual output length */
            byte[] tmp = new byte[outputLength];
            System.arraycopy(output, 0, tmp, 0, outputLength);
            output = tmp;
        }

        return output;
    }

    /**
     * AES-CFB encrypt/decrypt operation. Uses the operation mode set
     * with setKey() to determine encrypt or decrypt.
     *
     * @param input input data for encrypt/decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     *
     * @return output data array from operation
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
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
     * AES-CFB encrypt operation.
     *
     * @param input input data for encrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     * @param output output array to place data
     * @param outputOffset offset into output array to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     * @throws WolfCryptException if input or output is null, or native error
     */
    public synchronized int encrypt(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        return native_update(ENCRYPT_MODE, input, offset, length, output,
            outputOffset);
    }

    /**
     * AES-CFB decrypt operation.
     *
     * @param input input data for decrypt
     * @param offset offset into input data to begin operation
     * @param length length of data to process
     * @param output output array to place data
     * @param outputOffset offset into output array to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     * @throws WolfCryptException if input or output is null, or native error
     */
    public synchronized int decrypt(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        return native_update(DECRYPT_MODE, input, offset, length, output,
            outputOffset);
    }

    /**
     * AES-CFB encrypt/decrypt operation. Uses the operation mode set
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
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     * @throws WolfCryptException if input or output is null, or native error
     */
    public synchronized int update(byte[] input, int offset, int length,
        byte[] output, int outputOffset) throws IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        return native_update(opmode, input, offset, length, output,
            outputOffset);
    }

    /**
     * AES-CFB encrypt operation using ByteBuffers.
     *
     * @param input input ByteBuffer for encrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public synchronized int encrypt(ByteBuffer input, ByteBuffer output)
        throws IllegalStateException {

        int ret;
        int inputLength;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        inputLength = input.remaining();

        ret = native_update(ENCRYPT_MODE, input, input.position(), inputLength,
            output, output.position());

        /* Update ByteBuffer positions */
        input.position(input.position() + ret);
        output.position(output.position() + ret);

        return ret;
    }

    /**
     * AES-CFB decrypt operation using ByteBuffers.
     *
     * @param input input ByteBuffer for decrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
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
     * AES-CFB encrypt/decrypt operation using ByteBuffers. Uses the operation
     * mode set with setKey() to determine encrypt or decrypt.
     *
     * @param input input ByteBuffer for encrypt/decrypt
     * @param output output ByteBuffer to place data
     *
     * @return number of bytes stored in output
     *
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
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
     * Release native AES-CFB structure.
     */
    @Override
    public synchronized void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {
                synchronized (pointerLock) {
                    wc_AesFree();
                    super.releaseNativeStruct();
                }
            }
            state = WolfCryptState.RELEASED;
        }
    }
}

