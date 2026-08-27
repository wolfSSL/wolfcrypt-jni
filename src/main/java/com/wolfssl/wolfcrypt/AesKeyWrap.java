/* AesKeyWrap.java
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

import java.util.Arrays;

/**
 * Wrapper for the wolfCrypt AES Key Wrap implementation
 * (RFC 3394 / NIST SP 800-38F KW).
 *
 * Input must be at least 16 bytes and a multiple of 8, output is 8 bytes
 * longer. The 8-byte IV is the integrity check value, not a nonce, and
 * defaults to the RFC 3394 constant. Wrap needs a key set with ENCRYPT_MODE,
 * unwrap with DECRYPT_MODE.
 *
 * Requires native wolfSSL built with HAVE_AES_KEYWRAP.
 *
 * @author wolfSSL Inc.
 */
public class AesKeyWrap extends NativeStruct {

    /** AES-128 key size */
    public static final int KEY_SIZE_128 = 16;
    /** AES-192 key size */
    public static final int KEY_SIZE_192 = 24;
    /** AES-256 key size */
    public static final int KEY_SIZE_256 = 32;

    /** Key wrap works in 8-byte blocks, native KEYWRAP_BLOCK_SIZE */
    public static final int KEYWRAP_BLOCK_SIZE = 8;
    /** IV (integrity check value) size */
    public static final int IV_SIZE = 8;
    /** Minimum wrap input size, two 8-byte blocks */
    public static final int MIN_WRAP_INPUT_SIZE = 16;
    /** Minimum unwrap input size, three 8-byte blocks */
    public static final int MIN_UNWRAP_INPUT_SIZE = 24;

    /** Key mode for wrap */
    public static final int ENCRYPT_MODE = 0;
    /** Key mode for unwrap */
    public static final int DECRYPT_MODE = 1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /** Mode the current key was set with */
    private int opmode = -1;

    /* Native JNI methods, callers synchronize on pointerLock */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void wc_AesInit();
    private native void wc_AesFree();
    private native void wc_AesSetKey(byte[] key, int opmode);
    private native int wc_AesKeyWrap_ex(byte[] input, int inputOffset,
        int inputLen, byte[] output, int outputOffset, byte[] iv);
    private native int wc_AesKeyUnWrap_ex(byte[] input, int inputOffset,
        int inputLen, byte[] output, int outputOffset, byte[] iv);

    /**
     * Create new AesKeyWrap object.
     *
     * @throws WolfCryptException if AES Key Wrap has not been compiled into
     *         native wolfCrypt library (HAVE_AES_KEYWRAP).
     */
    public AesKeyWrap() {
        if (!FeatureDetect.AesKeyWrapEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    /**
     * Malloc native Aes structure.
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    @Override
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        synchronized (pointerLock) {
            return mallocNativeStruct_internal();
        }
    }

    /**
     * Release native Aes structure, zeroizing the key schedule. The
     * object may be re-keyed with setKey() after release.
     */
    @Override
    public synchronized void releaseNativeStruct() {

        synchronized (stateLock) {
            synchronized (pointerLock) {
                if ((state == WolfCryptState.INITIALIZED) ||
                    (state == WolfCryptState.READY)) {
                    wc_AesFree();
                }
                super.releaseNativeStruct();
            }
            this.opmode = -1;
            state = WolfCryptState.RELEASED;
        }
    }

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly
     */
    private void checkStateAndInitialize() throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED ||
                state == WolfCryptState.RELEASED) {
                synchronized (pointerLock) {
                    initNativeStruct();
                    try {
                        wc_AesInit();
                    } catch (WolfCryptException e) {
                        super.releaseNativeStruct();
                        throw e;
                    }
                }
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    /**
     * Throw exception if a key has been loaded into this object.
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
     * Throw exception if a key has not been loaded into this object.
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
     * Throw exception if the key was set for the other direction.
     *
     * @param required ENCRYPT_MODE for wrap, DECRYPT_MODE for unwrap
     * @param op operation name for the exception message
     *
     * @throws IllegalStateException if key was set for the other direction
     */
    private void throwIfWrongDirection(int required, String op)
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.opmode != required) {
                throw new IllegalStateException(op + "() requires key set " +
                    "with " + ((required == ENCRYPT_MODE) ?
                    "ENCRYPT_MODE" : "DECRYPT_MODE"));
            }
        }
    }

    /**
     * Validate wrap/unwrap arguments before they reach native code.
     *
     * @param input input array
     * @param inputOffset offset into input
     * @param inputLen number of input bytes
     * @param output output array
     * @param outputOffset offset into output
     * @param iv optional IV, null or IV_SIZE bytes
     * @param minInput minimum inputLen for this direction
     * @param outputLen number of bytes this direction writes to output
     *
     * @throws WolfCryptException if any argument is invalid
     */
    private static void checkArgs(byte[] input, int inputOffset,
        int inputLen, byte[] output, int outputOffset, byte[] iv,
        int minInput, long outputLen) throws WolfCryptException {

        if (input == null) {
            throw new WolfCryptException("Input array is null");
        }

        if (output == null) {
            throw new WolfCryptException("Output array is null");
        }

        if (inputOffset < 0 || inputLen < 0 || outputOffset < 0) {
            throw new WolfCryptException(
                "Offsets and length must not be negative");
        }

        if (inputLen < minInput) {
            throw new WolfCryptException("Input length must be at least " +
                minInput + " bytes, got " + inputLen);
        }

        if ((inputLen % KEYWRAP_BLOCK_SIZE) != 0) {
            throw new WolfCryptException("Input length must be a multiple " +
                "of " + KEYWRAP_BLOCK_SIZE + " bytes, got " + inputLen);
        }

        if (iv != null && iv.length != IV_SIZE) {
            throw new WolfCryptException("IV must be " + IV_SIZE +
                " bytes, got " + iv.length);
        }

        if (((long)inputOffset + (long)inputLen) > (long)input.length) {
            throw new WolfCryptException(
                "Input offset plus length exceeds input array size");
        }

        if (((long)outputOffset + outputLen) > (long)output.length) {
            throw new WolfCryptException("Output array too small, need " +
                outputLen + " bytes at offset " + outputOffset + ", have " +
                output.length);
        }
    }

    /**
     * Get the wrapped (ciphertext) size for a given plaintext size.
     *
     * @param inputLen plaintext length in bytes
     *
     * @return wrapped size, inputLen + 8
     *
     * @throws IllegalArgumentException if inputLen is negative
     */
    public static int getWrappedSize(int inputLen)
        throws IllegalArgumentException {

        if (inputLen < 0) {
            throw new IllegalArgumentException("inputLen must not be negative");
        }

        if (inputLen > (Integer.MAX_VALUE - KEYWRAP_BLOCK_SIZE)) {
            throw new IllegalArgumentException("inputLen too large");
        }

        return inputLen + KEYWRAP_BLOCK_SIZE;
    }

    /**
     * Get the unwrapped (plaintext) size for a given wrapped size. Input
     * shorter than 8 bytes gives 0 rather than an error, so a buffer can be
     * sized before unwrap() checks its arguments.
     *
     * @param inputLen wrapped data length in bytes
     *
     * @return unwrapped size, inputLen - 8, or 0 if inputLen is smaller
     *         than 8
     *
     * @throws IllegalArgumentException if inputLen is negative
     */
    public static int getUnwrappedSize(int inputLen)
        throws IllegalArgumentException {

        if (inputLen < 0) {
            throw new IllegalArgumentException("inputLen must not be negative");
        }

        if (inputLen < KEYWRAP_BLOCK_SIZE) {
            return 0;
        }

        return inputLen - KEYWRAP_BLOCK_SIZE;
    }

    /**
     * Set the key encryption key (KEK) and direction.
     *
     * @param key AES KEK, 16, 24, or 32 bytes
     * @param opmode ENCRYPT_MODE to wrap, DECRYPT_MODE to unwrap
     *
     * @throws WolfCryptException if key is null, has an invalid length, if
     *         opmode is invalid, or if native key setup fails
     * @throws IllegalStateException if a key has already been set, or if
     *         the object fails to initialize
     */
    public synchronized void setKey(byte[] key, int opmode)
        throws WolfCryptException, IllegalStateException {

        if (key == null) {
            throw new WolfCryptException("Key is null");
        }

        if (key.length != KEY_SIZE_128 && key.length != KEY_SIZE_192 &&
            key.length != KEY_SIZE_256) {
            throw new WolfCryptException("AES key must be " + KEY_SIZE_128 +
                ", " + KEY_SIZE_192 + ", or " + KEY_SIZE_256 +
                " bytes, got " + key.length);
        }

        if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
            throw new WolfCryptException(
                "opmode must be ENCRYPT_MODE or DECRYPT_MODE");
        }

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_AesSetKey(key, opmode);
        }
        this.opmode = opmode;
        state = WolfCryptState.READY;
    }

    /**
     * Wrap key material with the default RFC 3394 IV.
     *
     * @param input plaintext to wrap, at least 16 bytes and a multiple of 8
     *
     * @return wrapped data, input.length + 8 bytes
     *
     * @throws WolfCryptException if input is invalid or native wrap fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with DECRYPT_MODE
     */
    public synchronized byte[] wrap(byte[] input)
        throws WolfCryptException, IllegalStateException {

        return wrap(input, null);
    }

    /**
     * Wrap key material with the given IV (integrity check value).
     *
     * @param input plaintext to wrap, at least 16 bytes and a multiple of 8
     * @param iv 8-byte IV, or null to use the RFC 3394 default
     *
     * @return wrapped data, input.length + 8 bytes
     *
     * @throws WolfCryptException if input or iv is invalid or native wrap
     *         fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with DECRYPT_MODE
     */
    public synchronized byte[] wrap(byte[] input, byte[] iv)
        throws WolfCryptException, IllegalStateException {

        int ret;
        byte[] output;

        if (input == null) {
            throw new WolfCryptException("Input array is null");
        }

        if (input.length > (Integer.MAX_VALUE - KEYWRAP_BLOCK_SIZE)) {
            throw new WolfCryptException("Input too large to wrap");
        }

        output = new byte[getWrappedSize(input.length)];

        ret = wrap(input, 0, input.length, output, 0, iv);
        if (ret != output.length) {
            throw new WolfCryptException("Unexpected wrapped size " + ret +
                ", expected " + output.length);
        }

        return output;
    }

    /**
     * Wrap key material into a caller-supplied output array.
     *
     * @param input array holding plaintext to wrap
     * @param inputOffset offset into input
     * @param inputLen number of bytes to wrap, at least 16 and a multiple
     *        of 8
     * @param output array to receive the wrapped data, must have at least
     *        inputLen + 8 bytes available from outputOffset
     * @param outputOffset offset into output
     * @param iv 8-byte IV, or null to use the RFC 3394 default
     *
     * @return number of bytes written to output, inputLen + 8
     *
     * @throws WolfCryptException if any argument is invalid or native wrap
     *         fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with DECRYPT_MODE
     */
    public synchronized int wrap(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset, byte[] iv)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();
        throwIfWrongDirection(ENCRYPT_MODE, "wrap");

        checkArgs(input, inputOffset, inputLen, output, outputOffset, iv,
            MIN_WRAP_INPUT_SIZE, (long)inputLen + KEYWRAP_BLOCK_SIZE);

        synchronized (pointerLock) {
            return wc_AesKeyWrap_ex(input, inputOffset, inputLen, output,
                outputOffset, iv);
        }
    }

    /**
     * Unwrap key material with the default RFC 3394 IV.
     *
     * @param input wrapped data, at least 24 bytes and a multiple of 8
     *
     * @return unwrapped plaintext, input.length - 8 bytes
     *
     * @throws WolfCryptException if input is invalid, or with error
     *         BAD_KEYWRAP_IV_E if the integrity check fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with ENCRYPT_MODE
     */
    public synchronized byte[] unwrap(byte[] input)
        throws WolfCryptException, IllegalStateException {

        return unwrap(input, null);
    }

    /**
     * Unwrap key material with the given IV (integrity check value).
     *
     * @param input wrapped data, at least 24 bytes and a multiple of 8
     * @param iv 8-byte IV, or null to use the RFC 3394 default
     *
     * @return unwrapped plaintext, input.length - 8 bytes
     *
     * @throws WolfCryptException if input or iv is invalid, or with error
     *         BAD_KEYWRAP_IV_E if the integrity check fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with ENCRYPT_MODE
     */
    public synchronized byte[] unwrap(byte[] input, byte[] iv)
        throws WolfCryptException, IllegalStateException {

        int ret;
        byte[] output;

        if (input == null) {
            throw new WolfCryptException("Input array is null");
        }

        /* validated by the array variant, this only sizes the output */
        output = new byte[getUnwrappedSize(input.length)];

        ret = unwrap(input, 0, input.length, output, 0, iv);
        if (ret != output.length) {
            Arrays.fill(output, (byte)0);
            throw new WolfCryptException("Unexpected unwrapped size " + ret +
                ", expected " + output.length);
        }

        return output;
    }

    /**
     * Unwrap key material into a caller-supplied output array.
     *
     * Nothing is written to output unless the integrity check passes.
     *
     * @param input array holding wrapped data
     * @param inputOffset offset into input
     * @param inputLen number of bytes to unwrap, at least 24 and a multiple
     *        of 8
     * @param output array to receive the plaintext, must have at least
     *        inputLen - 8 bytes available from outputOffset
     * @param outputOffset offset into output
     * @param iv 8-byte IV, or null to use the RFC 3394 default
     *
     * @return number of bytes written to output, inputLen - 8
     *
     * @throws WolfCryptException if any argument is invalid, or with error
     *         BAD_KEYWRAP_IV_E if the integrity check fails
     * @throws IllegalStateException if no key is loaded, or the key was
     *         loaded with ENCRYPT_MODE
     */
    public synchronized int unwrap(byte[] input, int inputOffset,
        int inputLen, byte[] output, int outputOffset, byte[] iv)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();
        throwIfWrongDirection(DECRYPT_MODE, "unwrap");

        checkArgs(input, inputOffset, inputLen, output, outputOffset, iv,
            MIN_UNWRAP_INPUT_SIZE, (long)inputLen - KEYWRAP_BLOCK_SIZE);

        synchronized (pointerLock) {
            return wc_AesKeyUnWrap_ex(input, inputOffset, inputLen, output,
                outputOffset, iv);
        }
    }
}
