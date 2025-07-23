/* AesCcm.java
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

/**
 * Wrapper for native wolfCrypt AES-CCM implementation.
 */
public class AesCcm extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Lock around native Aes poiner use */
    private final Object aesLock = new Object();

    /* Native JNI methods, implemented in jni/jni_aesccm.c */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void wc_AesInit();
    private native void wc_AesFree();
    private native void wc_AesCcmSetKey(byte[] key);
    private native byte[] wc_AesCcmEncrypt(byte[] input, byte[] nonce,
        byte[] authTagOut, byte[] authIn);
    private native byte[] wc_AesCcmDecrypt(byte[] input, byte[] nonce,
        byte[] authTag, byte[] authIn);

    /**
     * Create a new AesCcm object.
     *
     * @throws WolfCryptException if AES-CCM has not been compiled into native
     *         wolfCrypt library.
     */
    public AesCcm() {
        if (!FeatureDetect.AesCcmEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    /**
     * Create a new AesCcm object using provided key.
     *
     * @param key AES-CCM key to be used with this object
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of the AES key inside this AesCcm class at the Java level.
     *             Please refactor existing code to call
     *             AesCcm.setKey(byte[] key) after this object has been
     *             created with the default AesCcm() constructor.
     */
    @Deprecated
    public AesCcm(byte[] key) {
        throw new WolfCryptException(
            "Constructor deprecated, use AesCcm.setKey(byte[] key) " +
            "after object creation with AesCcm()");
    }

    /**
     * Malloc native Aes structure via JNI. Called by NativeStruct
     * constructor when this object is created.
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
     * Release native Aes structure memory via JNI. Either called explicitly
     * by application or from NativeStruct finalize() method upon object
     * cleanup.
     */
    @Override
    public synchronized void releaseNativeStruct() {

        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {
                synchronized (pointerLock) {
                    wc_AesFree();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly
     * @throws IllegalStateException if releaseNativeStruct() has been called
     *         and object has been released
     */
    private synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                init();
                if (state != WolfCryptState.INITIALIZED) {
                    throw new IllegalStateException(
                        "Failed to initialize Object");
                }
            }
        }
    }

    /**
     * Throw exception if AES key has been loaded into this object.
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
     * Throw exception if AES key has not been loaded into this object.
     *
     * @throws IllegalStateException if key has not been loaded
     */
    private void throwIfKeyNotLoaded() throws IllegalStateException {

        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException("No AES key loaded");
            }
        }
    }

    /** Initialize AesCcm object and underlying native Aes structure */
    private synchronized void init() {

        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_AesInit();
        }
        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Set AES-CCM key.
     *
     * @param key AES key as byte array. Supported key lengths include:
     *        16 bytes (128-bit)
     *        24 bytes (192-bit)
     *        32 bytes (256-bit)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void setKey(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_AesCcmSetKey(key);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Encrypt data with AES-CCM.
     *
     * @param input input data to be encrypted
     * @param nonce nonce/IV for AES-CCM operation. Valid nonce sizes are
     *        between 7 and 13 bytes.
     * @param authTagOut output byte array for auth tag to be placed. Should
     *        be sized to desired tag size. Valid tag sizes are 4, 6, 8,
     *        10, 12, 14, and 16 bytes.
     * @param authIn additional data to be authenticated but not encrypted,
     *        can be null if no additional data desired or available.
     *
     * @return encrypted cipertext buffer
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] encrypt(byte[] input, byte[] nonce,
        byte[] authTagOut, byte[] authIn)
        throws IllegalStateException, WolfCryptException {

        byte[] output = null;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            output = wc_AesCcmEncrypt(input, nonce, authTagOut, authIn);
        }

        return output;
    }

    /**
     * Decrypt data with AES-CCM.
     *
     * @param input ciphertext to be decrypted
     * @param nonce nonce/IV for AES-CCM operation
     * @param authTag authentication tag generated during encryption operation
     * @param authIn additional data to be authenticated but not decrypted
     *
     * @return decrypted plaintext buffer
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] decrypt(byte[] input, byte[] nonce,
        byte[] authTag, byte[] authIn)
        throws IllegalStateException, WolfCryptException {

        byte[] output = null;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            output = wc_AesCcmDecrypt(input, nonce, authTag, authIn);
        }

        return output;
    }
}