/* AesGcm.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Wrapper for native wolfCrypt AES-GCM implementation.
 */
public class AesGcm extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /* Lock around object state */
    protected final Object stateLock = new Object();

    /* Lock around native Aes poiner use */
    private final Object aesLock = new Object();

    /* Native JNI methods, implemented in jni/jni_aesgcm.c */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void wc_AesInit();
    private native void wc_AesFree();
    private native void wc_AesGcmSetKey(byte[] key);
    private native byte[] wc_AesGcmEncrypt(byte[] input, byte[] iv,
        byte[] authTagOut, byte[] authIn);
    private native byte[] wc_AesGcmDecrypt(byte[] input, byte[] iv,
        byte[] authTag, byte[] authIn);

    /**
     * Create and initialize new AesGcm object
     */
    public AesGcm() {
        init();
    }

    public AesGcm(byte[] key) {
        init();
        setKey(key);
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
        free();
        super.releaseNativeStruct();
    }

    /** Initialize AesGcm object and underlying native Aes structure */
    protected void init() {

        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED) {
                synchronized (pointerLock) {
                    wc_AesInit();
                }
                state = WolfCryptState.INITIALIZED;
            } else {
                throw new IllegalStateException(
                    "Native resources already initialized");
            }
        }
    }

    /** Free AesGcm object and underlying native Aes structure */
    protected synchronized void free() {

        synchronized (stateLock) {
            if (state != WolfCryptState.UNINITIALIZED) {
                synchronized (pointerLock) {
                    wc_AesFree();
                }
                state = WolfCryptState.UNINITIALIZED;
            }
        }
    }

    /**
     * Set AES-GCM key.
     *
     * @param key AES key as byte array. Supported key lengths include:
     *        16 bytes (128-bit)
     *        24 bytes (192-bit)
     *        32 bytes (256-bit)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set
     */
    public synchronized void setKey(byte[] key)
        throws WolfCryptException, IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.INITIALIZED) {
                synchronized (pointerLock) {
                    wc_AesGcmSetKey(key);
                }
                state = WolfCryptState.READY;
            } else {
                throw new IllegalStateException(
                    "Key has already been set for this AesGcm object, " +
                    "or object not initialized");
            }
        }
    }

    /**
     * Encrypt data with AES-GCM.
     *
     * @param input input data to be encrypted
     * @param iv IV for AES-GCM operation
     * @param authTagOut output byte array for auth tag to be placed. Should
     *        be sized to desired tag size, which can be between wolfSSL
     *        minimum auth tag size (default 12) and AES block size (16).
     *        User compiling native wolfSSL can override default minimum
     *        auth tag size by defining WOLFSSL_MIN_AUTH_TAG_SZ.
     * @param authIn additional data to be authenticated but not encrypted,
     *        can be null if no additional data desired or available.
     *
     * @return encrypted cipertext buffer
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set
     */
    public synchronized byte[] encrypt(byte[] input, byte[] iv,
        byte[] authTagOut, byte[] authIn)
        throws IllegalStateException, WolfCryptException {

        byte[] output = null;

        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                synchronized (pointerLock) {
                    output = wc_AesGcmEncrypt(input, iv, authTagOut, authIn);
                }
            }
            else {
                throw new IllegalStateException(
                    "Object has not bee initialized or set up");
            }

            return output;
        }
    }

    /**
     * Decrypt data with AES-GCM.
     *
     * @param input ciphertext to be decrypted
     * @param iv IV for AES-GCM operation
     * @param authTag authentication tag generated during encryption operation
     * @param authIn additional data to be authenticated but not decrypted
     *
     * @return decrypted plaintext buffer
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set
     */
    public synchronized byte[] decrypt(byte[] input, byte[] iv, byte[] authTag,
        byte[] authIn) throws IllegalStateException, WolfCryptException {

        byte[] output = null;

        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                synchronized (pointerLock) {
                    output = wc_AesGcmDecrypt(input, iv, authTag, authIn);
                }
            }
            else {
                throw new IllegalStateException(
                    "Object has not been initialized or set up");
            }

            return output;
        }
    }
}

