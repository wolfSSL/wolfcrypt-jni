/* AesGmac.java
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
 * Wrapper for the native WolfCrypt AES-GMAC implementation.
 *
 * AES-GMAC (Galois Message Authentication Code) is an authentication-only
 * mode of operation for AES-GCM. It provides data integrity and authenticity
 * verification without encryption.
 */
public class AesGmac extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Native JNI methods */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_init();
    private native void native_free();
    private native void wc_GmacSetKey(byte[] key);
    private native byte[] wc_GmacUpdate(byte[] iv, byte[] authIn,
        int authTagSz);
    private static native int wc_Gmac(byte[] key, byte[] iv, byte[] authIn,
        byte[] authTag);
    private static native int wc_GmacVerify(byte[] key, byte[] iv,
        byte[] authIn, byte[] authTag);

    /**
     * Create new AesGmac object.
     *
     * @throws WolfCryptException if AES-GMAC has not been compiled into native
     *         wolfCrypt library.
     */
    public AesGmac() {
        if (!FeatureDetect.AesGmacEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    @Override
    protected long mallocNativeStruct() throws OutOfMemoryError {
        return mallocNativeStruct_internal();
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            native_free();
            super.releaseNativeStruct();
        }
    }

    /**
     * Set AES-GMAC key
     *
     * @param key AES-GMAC key (128, 192, or 256 bits)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has been freed
     */
    public synchronized void setKey(byte[] key)
        throws WolfCryptException, IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED) {
                native_init();
                state = WolfCryptState.INITIALIZED;
            }

            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            /* init native struct with key */
            synchronized (pointerLock) {
                wc_GmacSetKey(key);
            }

            state = WolfCryptState.READY;
        }
    }

    /**
     * Perform AES-GMAC authentication operation
     *
     * @param iv initialization vector
     * @param authIn data to authenticate
     * @param authTagSz size of authentication tag to generate
     *
     * @return authentication tag as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] update(byte[] iv, byte[] authIn, int authTagSz)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_GmacUpdate(iv, authIn, authTagSz);
        }
    }

    /**
     * Get AES-GMAC algorithm name
     *
     * @return AES-GMAC algorithm name
     *
     * @throws IllegalStateException if object has no key
     */
    public synchronized String getAlgorithm()
        throws IllegalStateException {

        throwIfKeyNotLoaded();

        return "AES-GMAC";
    }

    /**
     * Get default AES-GMAC tag length in bytes
     *
     * @return default AES-GMAC tag length (16 bytes)
     *
     * @throws IllegalStateException if object has no key
     */
    public synchronized int getMacLength()
        throws IllegalStateException {

        throwIfKeyNotLoaded();

        return Aes.BLOCK_SIZE;
    }

    /**
     * Generate AES-GMAC for given data with given key
     *
     * @param key AES-GMAC key
     * @param iv initialization vector
     * @param authIn data to authenticate
     * @param authTagSz size of authentication tag to generate
     *
     * @return AES-GMAC authentication tag as byte array
     *
     * @throws WolfCryptException if native operation fails
     */
    public static synchronized byte[] generate(byte[] key, byte[] iv,
        byte[] authIn, int authTagSz) throws WolfCryptException {

        byte[] authTag = new byte[authTagSz];

        int ret = wc_Gmac(key, iv, authIn, authTag);

        if (ret != 0) {
            throw new WolfCryptException(ret);
        }

        return authTag;
    }

    /**
     * Generate AES-GMAC for given data with given key using default tag size
     *
     * @param key AES-GMAC key
     * @param iv initialization vector
     * @param authIn data to authenticate
     *
     * @return AES-GMAC authentication tag as byte array
     *
     * @throws WolfCryptException if native operation fails
     */
    public static synchronized byte[] generate(byte[] key, byte[] iv,
        byte[] authIn) throws WolfCryptException {

        return generate(key, iv, authIn, Aes.BLOCK_SIZE);
    }

    /**
     * Verify AES-GMAC for given data with given key
     *
     * @param key AES-GMAC key
     * @param iv initialization vector
     * @param authIn data that was authenticated
     * @param authTag authentication tag to verify
     *
     * @return true if verification succeeds, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     */
    public static synchronized boolean verify(byte[] key, byte[] iv,
        byte[] authIn, byte[] authTag) throws WolfCryptException {

        int ret = wc_GmacVerify(key, iv, authIn, authTag);

        return (ret == 0);
    }

    private void throwIfKeyNotLoaded() throws IllegalStateException {
        if (state != WolfCryptState.READY) {
            throw new IllegalStateException("No key available");
        }
    }

}
