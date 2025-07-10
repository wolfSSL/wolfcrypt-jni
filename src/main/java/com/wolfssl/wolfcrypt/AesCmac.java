/* AesCmac.java
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
 * Wrapper for the native WolfCrypt AES-CMAC implementation.
 *
 * AES-CMAC (Cipher-based Message Authentication Code) is a block cipher-based
 * MAC algorithm. It provides data integrity and authenticity verification.
 */
public class AesCmac extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /* Native JNI methods */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;

    private native void native_init();
    private native void native_free();

    private native void wc_CmacSetKey(byte[] key);
    private native void wc_CmacUpdate(byte data);
    private native void wc_CmacUpdate(byte[] data, int offset, int length);
    private native void wc_CmacUpdate(ByteBuffer data, int offset, int length);
    private native byte[] wc_CmacFinal();

    private static native int wc_AesCmacGenerate(byte[] data, int dataSz,
        byte[] key, int keySz, byte[] mac, int macSz);
    private static native int wc_AesCmacVerify(byte[] mac, int macSz,
        byte[] data, int dataSz, byte[] key, int keySz);

    /**
     * Create new AesCmac object.
     *
     * @throws WolfCryptException if AES-CMAC has not been compiled into native
     *         wolfCrypt library.
     */
    public AesCmac() {
        if (!FeatureDetect.AesCmacEnabled()) {
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
     * Set AES-CMAC key
     *
     * @param key AES-CMAC key (128, 192, or 256 bits)
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
                wc_CmacSetKey(key);
            }

            /* Store key for reset functionality */
            this.key = new byte[key.length];
            System.arraycopy(key, 0, this.key, 0, key.length);

            state = WolfCryptState.READY;
        }
    }

    /**
     * Perform AES-CMAC update operation
     *
     * @param data input data to update AES-CMAC with
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(byte data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_CmacUpdate(data);
        }
    }

    /**
     * Perform AES-CMAC update operation
     *
     * @param data input data to update AES-CMAC with
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(byte[] data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_CmacUpdate(data, 0, data.length);
        }
    }

    /**
     * Perform AES-CMAC update operation
     *
     * @param data input data to update AES-CMAC with
     * @param offset offset into data array to start from
     * @param length number of bytes to process
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(byte[] data, int offset, int length)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_CmacUpdate(data, offset, length);
        }
    }

    /**
     * Perform AES-CMAC update operation
     *
     * @param data input data to update AES-CMAC with
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(ByteBuffer data)
        throws WolfCryptException, IllegalStateException {

        int offset = data.position();
        int length = data.remaining();

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_CmacUpdate(data, offset, length);
        }

        data.position(offset + length);
    }

    /**
     * Calculate final AES-CMAC
     *
     * @return AES-CMAC result as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] doFinal()
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_CmacFinal();
        }
    }

    /**
     * Calculate final AES-CMAC after processing additional supplied data
     *
     * @param data input data to update AES-CMAC with
     *
     * @return AES-CMAC result as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] doFinal(byte[] data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        update(data);

        synchronized (pointerLock) {
            return wc_CmacFinal();
        }
    }

    /**
     * Reset AES-CMAC object state with key that has been set
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void reset()
        throws WolfCryptException, IllegalStateException {

        synchronized (stateLock) {
            throwIfKeyNotLoaded();

            /* Reset the CMAC state without accessing the stored key.
             * Since we already have a valid CMAC context with the key set,
             * we can simply re-initialize it with the same key that's
             * already stored. */
            synchronized (pointerLock) {
                /* Re-set the key using the existing stored key */
                wc_CmacSetKey(key);
            }
        }
    }

    /**
     * Clear the stored key for security purposes.
     * After calling this method, the object must be reinitialized with setKey()
     * before use.
     */
    public synchronized void clearKey() {
        synchronized (stateLock) {
            zeroizeKey();
            state = WolfCryptState.UNINITIALIZED;
        }
    }

    /**
     * Get AES-CMAC algorithm name
     *
     * @return AES-CMAC algorithm name
     *
     * @throws IllegalStateException if object has no key
     */
    public synchronized String getAlgorithm()
        throws IllegalStateException {

        throwIfKeyNotLoaded();

        return "AES-CMAC";
    }

    /**
     * Get AES-CMAC output length in bytes
     *
     * @return AES-CMAC output length (AES block size bytes)
     *
     * @throws IllegalStateException if object has no key
     */
    public synchronized int getMacLength()
        throws IllegalStateException {

        throwIfKeyNotLoaded();

        return Aes.BLOCK_SIZE;
    }

    /**
     * Generate AES-CMAC for given data with given key
     *
     * @param data input data to authenticate
     * @param key AES-CMAC key
     *
     * @return AES-CMAC result as byte array
     *
     * @throws WolfCryptException if native operation fails
     */
    public static synchronized byte[] generate(byte[] data, byte[] key)
        throws WolfCryptException {

        byte[] mac = new byte[Aes.BLOCK_SIZE];

        int ret = wc_AesCmacGenerate(data, data.length, key, key.length,
                                     mac, mac.length);

        if (ret != 0) {
            throw new WolfCryptException(ret);
        }

        return mac;
    }

    /**
     * Verify AES-CMAC for given data with given key
     *
     * @param mac AES-CMAC to verify
     * @param data input data to authenticate
     * @param key AES-CMAC key
     *
     * @return true if verification succeeds, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     */
    public static synchronized boolean verify(byte[] mac, byte[] data,
        byte[] key) throws WolfCryptException {

        int ret = wc_AesCmacVerify(mac, mac.length, data, data.length,
                                   key, key.length);

        return (ret == 0);
    }

    private void throwIfKeyNotLoaded() throws IllegalStateException {
        if (state != WolfCryptState.READY) {
            throw new IllegalStateException("No key available");
        }
    }

}
