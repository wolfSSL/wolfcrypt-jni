/* Hmac.java
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
 * Wrapper for the native WolfCrypt HMAC implementation.
 */
public class Hmac extends NativeStruct {

    private enum hashType {
        typeMD5, typeSHA, typeSHA256, typeSHA384, typeSHA512;
    }

    /* types may be -1 if not compiled in at native level */
    /** HMAC-MD5 type */
    public static final int MD5     = getHashCode(hashType.typeMD5);
    /** HMAC-SHA-1 type */
    public static final int SHA     = getHashCode(hashType.typeSHA);
    /** HMAC-SHA2-256 type */
    public static final int SHA256  = getHashCode(hashType.typeSHA256);
    /** HMAC-SHA2-384 type */
    public static final int SHA384  = getHashCode(hashType.typeSHA384);
    /** HMAC-SHA2-512 type */
    public static final int SHA512  = getHashCode(hashType.typeSHA512);

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private int type = -1;
    private byte[] key;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Hmac object.
     *
     * @throws WolfCryptException if HMAC has not been compiled into native
     *         wolfCrypt library.
     */
    public Hmac() {
        if (!FeatureDetect.HmacEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Create new Hmac object
     *
     * @param type HMAC type (Hmac.SHA, Hmac.SHA256, etc)
     * @param key HMAC key
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of the HMAC key inside this Hmac class at the Java level.
     *             Please refactor existing code to call
     *             Hmac.setKey(int type, byte[] key) after this object has been
     *             created with the default Hmac() constructor.
     */
    @Deprecated
    public Hmac(int type, byte[] key) {

        throw new WolfCryptException(
            "Constructor deprecated, use Hmac.setKey(int type, byte[] key) " +
            "after object creation with Hmac()");
    }

    private native void wc_HmacSetKey(int type, byte[] key);
    private native void wc_HmacUpdate(byte data);
    private native void wc_HmacUpdate(byte[] data, int offset, int length);
    private native void wc_HmacUpdate(ByteBuffer data, int offset, int length);
    private native byte[] wc_HmacFinal();
    private native int wc_HmacSizeByType(int type);
    private native static int getCodeMd5();
    private native static int getCodeSha();
    private native static int getCodeSha256();
    private native static int getCodeSha384();
    private native static int getCodeSha512();
    private native static int getCodeBlake2b();

    /**
     * Malloc native JNI Hmac structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Check if type is -1, if so that type is not compiled in at native
     * wolfSSL level.
     *
     * @throws WolfCryptException if hash type is not compiled in at native
     *         wolfSSL level.
     */
    private void checkHashTypeCompiledIn(int type)
        throws WolfCryptException {

        WolfCryptError notCompiledIn = WolfCryptError.NOT_COMPILED_IN;
        if (type == -1) {
            throw new WolfCryptException(notCompiledIn.getCode());
        }
    }

    /**
     * Throw exception if HMAC key has not been loaded into this object.
     *
     * @throws IllegalStateException if key has not been loaded
     */
    private void throwIfKeyNotLoaded() throws IllegalStateException {

        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException("No HMAC key loaded");
            }
        }
    }

    /**
     * Set HMAC key
     *
     * @param type HMAC type (Hmac.SHA, Hmac.SHA256, etc)
     * @param key HMAC key
     *
     * @throws WolfCryptException if native operation fails
     */
    public synchronized void setKey(int type, byte[] key)
        throws WolfCryptException {

        synchronized (stateLock) {
            /* verify hash type is compiled in */
            checkHashTypeCompiledIn(type);

            synchronized (pointerLock) {
                /* Release native struct in case previously set */
                releaseNativeStruct();

                /* Allocate native struct pointer from NativeStruct */
                initNativeStruct();

                wc_HmacSetKey(type, key);
            }
            this.type = type;
            this.key = key;

            state = WolfCryptState.READY;
        }
    }

    /**
     * Reset Hmac object state with key and type that have been set
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void reset()
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        setKey(type, key);
    }

    /**
     * Perform HMAC update operation
     *
     * @param data single input data byte to update HMAC with
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(byte data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_HmacUpdate(data);
        }
    }

    /**
     * Perform HMAC update operation
     *
     * @param data input data to update HMAC with
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public void update(byte[] data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_HmacUpdate(data, 0, data.length);
        }
    }

    /**
     * Perform HMAC update operation
     *
     * @param data input data to update HMAC with
     * @param offset offset into input data to begin reading
     * @param length length of input data to read
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized void update(byte[] data, int offset, int length)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_HmacUpdate(data, offset, length);
        }
    }

    /**
     * Perform HMAC update operation
     *
     * @param data input data to update HMAC with
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
            wc_HmacUpdate(data, offset, length);
        }

        data.position(offset + length);
    }

    /**
     * Calculate final HMAC
     *
     * @return HMAC result as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] doFinal()
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_HmacFinal();
        }
    }

    /**
     * Calculate final HMAC after processing additional supplied data
     *
     * @param data input data to update HMAC with
     *
     * @return HMAC result as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] doFinal(byte[] data)
        throws WolfCryptException, IllegalStateException {

        throwIfKeyNotLoaded();

        update(data);

        synchronized (pointerLock) {
            return wc_HmacFinal();
        }
    }

    /**
     * Get HMAC algorithm type
     *
     * @return HMAC algorithm
     *
     * @throws IllegalStateException if object has no key
     */
    public synchronized String getAlgorithm()
        throws IllegalStateException {

        throwIfKeyNotLoaded();

        if (type == MD5) {
            return "HmacMD5";
        }
        else if (type == SHA256) {
            return "HmacSHA256";
        }
        else if (type == SHA384) {
            return "HmacSHA384";
        }
        else if (type == SHA512) {
            return "HmacSHA512";
        }
        else {
            return "";
        }
    }

    /**
     * Get HMAC output length
     *
     * @return HMAC length
     *
     * @throws WolfCryptException if native operation fails
     */
    public synchronized int getMacLength() throws WolfCryptException {

        /* Does not use Hmac poiner, no need to lock or check state */
        return wc_HmacSizeByType(type);
    }

    /**
     * Get HMAC hash code
     *
     * @param hash HMAC hash type
     *
     * @return HMAC hash code, or WolfCrypt.FAILURE if hashType is not
     *         supported.
     */
    private static int getHashCode(hashType hash) {
        switch (hash) {
            case typeMD5:
                return getCodeMd5();
            case typeSHA:
                return getCodeSha();
            case typeSHA256:
                return getCodeSha256();
            case typeSHA384:
                return getCodeSha384();
            case typeSHA512:
                return getCodeSha512();
            default:
                return WolfCrypt.FAILURE;
        }
    }
}

