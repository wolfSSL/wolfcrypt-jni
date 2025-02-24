/* Dh.java
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
 * Wrapper for the native WolfCrypt DH implementation.
 */
public class Dh extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private byte[] privateKey = null;
    private byte[] publicKey = null;
    private int pSize = 0;

    /* DH parameters to init with, will reset to null after initialized */
    private byte[] paramP = null;
    private byte[] paramG = null;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Dh object.
     *
     * @throws WolfCryptException if DH has not been compiled into native
     *         wolfCrypt library.
     */
    public Dh() {
        if (!FeatureDetect.DhEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    /**
     * Create new Dh object
     *
     * @param p DH p parameter
     * @param g DH g parameter
     *
     * @throws WolfCryptException if DH has not been compiled into native
     *         wolfCrypt library.
     */
    public Dh(byte[] p, byte[] g) {
        if (!FeatureDetect.DhEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        /* Internal state is initialized on first use */
        this.paramP = p.clone();
        this.paramG = g.clone();
    }

    @Override
    public synchronized void releaseNativeStruct() {

        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_FreeDhKey();
                }
                setPrivateKey(new byte[0]);
                setPublicKey(new byte[0]);

                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void wc_InitDhKey();
    private native void wc_FreeDhKey();
    private native void wc_DhSetKey(byte[] p, byte[] g);
    private native void wc_DhGenerateKeyPair(Rng rng, int pSize);
    private native byte[] wc_DhAgree(byte[] priv, byte[] pub);

    /**
     * Malloc native JNI DH structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        synchronized (pointerLock) {
            return mallocNativeStruct_internal();
        }
    }

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly, or
     *         if releaseNativeStruct() has been called and object has been
     *         released
     */
    private synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                init();

                if (this.paramP != null && this.paramG != null) {
                    setParams(this.paramP, this.paramG);
                    this.paramP = null;
                    this.paramG = null;
                }
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                throw new IllegalStateException("Failed to initialize Object");
            }
        }
    }

    /**
     * Initialize Dh object.
     */
    private void init() {

        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_InitDhKey();
        }
        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Set private key
     *
     * @param priv private key array
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized void setPrivateKey(byte[] priv)
        throws IllegalStateException {

        checkStateAndInitialize();

        if (privateKey != null) {
            for (int i = 0; i < privateKey.length; i++) {
                privateKey[i] = 0;
            }
        }

        privateKey = priv.clone();
    }

    /**
     * Set public key
     *
     * @param pub public key array
     *
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized void setPublicKey(byte[] pub) {

        checkStateAndInitialize();

        if (publicKey != null) {
            for (int i = 0; i < publicKey.length; i++) {
                publicKey[i] = 0;
            }
        }

        publicKey = pub.clone();
    }

    /**
     * Get public key
     *
     * @return public key as byte array
     */
    public synchronized byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Get private key
     *
     * @return private key as byte array
     */
    public synchronized byte[] getPrivateKey() {
        return privateKey;
    }

    /**
     * Set DH parameters
     *
     * @param p DH p parameter
     * @param g DH g parameter
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized void setParams(byte[] p, byte[] g)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            wc_DhSetKey(p, g);
        }
        this.pSize = p.length;
        state = WolfCryptState.READY;
    }

    /**
     * Generate DH key inside object
     *
     * @param rng initialized Rng object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (privateKey == null) {
            /* use size of P to allocate key buffer size */
            synchronized (pointerLock) {
                wc_DhGenerateKeyPair(rng, this.pSize);
            }
        } else {
            throw new IllegalStateException("Object already has a key");
        }
    }

    /**
     * Generate DH shared secret using private and public key stored in
     * this object.
     *
     * @return shared secret as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no stored private and
     *         public keys, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized byte[] makeSharedSecret()
        throws WolfCryptException, IllegalStateException {

        byte[] publicKey = null;

        checkStateAndInitialize();

        publicKey = getPublicKey();
        if (publicKey == null) {
            throw new IllegalStateException(
                "Dh object has no public key");
        }

        return makeSharedSecret(publicKey);
    }

    /**
     * Generate DH shared secret
     *
     * @param pubKey public key to use for secret generation
     *
     * @return shared secret as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] makeSharedSecret(Dh pubKey)
        throws WolfCryptException, IllegalStateException {

        if (pubKey == null) {
            throw new IllegalStateException(
                "Provided public key is null");
        }

        checkStateAndInitialize();

        return makeSharedSecret(pubKey.getPublicKey());
    }

    /**
     * Generate DH shared secret using internal private key and
     * externally-provided public key as byte array.
     *
     * @param pubKey public key to use for secret generation
     *
     * @return shared secret as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] makeSharedSecret(byte[] pubKey)
        throws WolfCryptException, IllegalStateException {

        if (pubKey == null) {
            throw new IllegalStateException(
                "Provided public key is null");
        }

        if (this.privateKey == null) {
            throw new IllegalStateException(
                "Dh object has no private key");
        }

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_DhAgree(this.privateKey, pubKey);
        }
    }
}

