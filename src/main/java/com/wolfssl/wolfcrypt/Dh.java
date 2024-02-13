/* Dh.java
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
 * Wrapper for the native WolfCrypt DH implementation.
 */
public class Dh extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private byte[] privateKey = null;
    private byte[] publicKey = null;
    private int pSize = 0;

    /* Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Dh object
     */
    public Dh() {
        init();
    }

    /**
     * Create new Dh object
     *
     * @param p DH p parameter
     * @param g DH g parameter
     */
    public Dh(byte[] p, byte[] g) {
        init();
        setParams(p, g);
    }

    @Override
    public synchronized void releaseNativeStruct() {
        free();

        super.releaseNativeStruct();
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


    /** Initialize Dh object */
    protected void init() {

        synchronized (stateLock) {
            if (state == WolfCryptState.UNINITIALIZED) {

                synchronized (pointerLock) {
                    wc_InitDhKey();
                }
                state = WolfCryptState.INITIALIZED;
            } else {
                throw new IllegalStateException(
                    "Native resources already initialized");
            }
        }
    }

    /** Free Dh object */
    protected synchronized void free() {

        synchronized (stateLock) {
            if (state != WolfCryptState.UNINITIALIZED) {

                synchronized (pointerLock) {
                    wc_FreeDhKey();
                }
                setPrivateKey(new byte[0]);
                setPublicKey(new byte[0]);

                state = WolfCryptState.UNINITIALIZED;
            }
        }
    }

    /**
     * Set private key
     *
     * @param priv private key array
     *
     * @throws IllegalStateException if object uninitialized
     */
    public synchronized void setPrivateKey(byte[] priv)
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state != WolfCryptState.UNINITIALIZED) {
                if (privateKey != null) {
                    for (int i = 0; i < privateKey.length; i++) {
                        privateKey[i] = 0;
                    }
                }

                privateKey = priv.clone();
            } else {
                throw new IllegalStateException(
                    "No available parameters to perform operation");
            }
        }
    }

    /**
     * Set public key
     *
     * @param pub public key array
     *
     * @throws IllegalStateException if object uninitialized
     */
    public synchronized void setPublicKey(byte[] pub) {

        synchronized (stateLock) {
            if (state != WolfCryptState.UNINITIALIZED) {
                if (publicKey != null) {
                    for (int i = 0; i < publicKey.length; i++) {
                        publicKey[i] = 0;
                    }
                }

                publicKey = pub.clone();
            } else {
                throw new IllegalStateException(
                    "No available parameters to perform operation");
            }
        }
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
     * @throws IllegalStateException if object already initialized
     */
    public synchronized void setParams(byte[] p, byte[] g)
        throws WolfCryptException, IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.INITIALIZED) {

                synchronized (pointerLock) {
                    wc_DhSetKey(p, g);
                }
                this.pSize = p.length;
                state = WolfCryptState.READY;
            } else {
                throw new IllegalStateException(
                    "Object already has parameters");
            }
        }
    }

    /**
     * Generate DH key inside object
     *
     * @param rng initialized Rng object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key
     */
    public synchronized void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

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
     * @throws IllegalStateException if this object has no stored private
     *         and public keys
     */
    public synchronized byte[] makeSharedSecret()
        throws WolfCryptException, IllegalStateException {

        byte[] publicKey = getPublicKey();

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
     * @throws IllegalStateException if object has no key
     */
    public synchronized byte[] makeSharedSecret(Dh pubKey)
        throws WolfCryptException, IllegalStateException {

        byte[] publicKey = null;

        if (pubKey == null) {
            throw new IllegalStateException(
                "Provided public key is null");
        }

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
     * @throws IllegalStateException if object has no key
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

        synchronized (pointerLock) {
            return wc_DhAgree(this.privateKey, pubKey);
        }
    }
}

