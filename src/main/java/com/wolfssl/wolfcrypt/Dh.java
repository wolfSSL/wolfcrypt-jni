/* Dh.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
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
    public void releaseNativeStruct() {
        free();

        super.releaseNativeStruct();
    }

    /**
     * Malloc native JNI DH structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_InitDhKey();
    private native void wc_FreeDhKey();
    private native void wc_DhSetKey(byte[] p, byte[] g);
    private native void wc_DhGenerateKeyPair(Rng rng, int pSize);
    private native byte[] wc_DhAgree(byte[] priv, byte[] pub);

    /** Initialize Dh object */
    protected void init() {
        if (state == WolfCryptState.UNINITIALIZED) {
            wc_InitDhKey();
            state = WolfCryptState.INITIALIZED;
        } else {
            throw new IllegalStateException(
                    "Native resources already initialized.");
        }
    }

    /** Free Dh object */
    protected void free() {
        if (state != WolfCryptState.UNINITIALIZED) {
            wc_FreeDhKey();

            setPrivateKey(new byte[0]);
            setPublicKey(new byte[0]);

            state = WolfCryptState.UNINITIALIZED;
        }
    }

    /**
     * Set private key
     *
     * @param priv private key array
     *
     * @throws IllegalStateException if object uninitialized
     */
    public void setPrivateKey(byte[] priv) {
        if (state != WolfCryptState.UNINITIALIZED) {
            if (privateKey != null)
                for (int i = 0; i < privateKey.length; i++)
                    privateKey[i] = 0;

            privateKey = priv.clone();
        } else {
            throw new IllegalStateException(
                    "No available parameters to perform opetarion.");
        }
    }

    /**
     * Set public key
     *
     * @param pub public key array
     *
     * @throws IllegalStateException if object uninitialized
     */
    public void setPublicKey(byte[] pub) {
        if (state != WolfCryptState.UNINITIALIZED) {
            if (publicKey != null)
                for (int i = 0; i < publicKey.length; i++)
                    publicKey[i] = 0;

            publicKey = pub.clone();
        } else {
            throw new IllegalStateException(
                    "No available parameters to perform opetarion.");
        }
    }

    /**
     * Get public key
     *
     * @return public key as byte array
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Get private key
     *
     * @return private key as byte array
     */
    public byte[] getPrivateKey() {
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
    public void setParams(byte[] p, byte[] g) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_DhSetKey(p, g);
            this.pSize = p.length;
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has parameters.");
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
    public void makeKey(Rng rng) {
        if (privateKey == null) {
            /* use size of P to allocate key buffer size */
            wc_DhGenerateKeyPair(rng, this.pSize);
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
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
    public byte[] makeSharedSecret(Dh pubKey) {
        byte[] publicKey = pubKey.getPublicKey();

        if (privateKey != null || publicKey != null) {
            return wc_DhAgree(privateKey, publicKey);
        } else {
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
        }
    }
}

