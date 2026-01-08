/* Dh.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

    /* Named DH group constants (FFDHE from RFC 7919) */
    /** FFDHE 2048-bit group */
    public static final int WC_FFDHE_2048 = 256;
    /** FFDHE 3072-bit group */
    public static final int WC_FFDHE_3072 = 257;
    /** FFDHE 4096-bit group */
    public static final int WC_FFDHE_4096 = 258;
    /** FFDHE 6144-bit group */
    public static final int WC_FFDHE_6144 = 259;
    /** FFDHE 8192-bit group */
    public static final int WC_FFDHE_8192 = 260;

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
    private native void wc_DhCheckPubKey(byte[] pub);
    private static native byte[][] wc_DhCopyNamedKey(int name);
    private static native byte[][] wc_DhGenerateParams(Rng rng, int modSz);
    private native void wc_DhImportKeyPair(byte[] priv, byte[] pub,
        byte[] p, byte[] g);
    private native byte[][] wc_DhExportKeyPair();
    private native byte[][] wc_DhExportParams();
    private native byte[] wc_DhPrivateKeyDecode(byte[] pkcs8);
    private native byte[] wc_DhPrivateKeyEncode();
    private native byte[] wc_DhPublicKeyDecode(byte[] x509);
    private native byte[] wc_DhPublicKeyEncode();

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

    /**
     * Get named DH parameters (FFDHE groups from RFC 7919).
     *
     * Returns an array containing [p, g] parameters for the named group.
     *
     * @param name Named DH group constant (WC_FFDHE_2048, WC_FFDHE_3072,
     *             WC_FFDHE_4096, WC_FFDHE_6144, or WC_FFDHE_8192)
     *
     * @return byte array containing [p, g] parameters, or null on error
     *
     * @throws WolfCryptException if native operation fails or named group
     *         is not supported
     */
    public static byte[][] getNamedDhParams(int name)
        throws WolfCryptException {

        if (!FeatureDetect.DhEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        return wc_DhCopyNamedKey(name);
    }

    /**
     * Generate DH parameters dynamically.
     *
     * Returns an array containing [p, g] parameters for the specified
     * modulus size.
     *
     * This method generates DH parameters at runtime, which can be slow
     * for larger modulus sizes. For standard sizes (2048, 3072, 4096,
     * 6144, 8192), consider using getNamedDhParams() which uses
     * pre-computed FFDHE parameters from RFC 7919.
     *
     * @param rng Initialized Rng object to use for parameter generation
     * @param modSz Modulus size in bits (e.g., 512, 1024, 2048)
     *
     * @return byte array containing [p, g] parameters, or null on error
     *
     * @throws WolfCryptException if native operation fails or if
     *         parameter generation is not supported
     */
    public static byte[][] generateDhParams(Rng rng, int modSz)
        throws WolfCryptException {

        if (!FeatureDetect.DhEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        if (rng == null) {
            throw new WolfCryptException("Rng cannot be null");
        }

        if (modSz <= 0) {
            throw new WolfCryptException("Invalid modulus size: " + modSz);
        }

        return wc_DhGenerateParams(rng, modSz);
    }

    /**
     * Import DH key pair with parameters into this Dh object.
     *
     * @param priv Private key value as byte array
     * @param pub Public key value as byte array
     * @param p Prime modulus parameter
     * @param g Base generator parameter
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized void importKeyPair(byte[] priv, byte[] pub,
        byte[] p, byte[] g)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            wc_DhImportKeyPair(priv, pub, p, g);
        }

        /* Reset stored keys if new ones are imported */
        this.privateKey = null;
        this.publicKey = null;
        this.pSize = 0;

        if (priv != null) {
            this.privateKey = priv.clone();
        }

        if (pub != null) {
            this.publicKey = pub.clone();
        }

        if (p != null) {
            this.pSize = p.length;
        }

        state = WolfCryptState.READY;
    }

    /**
     * Export DH key pair from this Dh object.
     *
     * @return byte[][] array containing [privateKey, publicKey]
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[][] exportKeyPair()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_DhExportKeyPair();
        }
    }

    /**
     * Export DH parameters from this Dh object.
     *
     * @return byte[][] array containing [p, g, q] or [p, g] if q is null
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[][] exportParams()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_DhExportParams();
        }
    }

    /**
     * Decode and import DH private key from PKCS#8 DER format.
     *
     * @param pkcs8 DER-encoded PKCS#8 private key
     *
     * @return DER-encoded private key (may be re-encoded by wolfCrypt)
     *
     * @throws WolfCryptException if native operation fails or DER is invalid
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[] privateKeyDecodePKCS8(byte[] pkcs8)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (pkcs8 == null || pkcs8.length == 0) {
            throw new WolfCryptException("PKCS#8 data cannot be null or empty");
        }

        synchronized (pointerLock) {
            return wc_DhPrivateKeyDecode(pkcs8);
        }
    }

    /**
     * Encode and export DH private key to PKCS#8 DER format.
     *
     * @return DER-encoded PKCS#8 private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[] privateKeyEncodePKCS8()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_DhPrivateKeyEncode();
        }
    }

    /**
     * Decode and import DH public key from X.509 DER format.
     *
     * @param x509 DER-encoded X.509 public key
     *
     * @return DER-encoded public key (may be re-encoded by wolfCrypt)
     *
     * @throws WolfCryptException if native operation fails or DER is invalid
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[] publicKeyDecodeX509(byte[] x509)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        if (x509 == null || x509.length == 0) {
            throw new WolfCryptException("X.509 data cannot be null or empty");
        }

        synchronized (pointerLock) {
            return wc_DhPublicKeyDecode(x509);
        }
    }

    /**
     * Encode and export DH public key to X.509 DER format.
     *
     * @return DER-encoded X.509 public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released
     */
    public synchronized byte[] publicKeyEncodeX509()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_DhPublicKeyEncode();
        }
    }
}

