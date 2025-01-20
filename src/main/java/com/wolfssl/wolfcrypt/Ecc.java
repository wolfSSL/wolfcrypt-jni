/* Ecc.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.EllipticCurve;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECFieldFp;

import com.wolfssl.wolfcrypt.Rng;

/**
 * Wrapper for the native WolfCrypt ECC implementation
 */
public class Ecc extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /* used with native wc_ecc_set_rng() */
    private Rng rng = null;

    /* Do we own the Rng struct, or has that been passed in? Used
     * during Rng cleanup. */
    private boolean weOwnRng = true;

    /** Lock around Rng object access */
    private final Object rngLock = new Object();

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Ecc object.
     *
     * @throws WolfCryptException if ECC has not been compiled into native
     *         wolfCrypt library.
     */
    public Ecc() {
        if (!FeatureDetect.EccEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    /**
     * Create new Ecc object with existing Rng object.
     *
     * @param rng initialized com.wolfssl.wolfcrypt.Rng object
     *
     * @throws WolfCryptException if ECC has not been compiled into native
     *         wolfCrypt library.
     */
    public Ecc(Rng rng) {
        if (!FeatureDetect.EccEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        /* Internal state is initialized on first use */
        this.rng = rng;
        weOwnRng = false;
    }

    @Override
    public synchronized void releaseNativeStruct() {

        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_ecc_free();
                }

                synchronized (rngLock) {
                    if (this.weOwnRng && this.rng != null) {
                        rng.free();
                        rng.releaseNativeStruct();
                        rng = null;
                    }
                }

                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Malloc native JNI ecc_key structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_ecc_init();
    private native void wc_ecc_free();
    private native void wc_ecc_make_key(Rng rng, int size);
    private native void wc_ecc_make_key_ex(Rng rng, int size, String curveName);
    private native void wc_ecc_check_key();
    private native byte[] wc_ecc_shared_secret(Ecc pubKey, Rng rng);
    private native void wc_ecc_import_private(byte[] privKey, byte[] x963Key,
                                              String curveName);
    private native byte[] wc_ecc_export_private();
    private native void wc_ecc_import_x963(byte[] key);
    private native byte[] wc_ecc_export_x963();
    private native void wc_EccPrivateKeyDecode(byte[] key);
    private native byte[] wc_EccKeyToDer();
    private native void wc_EccPublicKeyDecode(byte[] key);
    private native byte[] wc_EccPublicKeyToDer();
    private native byte[] wc_ecc_sign_hash(byte[] hash, Rng rng);
    private native boolean wc_ecc_verify_hash(byte[] hash, byte[] signature);
    private static native int wc_ecc_get_curve_size_from_name(String name);
    private native byte[] wc_ecc_private_key_to_pkcs8();
    private static native String wc_ecc_get_curve_name_from_id(int curve_id);
    private static native int wc_ecc_get_curve_id_from_params(int fieldSize,
            byte[] prime, byte[] Af, byte[] Bf, byte[] order,
            byte[] Gx, byte[] Gy, int cofactor);

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly or
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
                if (state != WolfCryptState.INITIALIZED) {
                    throw new IllegalStateException(
                        "Failed to initialize Object");
                }
            }
        }
    }

    /**
     * Initialize Ecc object
     */
    private void init() {
        /* Allocate native struct pointer from NativeStruct */
        initNativeStruct();
        synchronized (pointerLock) {
            wc_ecc_init();
        }

        /* used with native wc_ecc_set_rng() */
        synchronized (rngLock) {
            if (rng == null) {
                rng = new Rng();
                rng.init();
                weOwnRng = true;
            }
        }

        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Throw exception if key has been loaded already.
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
     * Throw exception if key has not been loaded.
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
     * Generate ECC key
     *
     * @param rng initialized Rng object
     * @param size size of key to generate
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void makeKey(Rng rng, int size)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_ecc_make_key(rng, size);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Generate ECC key on specified curve
     *
     * @param rng initialized Rng object
     * @param size size of key to generate
     * @param curveName name of ECC curve on which to generate key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void makeKeyOnCurve(Rng rng, int size, String curveName)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_ecc_make_key_ex(rng, size, curveName.toUpperCase());
        }
        state = WolfCryptState.READY;
    }

    /**
     * Check correctness of ECC key
     *
     * @throws WolfCryptException if native operation fails or key is
     *         incorrect or invalid
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void checkKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_ecc_check_key();
        }
    }

    /**
     * Import private ECC key
     *
     * @param privKey byte array holding private key
     * @param x963Key byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void importPrivate(byte[] privKey, byte[] x963Key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_ecc_import_private(privKey, x963Key, null);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Import private key on specified ECC curve
     *
     * @param privKey byte array holding private key
     * @param x963Key byte array holding public key
     * @param curveName name of ECC curve key is on
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void importPrivateOnCurve(byte[] privKey,
        byte[] x963Key, String curveName)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_ecc_import_private(privKey, x963Key, curveName);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Export private ECC key
     *
     * @return byte array with private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] exportPrivate()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ecc_export_private();
        }
    }

    /**
     * Import public ECC key in X9.63 format
     *
     * @param key public key in X9.63 format
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void importX963(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_ecc_import_x963(key);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Export public ECC key in X9.63 format
     *
     * @return public key in X9.63 format
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] exportX963()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ecc_export_x963();
        }
    }

    /**
     * Decode/import private ECC key in ASN.1/DER format
     *
     * @param key private key array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void privateKeyDecode(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_EccPrivateKeyDecode(key);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Encode/export private ECC key in ASN.1/DER format
     *
     * @return private key byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] privateKeyEncode()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_EccKeyToDer();
        }
    }

    /**
     * Decode/import public ECC key in ASN.1/DER format
     *
     * @param key public key array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void publicKeyDecode(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (pointerLock) {
            wc_EccPublicKeyDecode(key);
        }
        state = WolfCryptState.READY;
    }

    /**
     * Encode/export public ECC key in ASN.1/DER format
     *
     * @return public key byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] publicKeyEncode()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_EccPublicKeyToDer();
        }
    }

    /**
     * Generate ECDH shared secret between this object and specified public key
     *
     * @param pubKey public ECC key to use with secret generation
     *
     * @return generated shared secret byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] makeSharedSecret(Ecc pubKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            synchronized (rngLock) {
                return wc_ecc_shared_secret(pubKey, this.rng);
            }
        }
    }

    /**
     * Generate an ECDSA signature.
     *
     * @param hash input hash to be signed
     * @param rng initialized Rng object
     *
     * @return ECDSA signature of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] sign(byte[] hash, Rng rng)
        throws WolfCryptException, IllegalStateException {

        byte[] signature = null;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            synchronized (rngLock) {
                signature = wc_ecc_sign_hash(hash, rng);
            }
        }

        return signature;
    }

    /**
     * Verify an ECDSA signature.
     *
     * @param hash input hash to verify signature against
     * @param signature input signature to verify
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized boolean verify(byte[] hash, byte[] signature)
        throws WolfCryptException, IllegalStateException {

        boolean result = false;

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            result = wc_ecc_verify_hash(hash, signature);
        }

        return result;
    }

    /**
     * Get ECC curve size from curve name.
     *
     * Ecc object does not need to be initialized to call this method.
     *
     * @param curveName name of ECC curve
     *
     * @return size of ECC curve
     *
     * @throws WolfCryptException if native operation fails
     */
    public static int getCurveSizeFromName(String curveName)
        throws WolfCryptException {

        /* Ecc object doesn't need to be initialied before call */
        return wc_ecc_get_curve_size_from_name(curveName);
    }

    /**
     * Encode private ECC key in PKCS#8 format.
     *
     * @return encoded private key as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] privateKeyEncodePKCS8()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ecc_private_key_to_pkcs8();
        }
    }

    /**
     * Get ECC curve name from ECParameterSpec
     *
     * @param spec ECParameterSpec to get curve name from
     *
     * @return ECC curve name
     *
     * @throws WolfCryptException if native operation fails
     * @throws InvalidAlgorithmParameterException if spec.getCurve().getField()
     *         is not an instance of ECFieldFp
     */
    public static String getCurveName(ECParameterSpec spec)
        throws WolfCryptException, InvalidAlgorithmParameterException {

        int curve_id;

        /* Ecc object doesn't need to be initialied before call */
        if (!(spec.getCurve().getField() instanceof ECFieldFp)) {
            throw new InvalidAlgorithmParameterException(
                "Currently only ECFieldFp fields supported");
        }
        ECFieldFp field = (ECFieldFp)spec.getCurve().getField();
        EllipticCurve curve = spec.getCurve();

        curve_id = wc_ecc_get_curve_id_from_params(
                    field.getFieldSize(),
                    field.getP().toByteArray(),
                    curve.getA().toByteArray(),
                    curve.getB().toByteArray(),
                    spec.getOrder().toByteArray(),
                    spec.getGenerator().getAffineX().toByteArray(),
                    spec.getGenerator().getAffineY().toByteArray(),
                    spec.getCofactor());

        return wc_ecc_get_curve_name_from_id(curve_id);
    }
}

