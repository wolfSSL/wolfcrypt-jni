/* Rsa.java
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt RSA implementation.
 */
public class Rsa extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private boolean hasPrivateKey = false;
    private Rng rng;

    /**
     * Minimum RSA key size in bits, as supported by native wolfSSL
     */
    public static final int RSA_MIN_SIZE = Rsa.rsaMinSize();

    /**
     * Used to indicate that salt length is the same as hash length
     */
    public static final int RSA_PSS_SALT_LEN_DEFAULT = -1;
    /**
     * Used to indicate that the salt length is determined from the data.
     */
    public static final int RSA_PSS_SALT_LEN_DISCOVER = -2;

    /**
     * Mask Generation Function 1 with no hash function
     */
    public static final int WC_MGF1NONE = 0;

    /**
     * Mask Generation Function 1 with SHA-1
     */
    public static final int WC_MGF1SHA1 = 26;

    /**
     * Mask Generation Function 1 with SHA-224
     */
    public static final int WC_MGF1SHA224 = 4;

    /**
     * Mask Generation Function 1 with SHA-256
     */
    public static final int WC_MGF1SHA256 = 1;

    /**
     * Mask Generation Function 1 with SHA-384
     */
    public static final int WC_MGF1SHA384 = 2;

    /**
     * Mask Generation Function 1 with SHA-512
     */
    public static final int WC_MGF1SHA512 = 3;

    /**
     * Mask Generation Function 1 with SHA-512/224
     */
    public static final int WC_MGF1SHA512_224 = 5;

    /**
     * Mask Generation Function 1 with SHA-512/256
     */
    public static final int WC_MGF1SHA512_256 = 6;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Malloc native JNI Rsa structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Decode/import raw RSA public key
     *
     * @param n RSA n parameter
     * @param nSize size of n
     * @param e RSA e parameter
     * @param eSize size of e
     *
     * @throws WolfCryptException if native operation fails
     */
    private native void wc_RsaPublicKeyDecodeRaw(ByteBuffer n, long nSize,
            ByteBuffer e, long eSize) throws WolfCryptException;
    private native void wc_RsaPublicKeyDecodeRaw(byte[] n, long nSize, byte[] e,
            long eSize) throws WolfCryptException;

    private native void RsaFlattenPublicKey(ByteBuffer n, ByteBuffer e)
            throws WolfCryptException;
    private native void RsaFlattenPublicKey(byte[] n, long[] nSize, byte[] e,
            long[] eSize) throws WolfCryptException;
    private native void wc_RsaExportCrtKey(byte[] n, long[] nSz, byte[] e,
            long[] eSz, byte[] d, long[] dSz, byte[] p, long[] pSz,
            byte[] q, long[] qSz, byte[] dP, long[] dPSz, byte[] dQ,
            long[] dQSz, byte[] u, long[] uSz) throws WolfCryptException;
    private native void wc_RsaImportCrtKey(byte[] n, byte[] e, byte[] d,
            byte[] p, byte[] q, byte[] dP, byte[] dQ, byte[] u)
            throws WolfCryptException;
    private native void MakeRsaKey(int size, long e, Rng rng)
        throws WolfCryptException;
    private native byte[] wc_RsaKeyToDer()
            throws WolfCryptException;
    private native byte[] wc_RsaKeyToPublicDer()
            throws WolfCryptException;
    private native byte[] wc_RsaPrivateKeyToPkcs8()
            throws WolfCryptException;
    private native void wc_InitRsaKey()
            throws WolfCryptException;
    private native void wc_FreeRsaKey()
            throws WolfCryptException;
    private native boolean wc_RsaSetRNG(Rng rng)
            throws WolfCryptException;
    private native void wc_RsaPrivateKeyDecode(byte[] key)
            throws WolfCryptException;
    private native void wc_RsaPrivateKeyDecodePKCS8(byte[] key)
            throws WolfCryptException;
    private native void wc_RsaPublicKeyDecode(byte[] key)
            throws WolfCryptException;
    private native int wc_RsaEncryptSize()
            throws WolfCryptException;
    private native byte[] wc_RsaPublicEncrypt(byte[] data, Rng rng)
            throws WolfCryptException;
    private native byte[] wc_RsaPrivateDecrypt(byte[] data)
            throws WolfCryptException;
    private native byte[] wc_RsaSSL_Sign(byte[] data, Rng rng)
            throws WolfCryptException;
    private native byte[] wc_RsaSSL_Verify(byte[] data)
            throws WolfCryptException;
    private static native int rsaMinSize();

    /* RSA-PSS functions */
    private native byte[] wc_RsaPSS_Sign(byte[] data, long hashType, int mgf,
            int saltLen, Rng rng) throws WolfCryptException;
    private native boolean wc_RsaPSS_Verify(byte[] signature, byte[] data,
            long hashType, int mgf, int saltLen) throws WolfCryptException;
    private native boolean wc_RsaPSS_VerifyInline(byte[] signatureAndData,
            long hashType, int mgf, int saltLen) throws WolfCryptException;
    private native boolean wc_RsaPSS_VerifyCheck(byte[] signature, byte[] data,
            byte[] digest, long hashType, int mgf, int saltLen)
            throws WolfCryptException;
    private native boolean wc_RsaPSS_CheckPadding(byte[] pssData, byte[] digest,
            int hashType, int mgf, int saltLen) throws WolfCryptException;

    /**
     * Create new Rsa object.
     *
     * @throws WolfCryptException if RSA has not been compiled into native
     *         wolfCrypt library.
     */
    public Rsa() {
        if (!FeatureDetect.RsaEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Lazy init for Fips compatibility */
    }

    /**
     * Create new Rsa object from provided private key.
     *
     * @param key private RSA key, BER encoded
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of the private key bytes inside this Rsa class. Please
     *             refactor existing code to use the Rsa() default constructor
     *             then call Rsa.decodePrivateKey(byte[] key) after object
     *             creation.
     */
    @Deprecated
    public Rsa(byte[] key) throws WolfCryptException {

        throw new WolfCryptException(
            "Constructor deprecated, use Rsa.decodePrivateKey(byte[] key) " +
            "after object creation with Rsa()");
    }

    /**
     * Create new Rsa object from provided public key.
     *
     * @param n RSA n parameter
     * @param e RSA e parameter
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage of the
     *             RSA raw key components inside this Rsa class. Please
     *             refactor existing code to use the Rsa() default constructor
     *             then call Rsa.decodeRawPublicKey(byte[] n, byte[] e) after
     *             object creation.
     */
    @Deprecated
    public Rsa(byte[] n, byte[] e) throws WolfCryptException {

        throw new WolfCryptException(
            "Constructor deprecated, use " +
            "Rsa.decodeRawPublicKey(byte[] n, byte[] e) after object " +
            "creation with Rsa()");

    }

    /**
     * Return the value of native wolfCrypt default RSA public exponent size.
     * Native default is stored in the WC_RSA_EXPONENT define.
     *
     * @return value of native WC_RSA_EXPONENT, default RSA expoonent size
     */
    public static native long getDefaultRsaExponent();

    @Override
    public synchronized void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_FreeRsaKey();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

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
     * Initialize Rsa object, called internally by checkStateAndInitialize().
     *
     * @throws WolfCryptException if native operation fails
     */
    private void init() throws WolfCryptException {

        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_InitRsaKey();
        }
        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Throw exception if RSA key has been loaded into this object.
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
     * Throw exception if RSA key has not been loaded into this object.
     *
     * @param priv true to check private key, otherwise false to check if only
     *             public key has been loaded.
     *
     * @throws IllegalStateException if key has not been loaded
     */
    private void throwIfKeyNotLoaded(boolean priv)
        throws IllegalStateException {

        synchronized (stateLock) {
            if (priv && !hasPrivateKey) {
                throw new IllegalStateException("No RSA private key loaded");
            }
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException("No RSA public key loaded");
            }
        }
    }

    /**
     * Set Rng object to be used in this Rsa object.
     *
     * @param rng Rng to be used with this Rsa object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized void setRng(Rng rng) throws WolfCryptException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            if (wc_RsaSetRNG(rng)) {
                this.rng = rng;
            }
        }
    }

    /**
     * Generate an RSA key of specified size and exponent.
     *
     * @param size size of RSA key to generate
     * @param e RSA exponent to use for generation
     * @param rng initiailzed Rng object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void makeKey(int size, long e, Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                MakeRsaKey(size, e, rng);
            }

            state = WolfCryptState.READY;
            hasPrivateKey = true;
        }
    }

    /**
     * Decode/import a public RSA key from byte array.
     *
     * @param key DER encoded RSA public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has already been set, if
     *         object fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodePublicKey(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaPublicKeyDecode(key);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Decode/import a private RSA key from byte array.
     *
     * @param key DER encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodePrivateKey(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaPrivateKeyDecode(key);
            }
            state = WolfCryptState.READY;
            hasPrivateKey = true;
        }
    }

    /**
     * Decode/import a private RSA key from PKCS#8 format byte array.
     *
     * @param key PKCS#8 encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodePrivateKeyPKCS8(byte[] key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaPrivateKeyDecodePKCS8(key);
            }

            state = WolfCryptState.READY;
            hasPrivateKey = true;
        }
    }

    /**
     * Decode/import a public RSA key from component byte arrays.
     *
     * @param n RSA n component
     * @param e RSA e component
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodeRawPublicKey(byte[] n, byte[] e)
        throws WolfCryptException, IllegalStateException {

        decodeRawPublicKey(n, n.length, e, e.length);
    }

    /**
     * Decode/import raw public RSA key
     *
     * @param n RSA n component
     * @param nSize size of n
     * @param e RSA e component
     * @param eSize size of e
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodeRawPublicKey(byte[] n, long nSize,
        byte[] e, long eSize)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Decode/import a raw public RSA key from component ByteBuffers.
     *
     * @param n RSA n component
     * @param e RSA e component
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodeRawPublicKey(ByteBuffer n, ByteBuffer e)
        throws WolfCryptException, IllegalStateException {

        decodeRawPublicKey(n, n.limit(), e, e.limit());
    }

    /**
     * Decode/import a raw public RSA key from component ByteBuffers and
     * sizes.
     *
     * @param n RSA n component
     * @param nSz size of n
     * @param e RSA e component
     * @param eSz size of e
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void decodeRawPublicKey(ByteBuffer n, long nSz,
        ByteBuffer e, long eSz)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Export RSA public key as raw byte array components.
     *
     * @param n output buffer to place RSA n component
     * @param nSz [IN/OUT] size of n buffer on input, size of data written to
     *        n array on output
     * @param e output buffer to place RSA e component
     * @param eSz [IN/OUT] size of e buffer on input, size of data written to
     *        e array on output
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void exportRawPublicKey(byte[] n, long[] nSz, byte[] e,
        long[] eSz) throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            RsaFlattenPublicKey(n, nSz, e, eSz);
        }
    }

    /**
     * Export RSA public key as raw ByteBuffer components.
     *
     * @param n output buffer to place RSA n component
     * @param e output buffer to place RSA e component
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void exportRawPublicKey(ByteBuffer n, ByteBuffer e)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            RsaFlattenPublicKey(n, e);
        }
    }

    /**
     * Export RSA private key components including CRT parameters.
     *
     * Exports all RSA private key components: modulus (n), public exponent
     * (e), private exponent (d), prime factors (p, q), and CRT parameters
     * (dP, dQ, u). Each output buffer should be pre-allocated to appropriate
     * size, and size arrays will be updated with actual exported sizes.
     *
     * @param n output buffer for modulus
     * @param nSz array with buffer size, updated with actual size
     * @param e output buffer for public exponent
     * @param eSz array with buffer size, updated with actual size
     * @param d output buffer for private exponent
     * @param dSz array with buffer size, updated with actual size
     * @param p output buffer for prime p
     * @param pSz array with buffer size, updated with actual size
     * @param q output buffer for prime q
     * @param qSz array with buffer size, updated with actual size
     * @param dP output buffer for CRT exponent dP (d mod (p-1))
     * @param dPSz array with buffer size, updated with actual size
     * @param dQ output buffer for CRT exponent dQ (d mod (q-1))
     * @param dQSz array with buffer size, updated with actual size
     * @param u output buffer for CRT coefficient u (q^-1 mod p)
     * @param uSz array with buffer size, updated with actual size
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if
     *         object fails to initialize, or if releaseNativeStruct() has
     *         been called and object has been released.
     */
    public synchronized void exportRawPrivateKey(byte[] n, long[] nSz,
        byte[] e, long[] eSz, byte[] d, long[] dSz, byte[] p, long[] pSz,
        byte[] q, long[] qSz, byte[] dP, long[] dPSz, byte[] dQ,
        long[] dQSz, byte[] u, long[] uSz) throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            wc_RsaExportCrtKey(n, nSz, e, eSz, d, dSz, p, pSz, q, qSz,
                dP, dPSz, dQ, dQSz, u, uSz);
        }
    }

    /**
     * Import RSA private key from raw CRT parameters.
     *
     * Imports RSA private key from all components: modulus (n), public
     * exponent (e), private exponent (d), prime factors (p, q), and CRT
     * parameters (dP, dQ, u).
     *
     * @param n modulus as byte array (big-endian, unsigned)
     * @param e public exponent as byte array (big-endian, unsigned)
     * @param d private exponent as byte array (big-endian, unsigned)
     * @param p prime factor p as byte array (big-endian, unsigned)
     * @param q prime factor q as byte array (big-endian, unsigned)
     * @param dP CRT exponent dP (d mod (p-1)) as byte array
     * @param dQ CRT exponent dQ (d mod (q-1)) as byte array
     * @param u CRT coefficient u (q^-1 mod p) as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized void importRawPrivateKey(byte[] n, byte[] e,
        byte[] d, byte[] p, byte[] q, byte[] dP, byte[] dQ, byte[] u)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_RsaImportCrtKey(n, e, d, p, q, dP, dQ, u);
            }

            state = WolfCryptState.READY;
            hasPrivateKey = true;
        }
    }

    /**
     * Export RSA private key as a DER format byte array.
     *
     * @return byte array containing DER encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] exportPrivateDer()
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            return wc_RsaKeyToDer();
        }
    }

    /**
     * Export RSA public key as DER format byte array.
     *
     * @return byte array containing DER encoded RSA public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] exportPublicDer()
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaKeyToPublicDer();
        }
    }

    /**
     * Encode and return RSA private key as PKCS#8 format byte buffer.
     *
     * @return byte array containing a PKCS#8 encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] privateKeyEncodePKCS8()
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            return wc_RsaPrivateKeyToPkcs8();
        }
    }

    /**
     * Get the RSA encrypt size, using RSA public n component.
     *
     * @return RSA encrypt size
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized int getEncryptSize()
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaEncryptSize();
        }
    }

    /**
     * Encrypt data with RSA using public key.
     *
     * @param plain input data to be encrypted
     * @param rng initialized Rng object
     *
     * @return encrypted data as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] encrypt(byte[] plain, Rng rng)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaPublicEncrypt(plain, rng);
        }
    }

    /**
     * Decrypt data with RSA using private key.
     *
     * @param ciphertext encrypted data to decrypt
     *
     * @return decrypted data as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] decrypt(byte[] ciphertext)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            return wc_RsaPrivateDecrypt(ciphertext);
        }
    }

    /**
     * Sign data with RSA private key.
     *
     * @param data input data to be signed
     * @param rng initialized Rng object
     *
     * @return RSA signature of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] sign(byte[] data, Rng rng)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            return wc_RsaSSL_Sign(data, rng);
        }
    }

    /**
     * Verify data with RSA public key.
     *
     * @param signature signature to be verified
     *
     * @return data unwrapped as part of signature operation
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] verify(byte[] signature)
        throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaSSL_Verify(signature);
        }
    }

    /**
     * Sign data with RSA-PSS private key.
     *
     * @param data input data to be signed
     * @param hashType hash type (WC_HASH_TYPE_*)
     * @param mgf mask generation function (ex: WC_MGF1SHA256 for MGF1
     *            with SHA-256)
     * @param saltLen salt length in bytes, or special value
     * @param rng initialized Rng object
     *
     * @return RSA-PSS signature of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if private key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized byte[] rsaPssSign(byte[] data, long hashType, int mgf,
        int saltLen, Rng rng) throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(true);

        synchronized (pointerLock) {
            return wc_RsaPSS_Sign(data, hashType, mgf, saltLen, rng);
        }
    }

    /**
     * Verify data with RSA-PSS public key.
     *
     * @param signature signature to be verified
     * @param data original data that was signed
     * @param hashType hash type (WC_HASH_TYPE_*)
     * @param mgf mask generation function (ex: WC_MGF1SHA256 for MGF1
     *            with SHA-256)
     * @param saltLen salt length in bytes, or special value
     *
     * @return true if signature is valid, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized boolean rsaPssVerify(byte[] signature, byte[] data,
        long hashType, int mgf, int saltLen) throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaPSS_Verify(signature, data, hashType, mgf, saltLen);
        }
    }

    /**
     * RSA-PSS verification of precomputed digest.
     *
     * @param signature signature to be verified
     * @param data original data that was signed
     * @param digest pre-computed digest of data
     * @param hashType hash type (WC_HASH_TYPE_*)
     * @param mgf mask generation function (WC_MGF1SHA256 for MGF1 with SHA-256)
     * @param saltLen salt length in bytes, or special value
     *
     * @return true if signature is valid, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if public key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public synchronized boolean rsaPssVerifyWithDigest(byte[] signature,
            byte[] data, byte[] digest, long hashType, int mgf, int saltLen)
            throws WolfCryptException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded(false);

        synchronized (pointerLock) {
            return wc_RsaPSS_VerifyCheck(signature, data, digest, hashType,
                mgf, saltLen);
        }
    }

    /**
     * Check RSA-PSS padding separately from signature verification.
     *
     * @param pssData PSS padded data
     * @param digest expected message digest
     * @param hashType hash algorithm type
     * @param mgf mask generation function (WC_MGF1SHA256 for MGF1 with SHA-256)
     * @param saltLen salt length in bytes, or special value
     *
     * @return true if padding is valid, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public synchronized boolean rsaPssCheckPadding(byte[] pssData,
            byte[] digest, int hashType, int mgf, int saltLen)
            throws WolfCryptException {

        checkStateAndInitialize();

        synchronized (pointerLock) {
            return wc_RsaPSS_CheckPadding(pssData, digest, hashType,
                mgf, saltLen);
        }
    }
}

