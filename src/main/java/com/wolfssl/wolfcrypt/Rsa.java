/* Rsa.java
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt RSA implementation.
 */
public class Rsa extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;
    private boolean hasPrivateKey = false;
    private Rng rng;

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
            ByteBuffer e, long eSize);
    private native void wc_RsaPublicKeyDecodeRaw(byte[] n, long nSize, byte[] e,
            long eSize);
    private native void RsaFlattenPublicKey(ByteBuffer n, ByteBuffer e);
    private native void RsaFlattenPublicKey(byte[] n, long[] nSize, byte[] e,
            long[] eSize);
    private native void MakeRsaKey(int size, long e, Rng rng);
    private native void wc_InitRsaKey();
    private native void wc_FreeRsaKey();
    private native boolean wc_RsaSetRNG(Rng rng);
    private native void wc_RsaPrivateKeyDecode(byte[] key);
    private native void wc_RsaPrivateKeyDecodePKCS8(byte[] key);
    private native void wc_RsaPublicKeyDecode(byte[] key);
    private native int wc_RsaEncryptSize();
    private native byte[] wc_RsaPublicEncrypt(byte[] data, Rng rng);
    private native byte[] wc_RsaPrivateDecrypt(byte[] data);
    private native byte[] wc_RsaSSL_Sign(byte[] data, Rng rng);
    private native byte[] wc_RsaSSL_Verify(byte[] data);

    /**
     * Create new Rsa object
     */
    public Rsa() {
        /* Lazy init for Fips compatibility */
    }

    /**
     * Create new Rsa object from private key
     *
     * @param key private RSA key, BER encoded
     *
     * @throws WolfCryptException if native operation fails
     */
    public Rsa(byte[] key) {
        decodePrivateKey(key);
    }

    /**
     * Create new Rsa object from public key
     *
     * @param n RSA n parameter
     * @param e RSA e parameter
     *
     * @throws WolfCryptException if native operation fails
     */
    public Rsa(byte[] n, byte[] e) {
        decodeRawPublicKey(n, e);
    }

    /**
     * Set Rng for Rsa object
     *
     * @param rng Rng to be used with this Rsa object
     *
     * @throws WolfCryptException if native operation fails
     */
    public void setRng(Rng rng) {
        init();

        if (wc_RsaSetRNG(rng))
            this.rng = rng;
    }

    @Override
    public void releaseNativeStruct() {
        free();

        super.releaseNativeStruct();
    }

    /**
     * Initialize Rsa object
     */
    protected void init() {
        if (state == WolfCryptState.UNINITIALIZED) {
            wc_InitRsaKey();
            state = WolfCryptState.INITIALIZED;
        }
    }

    /**
     * Initialize native RsaKey struct, check if object already has key
     *
     * @throws IllegalStateException if object already has key
     */
    protected void willSetKey() throws IllegalStateException {
        init();

        if (state != WolfCryptState.INITIALIZED)
            throw new IllegalStateException("Object already has a key.");
    }

    /**
     * Check that RsaKey struct has correct key configured.
     *
     * @param priv true if operation will use private key, otherwise false
     *
     * @throws IllegalStateException if no private key available, but needed
     * @throws IllegalStateException if object has no public key
     */
    protected void willUseKey(boolean priv) throws IllegalStateException {
        if (priv && !hasPrivateKey)
            throw new IllegalStateException(
                    "No available private key to perform the opperation.");

        if (state != WolfCryptState.READY)
            throw new IllegalStateException(
                    "No available key to perform the opperation.");
    }

    /**
     * Free Rsa object
     */
    protected void free() {
        if (state != WolfCryptState.UNINITIALIZED) {
            wc_FreeRsaKey();
            state = WolfCryptState.UNINITIALIZED;
        }
    }

    /**
     * Generate RSA key
     *
     * @param size size of RSA key to generate
     * @param e RSA exponent to use for generation
     * @param rng initiailzed Rng object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void makeKey(int size, long e, Rng rng) {
        willSetKey();

        MakeRsaKey(size, e, rng);

        state = WolfCryptState.READY;
        hasPrivateKey = true;
    }

    /**
     * Decode/import public RSA key
     *
     * @param key DER encoded RSA public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodePublicKey(byte[] key) {
        willSetKey();

        wc_RsaPublicKeyDecode(key);
        state = WolfCryptState.READY;
    }

    /**
     * Decode/import private RSA key
     *
     * @param key DER encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodePrivateKey(byte[] key) {
        willSetKey();

        wc_RsaPrivateKeyDecode(key);
        state = WolfCryptState.READY;
        hasPrivateKey = true;
    }

    /**
     * Decode/import private RSA key from PKCS#8 format
     *
     * @param key PKCS#8 encoded RSA private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodePrivateKeyPKCS8(byte[] key) {
        willSetKey();

        wc_RsaPrivateKeyDecodePKCS8(key);

        state = WolfCryptState.READY;
        hasPrivateKey = true;
    }

    /**
     * Decode/import public RSA key
     *
     * @param n RSA n component
     * @param e RSA e component
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodeRawPublicKey(byte[] n, byte[] e) {
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
     * @throws IllegalStateException if object is already initialized
     */
    public void decodeRawPublicKey(byte[] n, long nSize, byte[] e, long eSize) {
        willSetKey();

        wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize);
        state = WolfCryptState.READY;
    }

    /**
     * Decode/import raw public RSA key
     *
     * @param n RSA n component
     * @param e RSA e component
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodeRawPublicKey(ByteBuffer n, ByteBuffer e) {
        decodeRawPublicKey(n, n.limit(), e, e.limit());
    }

    /**
     * Decode/import raw public RSA key
     *
     * @param n RSA n component
     * @param nSz size of n
     * @param e RSA e component
     * @param eSz size of e
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object is already initialized
     */
    public void decodeRawPublicKey(ByteBuffer n, long nSz, ByteBuffer e,
            long eSz) {
        willSetKey();

        wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz);
        state = WolfCryptState.READY;
    }

    /**
     * Export raw RSA public key
     *
     * @param n output buffer to place RSA n component
     * @param nSz [IN/OUT] size of n buffer on input, size of data written to
     *        n array on output
     * @param e output buffer to place RSA e component
     * @param eSz [IN/OUT] size of e buffer on input, size of data written to
     *        e array on output
     *
     * @throws WolfCryptException if native operation fails
     */
    public void exportRawPublicKey(byte[] n, long[] nSz, byte[] e, long[] eSz) {
        willUseKey(false);

        RsaFlattenPublicKey(n, nSz, e, eSz);
    }

    /**
     * Export raw RSA public key
     *
     * @param n output buffer to place RSA n component
     * @param e output buffer to place RSA e component
     *
     * @throws WolfCryptException if native operation fails
     */
    public void exportRawPublicKey(ByteBuffer n, ByteBuffer e) {
        willUseKey(false);

        RsaFlattenPublicKey(n, e);
    }

    /**
     * Get RSA encrypt size
     *
     * @return RSA encrypt size
     *
     * @throws WolfCryptException if native operation fails
     */
    public int getEncryptSize() {
        willUseKey(false);

        return wc_RsaEncryptSize();
    }

    /**
     * Encrypt data with RSA
     *
     * @param plain input to be encrypted
     * @param rng initialized Rng object
     *
     * @return encrypted data as byte array
     *
     * @throws WolfCryptException if native operation fails
     */
    public byte[] encrypt(byte[] plain, Rng rng) {
        willUseKey(false);

        return wc_RsaPublicEncrypt(plain, rng);
    }

    /**
     * Decrypt data with RSA
     *
     * @param ciphertext encrypted data to decrypt
     *
     * @return decrypted data as byte array
     *
     * @throws WolfCryptException if native operation fails
     */
    public byte[] decrypt(byte[] ciphertext) {
        willUseKey(true);

        return wc_RsaPrivateDecrypt(ciphertext);
    }

    /**
     * Sign data with RSA
     *
     * @param data input data to be signed
     * @param rng initialized Rng object
     *
     * @return RSA signature of input data
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object does not have key
     */
    public byte[] sign(byte[] data, Rng rng) {
        willUseKey(true);

        return wc_RsaSSL_Sign(data, rng);
    }

    /**
     * Verify data with RSA
     *
     * @param signature signature to be verified
     *
     * @return data unwrapped as part of signature operation
     *
     * @throws WolfCryptException if native operation fails
     */
    public byte[] verify(byte[] signature) {
        willUseKey(false);

        return wc_RsaSSL_Verify(signature);
    }
}

