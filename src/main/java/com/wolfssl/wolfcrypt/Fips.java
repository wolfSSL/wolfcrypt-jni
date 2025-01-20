/* Fips.java
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
import com.wolfssl.wolfcrypt.Aes;

/**
 * Thin JNI wrapper for the native WolfCrypt FIPS 140-2/3 specific APIs.
 *
 * -----------------------------------------------------------------------------
 * THREADING / SYNCHRONIZATION NOTE:
 * -----------------------------------------------------------------------------
 * If being used in a multi-threaded environment, please use the main
 * wolfCrypt JNI interface (com.wolfssl.wolfcrypt.*). The main wolfCrypt JNI
 * interface will call down to wolfCrypt FIPS internally when compiled against
 * a wolfSSL FIPS distribution. This class (com.wolfssl.wolfcrypt.Fips)
 * contains a very thin JNI wrapper around the FIPS-specific named APIs from
 * wolfCrypt, but currently lacks threading synchronization protections.
 *
 * This class should be used for the more generic FIPS handling and behavior.
 * For example Fips.enabled, functionality to get the core hash, and set the
 * FIPS error callback - regardless of if using the crypto APIs in this class
 * or the ones in the general wolfCrypt JNI classes.
 * -----------------------------------------------------------------------------
 */
public class Fips extends WolfObject {

    /** Is FIPS enabled at native wolfCrypt level */
    public static final boolean enabled = Fips.enabled();

    /** Native wolfCrypt FIPS version (HAVE_FIPS_VERSION) */
    public static final int fipsVersion = Fips.getFipsVersion();

    /* Internal flag to keep track of if FIPS CAST has already been run and
     * passed successfully. */
    private static volatile boolean fipsCastRunSuccessfully = false;

    /* Lock around fipsCastRunSuccessfully */
    private static final Object fipsCastLock = new Object();

    private Fips() {
    }

    /** wolfCrypt FIPS error callback interface */
    public interface ErrorCallback {
        /**
         * wolfCrypt FIPS error callback definition
         *
         * @param ok 1 if wolfCrypt verification passed, otherwise 0
         * @param err wolfCrypt FIPS error code
         * @param hash wolfCrypt FIPS verifyCore hash value
         */
        public void errorCallback(int ok, int err, String hash);
    }

    /**
     * Sets a callback class for handling FIPS errors.
     *
     * @param callback the wolfCrypt FIPS callback class.
     */
    public static native void wolfCrypt_SetCb_fips(ErrorCallback callback);

    /**
     * The current inCore hash of the wolfCrypt FIPS code.
     *
     * This value should be used to update the value stored in 'verifyCore':
     * native_wolfssl/wolfcrypt/src/fips_test.c
     *
     * @return current inCore hash.
     */
    public static native String wolfCrypt_GetCoreHash_fips();

    /**
     * Polls the underlying wolfCrypt library to see if HAVE_FIPS is defined.
     *
     * @return true if HAVE_FIPS has been defined and FIPS mode is enabled,
     *         otherwise false.
     */
    private static native boolean enabled();

    /**
     * Needs to match native WC_KEYTYPE_ALL in fips.h.
     * Used with Fips.get/setPrivateKeyReadEnable()
     */
    public static final int WC_KEYTYPE_ALL = 0;

    /**
     * Enable reading/export of private key from wolfCrypt FIPS module.
     *
     * @param enable enable/disable ability to read private keys from module
     * @param keyType type of key to enable/disable. Currently only supports
     *                Fips.WC_KEYTYPE_ALL
     * @return 0 on success, negative on error
     */
    public static native int setPrivateKeyReadEnable(int enable, int keyType);

    /**
     * Get enable status for ability of application to read/export private key
     * material from wolfCrypt FIPS library.
     *
     * @param keyType type of key to poll enable/disable status for. Currently
     *                the only keyType supported is Fips.WC_KEYTYPE_ALL
     *
     * @return 1 if able to read private key material, otherwise 0
     */
    public static native int getPrivateKeyReadEnable(int keyType);

    /**
     * Native JNI wrapper around running FIPS CASTs.
     *
     * Called by public runAllCast_fips() in this class.
     *
     * @return 0 on success, otherwise greater than zero if some algorithm
     *         self tests have failed. The count of tests failed will be
     *         returned on error.
     */
    private static native int wc_runAllCast_fips();

    /**
     * Run all FIPS Conditional Algorithm Self Tests (CAST).
     *
     * In wolfCrypt FIPS 140-3, the algorithm self tests are Conditional (CAST),
     * meaning they will run on-demand per algorithm the first time that
     * algorithm is used. This can be convienent for startup time if on a
     * single threaded application, but can introduce potentially unwanted
     * errors at runtime if operating in a multi threaded environment where
     * multiple threads will be using wolfCrypt cryptography in parallel. If
     * one thread is actively running an algorithm CAST and another thread
     * tries to use the algorithm, it may return a FIPS not allowed error.
     *
     * To avoid multi threaded errors at runtime due to the above, this method
     * can be called once up front when an application starts. It will run
     * all algorithm CASTS, and if run before threaded operations start will
     * avoid the FIPS not allowed errors which may occur otherwise.
     *
     * @return 0 on success, otherwise greater than zero if some algorithm
     *         self tests have failed. The count of tests failed will be
     *         returned on error.
     */
    public static int runAllCast_fips() {

        int ret = 0;

        synchronized (fipsCastLock) {
            if (!fipsCastRunSuccessfully) {
                ret = wc_runAllCast_fips();
                if (ret == 0) {
                    /* Only forcefully run FIPS CAST once */
                    fipsCastRunSuccessfully = true;
                }
            }
        }

        return ret;
    }

    /* wolfCrypt FIPS API - Show status Service */

    /**
     * Returns the current status of the wolfCrypt FIPS module.
     * @return A return code of 0 means the module is in a state without
     *         errors. Any other return code is the specific error state of
     *         the module.
     */
    public static native int wolfCrypt_GetStatus_fips();

    /**
     * Sets the fips module status. Only available if HAVE_FORCE_FIPS_FAILURE is
     * defined on the native library.
     *
     * @param status
     *            the new status.
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static native int wolfCrypt_SetStatus_fips(int status);

    private static native int getFipsVersion();

    /* -----------------------------------------------------------------------*/
    /* Private JNI methods, called by public methods in this class            */
    /* -----------------------------------------------------------------------*/
    private static native int wc_AesSetKey_fips(Aes aes, ByteBuffer userKey,
        long keylen, ByteBuffer iv, int dir);
    private static native int wc_AesSetKey_fips(Aes aes, byte[] userKey,
        long keylen, byte[] iv, int dir);
    private static native int wc_AesSetIV_fips(Aes aes, ByteBuffer iv);
    private static native int wc_AesSetIV_fips(Aes aes, byte[] iv);

    private static native int wc_AesCbcEncrypt_fips(Aes aes, ByteBuffer out,
        ByteBuffer in, long sz);
    private static native int wc_AesCbcEncrypt_fips(Aes aes, byte[] out,
        byte[] in, long sz);
    private static native int wc_AesCbcDecrypt_fips(Aes aes, ByteBuffer out,
        ByteBuffer in, long sz);
    private static native int wc_AesCbcDecrypt_fips(Aes aes, byte[] out,
        byte[] in, long sz);

    private static native int wc_AesGcmSetKey_fips(Aes aes, ByteBuffer userKey,
        long keylen);
    private static native int wc_AesGcmSetKey_fips(Aes aes, byte[] userKey,
        long keylen);
    private static native int wc_AesGcmSetExtIV_fips(Aes aes, ByteBuffer iv,
        long ivlen);
    private static native int wc_AesGcmSetExtIV_fips(Aes aes, byte[] iv,
        long ivlen);
    private static native int wc_AesGcmEncrypt_fips(Aes aes, ByteBuffer out,
        ByteBuffer in, long sz, ByteBuffer iv, long ivSz, ByteBuffer authTag,
        long authTagSz, ByteBuffer authIn, long authInSz);
    private static native int wc_AesGcmEncrypt_fips(Aes aes, byte[] out,
        byte[] in, long sz, byte[] iv, long ivSz, byte[] authTag,
        long authTagSz, byte[] authIn, long authInSz);
    private static native int wc_AesGcmDecrypt_fips(Aes aes, ByteBuffer out,
        ByteBuffer in, long sz, ByteBuffer iv, long ivSz, ByteBuffer authTag,
        long authTagSz, ByteBuffer authIn, long authInSz);
    private static native int wc_AesGcmDecrypt_fips(Aes aes, byte[] out,
        byte[] in, long sz, byte[] iv, long ivSz, byte[] authTag,
        long authTagSz, byte[] authIn, long authInSz);

    private static native int wc_Des3_SetKey_fips(Des3 des, ByteBuffer userKey,
        ByteBuffer iv, int dir);
    private static native int wc_Des3_SetKey_fips(Des3 des, byte[] userKey,
        byte[] iv, int dir);
    private static native int wc_Des3_SetIV_fips(Des3 des, ByteBuffer iv);
    private static native int wc_Des3_SetIV_fips(Des3 des, byte[] iv);
    private static native int wc_Des3_CbcEncrypt_fips(Des3 des, ByteBuffer out,
        ByteBuffer in, long sz);
    private static native int wc_Des3_CbcEncrypt_fips(Des3 des, byte[] out,
        byte[] in, long sz);
    private static native int wc_Des3_CbcDecrypt_fips(Des3 des, ByteBuffer out,
        ByteBuffer in, long sz);
    private static native int wc_Des3_CbcDecrypt_fips(Des3 des, byte[] out,
        byte[] in, long sz);

    private static native int wc_HmacSetKey_fips(Hmac hmac, int type,
        ByteBuffer key, long keySz);
    private static native int wc_HmacSetKey_fips(Hmac hmac, int type,
        byte[] key, long keySz);
    private static native int wc_HmacUpdate_fips(Hmac hmac, ByteBuffer data,
        long len);
    private static native int wc_HmacUpdate_fips(Hmac hmac, byte[] data,
        long len);
    private static native int wc_HmacFinal_fips(Hmac hmac, ByteBuffer hash);
    private static native int wc_HmacFinal_fips(Hmac hmac, byte[] hash);

    private static native int wc_InitRng_fips(Rng rng);
    private static native int wc_FreeRng_fips(Rng rng);
    private static native int wc_RNG_GenerateBlock_fips(Rng rng, ByteBuffer buf,
        long bufSz);
    private static native int wc_RNG_GenerateBlock_fips(Rng rng, byte[] buf,
        long bufSz);
    private static native int wc_RNG_HealthTest_fips(int reseed,
        ByteBuffer entropyA, long entropyASz, ByteBuffer entropyB,
        long entropyBSz, ByteBuffer output, long outputSz);
    private static native int wc_RNG_HealthTest_fips(int reseed,
        byte[] entropyA, long entropyASz, byte[] entropyB, long entropyBSz,
        byte[] output, long outputSz);

    private static native int wc_InitRsaKey_fips(Rsa key, ByteBuffer heap);
    private static native int wc_FreeRsaKey_fips(Rsa key);
    private static native int wc_RsaSSL_Sign_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key, Rng rng);
    private static native int wc_RsaSSL_Sign_fips(byte[] in, long inLen,
        byte[] out, long outLen, Rsa key, Rng rng);
    private static native int wc_RsaSSL_Verify_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key);
    private static native int wc_RsaSSL_Verify_fips(byte[] in, long inLen,
        byte[] out, long outLen, Rsa key);
    private static native int wc_RsaEncryptSize_fips(Rsa key);
    private static native int wc_RsaPrivateKeyDecode_fips(ByteBuffer input,
        long[] inOutIdx, Rsa key, long inSz);
    private static native int wc_RsaPrivateKeyDecode_fips(byte[] input,
        long[] inOutIdx, Rsa key, long inSz);
    private static native int wc_RsaPublicKeyDecode_fips(ByteBuffer input,
        long[] inOutIdx, Rsa key, long inSz);
    private static native int wc_RsaPublicKeyDecode_fips(byte[] input,
        long[] inOutIdx, Rsa key, long inSz);

    private static native int wc_InitSha_fips(Sha sha);
    private static native int wc_ShaUpdate_fips(Sha sha, ByteBuffer data,
        long len);
    private static native int wc_ShaUpdate_fips(Sha sha, byte[] data,
        long len);
    private static native int wc_ShaFinal_fips(Sha sha, ByteBuffer hash);
    private static native int wc_ShaFinal_fips(Sha sha, byte[] hash);

    private static native int wc_InitSha256_fips(Sha256 sha);
    private static native int wc_Sha256Update_fips(Sha256 sha, ByteBuffer data,
        long len);
    private static native int wc_Sha256Update_fips(Sha256 sha, byte[] data,
        long len);
    private static native int wc_Sha256Final_fips(Sha256 sha, ByteBuffer hash);
    private static native int wc_Sha256Final_fips(Sha256 sha, byte[] hash);

    private static native int wc_InitSha384_fips(Sha384 sha);
    private static native int wc_Sha384Update_fips(Sha384 sha, ByteBuffer data,
        long len);
    private static native int wc_Sha384Update_fips(Sha384 sha, byte[] data,
        long len);
    private static native int wc_Sha384Final_fips(Sha384 sha, ByteBuffer hash);
    private static native int wc_Sha384Final_fips(Sha384 sha, byte[] hash);

    private static native int wc_InitSha512_fips(Sha512 sha);
    private static native int wc_Sha512Update_fips(Sha512 sha, ByteBuffer data,
        long len);
    private static native int wc_Sha512Update_fips(Sha512 sha, byte[] data,
        long len);
    private static native int wc_Sha512Final_fips(Sha512 sha, ByteBuffer hash);
    private static native int wc_Sha512Final_fips(Sha512 sha, byte[] hash);

    private static native int wc_RsaPublicEncrypt_fips(ByteBuffer in,
        long inLen, ByteBuffer out, long outLen, Rsa key, Rng rng);
    private static native int wc_RsaPublicEncrypt_fips(byte[] in, long inLen,
        byte[] out, long outLen, Rsa key, Rng rng);
    private static native int wc_RsaPrivateDecrypt_fips(ByteBuffer in,
        long inLen, ByteBuffer out, long outLen, Rsa key);
    private static native int wc_RsaPrivateDecrypt_fips(byte[] in, long inLen,
        byte[] out, long outLen, Rsa key);

    private static native int wc_InitMd5(Md5 md5);
    private static native int wc_Md5Update(Md5 md5, ByteBuffer data, long len);
    private static native int wc_Md5Update(Md5 md5, byte[] data, long len);
    private static native int wc_Md5Final(Md5 md5, ByteBuffer hash);
    private static native int wc_Md5Final(Md5 md5, byte[] hash);

    private static native void wc_InitDhKey(Dh key);
    private static native void wc_FreeDhKey(Dh key);
    private static native int wc_DhGenerateKeyPair(Dh key, Rng rng,
        ByteBuffer priv, long[] privSz, ByteBuffer pub, long[] pubSz);
    private static native int wc_DhGenerateKeyPair(Dh key, Rng rng,
        byte[] priv, long[] privSz, byte[] pub, long[] pubSz);
    private static native int wc_DhAgree(Dh key, ByteBuffer agree,
        long[] agreeSz, ByteBuffer priv, long privSz, ByteBuffer otherPub,
        long pubSz);
    private static native int wc_DhAgree(Dh key, byte[] agree, long[] agreeSz,
        byte[] priv, long privSz, byte[] otherPub, long pubSz);
    private static native int wc_DhKeyDecode(ByteBuffer input, long[] inOutIdx,
        Dh key, long inSz);
    private static native int wc_DhKeyDecode(byte[] input, long[] inOutIdx,
        Dh key, long inSz);
    private static native int wc_DhSetKey(Dh key, ByteBuffer p, long pSz,
        ByteBuffer g, long gSz);
    private static native int wc_DhSetKey(Dh key, byte[] p, long pSz,
        byte[] g, long gSz);
    private static native int wc_DhParamsLoad(ByteBuffer input, long inSz,
        ByteBuffer p, long[] pInOutSz, ByteBuffer g, long[] gInOutSz);
    private static native int wc_DhParamsLoad(byte[] input, long inSz,
        byte[] p, long[] pInOutSz, byte[] g, long[] gInOutSz);
    private static native int wc_ecc_init(Ecc key);
    private static native void wc_ecc_free(Ecc key);
    private static native int wc_ecc_make_key(Rng rng, int keysize, Ecc key);
    private static native int wc_ecc_shared_secret(Ecc private_key,
        Ecc public_key, ByteBuffer out, long[] outlen);
    private static native int wc_ecc_shared_secret(Ecc private_key,
        Ecc public_key, byte[] out, long[] outlen);
    private static native int wc_ecc_import_x963(ByteBuffer in, long inLen,
        Ecc key);
    private static native int wc_ecc_import_x963(byte[] in, long inLen,
        Ecc key);
    private static native int wc_ecc_export_x963(Ecc key, ByteBuffer out,
        long[] outLen);
    private static native int wc_ecc_export_x963(Ecc key, byte[] out,
        long[] outLen);

    /* -----------------------------------------------------------------------*/
    /* FIPS Approved Security Methods                                         */
    /* -----------------------------------------------------------------------*/

    /* wolfCrypt FIPS API - Symmetric encrypt/decrypt Service */

    /* AES */

    /**
     * Initializes Aes object for CBC mode with key and iv.
     *
     * @param aes the Aes object.
     * @param userKey the key to be set.
     * @param keylen the key length.
     * @param iv the initialization vector (optional).
     * @param dir the direction (encryption|decryption).
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesSetKey_fips(Aes aes, ByteBuffer userKey, long keylen,
        ByteBuffer iv, int dir) {

        runAllCast_fips();

        return wc_AesSetKey_fips(aes, userKey, keylen, iv, dir);
    }

    /**
     * Initializes Aes object for CBC mode with key and iv.
     *
     * @param aes the Aes object.
     * @param userKey the key to be set.
     * @param keylen the key length.
     * @param iv the initialization vector (optional).
     * @param dir the direction (encryption|decryption).
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesSetKey_fips(Aes aes, byte[] userKey, long keylen,
        byte[] iv, int dir) {

        runAllCast_fips();

        return wc_AesSetKey_fips(aes, userKey, keylen, iv, dir);
    }

    /**
     * Initializes Aes object with iv.
     *
     * @param aes the Aes object.
     * @param iv the initialization vector.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesSetIV_fips(Aes aes, ByteBuffer iv) {

        runAllCast_fips();

        return wc_AesSetIV_fips(aes, iv);
    }

    /**
     * Initializes Aes object with iv.
     *
     * @param aes the Aes object.
     * @param iv the initialization vector.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesSetIV_fips(Aes aes, byte[] iv) {

        runAllCast_fips();

        return wc_AesSetIV_fips(aes, iv);
    }

    /**
     * Performs AES-CBC encryption.
     *
     * @param aes the Aes object
     * @param out the output buffer
     * @param in the input buffer
     * @param sz the input length
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesCbcEncrypt_fips(Aes aes, ByteBuffer out, ByteBuffer in,
        long sz) {

        runAllCast_fips();

        return wc_AesCbcEncrypt_fips(aes, out, in, sz);
    }

    /**
     * Performs AES-CBC encryption.
     *
     * @param aes the Aes object
     * @param out the output buffer
     * @param in the input buffer
     * @param sz the input length
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesCbcEncrypt_fips(Aes aes, byte[] out, byte[] in,
        long sz) {

        runAllCast_fips();

        return wc_AesCbcEncrypt_fips(aes, out, in, sz);
    }

    /**
     * Performs AES-CBC decryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesCbcDecrypt_fips(Aes aes, ByteBuffer out,
        ByteBuffer in, long sz) {

        runAllCast_fips();

        return wc_AesCbcDecrypt_fips(aes, out, in, sz);
    }

    /**
     * Performs AES-CBC decryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesCbcDecrypt_fips(Aes aes, byte[] out, byte[] in,
        long sz) {

        runAllCast_fips();

        return wc_AesCbcDecrypt_fips(aes, out, in, sz);
    }

    /**
     * Initializes Aes object for GCM mode with key.
     *
     * @param aes the Aes object.
     * @param userKey the key to be set.
     * @param keylen the key length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmSetKey_fips(Aes aes, ByteBuffer userKey,
        long keylen) {

        runAllCast_fips();

        return wc_AesGcmSetKey_fips(aes, userKey, keylen);
    }

    /**
     * Initializes Aes object for GCM mode with key.
     *
     * @param aes the Aes object.
     * @param userKey the key to be set.
     * @param keylen the key length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmSetKey_fips(Aes aes, byte[] userKey, long keylen) {

        runAllCast_fips();

        return wc_AesGcmSetKey_fips(aes, userKey, keylen);
    }

    /**
     * Initializes Aes object with external IV for AES-GCM.
     *
     * @param aes the Aes object.
     * @param iv the initialization vector.
     * @param ivlen length of IV
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmSetExtIV_fips(Aes aes, ByteBuffer iv, long ivlen) {

        runAllCast_fips();

        return wc_AesGcmSetExtIV_fips(aes, iv, ivlen);
    }

    /**
     * Initializes Aes object with external IV for AES-GCM.
     *
     * @param aes the Aes object.
     * @param iv the initialization vector.
     * @param ivlen length of IV
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmSetExtIV_fips(Aes aes, byte[] iv, long ivlen) {

        runAllCast_fips();

        return wc_AesGcmSetExtIV_fips(aes, iv, ivlen);
    }

    /**
     * Performs AES-GCM encryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     * @param iv the initialization vector buffer.
     * @param ivSz the initialization vector length.
     * @param authTag the authTag buffer.
     * @param authTagSz the authTag length.
     * @param authIn the authIn buffer.
     * @param authInSz the authIn length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmEncrypt_fips(Aes aes, ByteBuffer out, ByteBuffer in,
        long sz, ByteBuffer iv, long ivSz, ByteBuffer authTag, long authTagSz,
        ByteBuffer authIn, long authInSz) {

        runAllCast_fips();

        return wc_AesGcmEncrypt_fips(aes, out, in, sz, iv, ivSz, authTag,
            authTagSz, authIn, authInSz);
    }

    /**
     * Performs AES-GCM encryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     * @param iv the initialization vector buffer.
     * @param ivSz the initialization vector length.
     * @param authTag the authTag buffer.
     * @param authTagSz the authTag length.
     * @param authIn the authIn buffer.
     * @param authInSz the authIn length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmEncrypt_fips(Aes aes, byte[] out, byte[] in,
        long sz, byte[] iv, long ivSz, byte[] authTag, long authTagSz,
        byte[] authIn, long authInSz) {

        runAllCast_fips();

        return wc_AesGcmEncrypt_fips(aes, out, in, sz, iv, ivSz, authTag,
            authTagSz, authIn, authInSz);
    }

    /**
     * Performs AES-GCM decryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     * @param iv the initialization vector buffer.
     * @param ivSz the initialization vector length.
     * @param authTag the authTag buffer.
     * @param authTagSz the authTag length.
     * @param authIn the authIn buffer.
     * @param authInSz the authIn length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmDecrypt_fips(Aes aes, ByteBuffer out, ByteBuffer in,
        long sz, ByteBuffer iv, long ivSz, ByteBuffer authTag, long authTagSz,
        ByteBuffer authIn, long authInSz) {

        runAllCast_fips();

        return wc_AesGcmDecrypt_fips(aes, out, in, sz, iv, ivSz, authTag,
            authTagSz, authIn, authInSz);
    }


    /**
     * Performs AES-GCM decryption.
     *
     * @param aes the Aes object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     * @param iv the initialization vector buffer.
     * @param ivSz the initialization vector length.
     * @param authTag the authTag buffer.
     * @param authTagSz the authTag length.
     * @param authIn the authIn buffer.
     * @param authInSz the authIn length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int AesGcmDecrypt_fips(Aes aes, byte[] out, byte[] in,
        long sz, byte[] iv, long ivSz, byte[] authTag, long authTagSz,
        byte[] authIn, long authInSz) {

        runAllCast_fips();

        return wc_AesGcmDecrypt_fips(aes, out, in, sz, iv, ivSz, authTag,
            authTagSz, authIn, authInSz);
    }

    /* DES3 */

    /**
     * Initializes Des3 object for CBC mode with key and iv.
     *
     * @param des the Des3 object.
     * @param userKey the key to be set.
     * @param iv the initialization vector (optional).
     * @param dir the direction (encryption|decryption).
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_SetKey_fips(Des3 des, ByteBuffer userKey,
        ByteBuffer iv, int dir) {

        runAllCast_fips();

        return wc_Des3_SetKey_fips(des, userKey, iv, dir);
    }

    /**
     * Initializes Des3 object for CBC mode with key and iv.
     *
     * @param des the Des3 object.
     * @param userKey the key to be set.
     * @param iv the initialization vector (optional).
     * @param dir the direction (encryption|decryption).
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_SetKey_fips(Des3 des, byte[] userKey, byte[] iv,
        int dir) {

        runAllCast_fips();

        return wc_Des3_SetKey_fips(des, userKey, iv, dir);
    }

    /**
     * Initializes Des3 object with iv.
     *
     * @param des the Des3 object.
     * @param iv the initialization vector.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_SetIV_fips(Des3 des, ByteBuffer iv) {

        runAllCast_fips();

        return wc_Des3_SetIV_fips(des, iv);
    }

    /**
     * Initializes Des3 object with iv.
     *
     * @param des the Des3 object.
     * @param iv the initialization vector.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_SetIV_fips(Des3 des, byte[] iv) {

        runAllCast_fips();

        return wc_Des3_SetIV_fips(des, iv);
    }

    /**
     * Performs 3DES-CBC encryption.
     *
     * @param des the Des3 object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_CbcEncrypt_fips(Des3 des, ByteBuffer out,
        ByteBuffer in, long sz) {

        runAllCast_fips();

        return wc_Des3_CbcEncrypt_fips(des, out, in, sz);
    }

    /**
     * Performs 3DES-CBC encryption.
     *
     * @param des the Des3 object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_CbcEncrypt_fips(Des3 des, byte[] out, byte[] in,
        long sz) {

        runAllCast_fips();

        return wc_Des3_CbcEncrypt_fips(des, out, in, sz);
    }

    /**
     * Performs 3DES-CBC decryption.
     *
     * @param des the Des3 object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_CbcDecrypt_fips(Des3 des, ByteBuffer out,
        ByteBuffer in, long sz) {

        runAllCast_fips();

        return wc_Des3_CbcDecrypt_fips(des, out, in, sz);
    }

    /**
     * Performs 3DES-CBC decryption.
     *
     * @param des the Des3 object.
     * @param out the output buffer.
     * @param in the input buffer.
     * @param sz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Des3_CbcDecrypt_fips(Des3 des, byte[] out, byte[] in,
        long sz) {

        runAllCast_fips();

        return wc_Des3_CbcDecrypt_fips(des, out, in, sz);
    }

    /* wolfCrypt FIPS API - Keyed hash Service */

    /* HMAC */

    /**
     * Initializes Hmac object with type and key.
     *
     * @param hmac the Hmac object.
     * @param type the digest id.
     * @param key the key buffer.
     * @param keySz the key length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacSetKey_fips(Hmac hmac, int type, ByteBuffer key,
        long keySz) {

        runAllCast_fips();

        return wc_HmacSetKey_fips(hmac, type, key, keySz);
    }

    /**
     * Initializes Hmac object with type and key.
     *
     * @param hmac the Hmac object.
     * @param type the digest id.
     * @param key the key buffer.
     * @param keySz the key length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacSetKey_fips(Hmac hmac, int type, byte[] key,
        long keySz) {

        runAllCast_fips();

        return wc_HmacSetKey_fips(hmac, type, key, keySz);
    }

    /**
     * Updates Hmac object with data.
     *
     * @param hmac the Hmac object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacUpdate_fips(Hmac hmac, ByteBuffer data, long len) {

        runAllCast_fips();

        return wc_HmacUpdate_fips(hmac, data, len);
    }

    /**
     * Updates Hmac object with data.
     *
     * @param hmac the Hmac object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacUpdate_fips(Hmac hmac, byte[] data, long len) {

        runAllCast_fips();

        return wc_HmacUpdate_fips(hmac, data, len);
    }

    /**
     * Outputs Hmac digest to hash.
     *
     * @param hmac the Hmac object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacFinal_fips(Hmac hmac, ByteBuffer hash) {

        runAllCast_fips();

        return wc_HmacFinal_fips(hmac, hash);
    }

    /**
     * Outputs Hmac digest to hash.
     *
     * @param hmac the Hmac object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int HmacFinal_fips(Hmac hmac, byte[] hash) {

        runAllCast_fips();

        return wc_HmacFinal_fips(hmac, hash);
    }

    /* wolfCrypt FIPS API - Random number generation Service */

    /* RNG */

    /**
     * Initializes RNG object's resources and state. FreeRng_fips must be called
     * for resources deallocation.
     *
     * @param rng the RNG object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitRng_fips(Rng rng) {

        runAllCast_fips();

        return wc_InitRng_fips(rng);
    }

    /**
     * Releases RNG object's resources and zeros out state.
     *
     * @param rng the RNG object.
     *
     * @return 0 on success, {@literal <} 0 on error. Also part of Zeroize
     *         Service.
     */
    public static int FreeRng_fips(Rng rng) {

        runAllCast_fips();

        return wc_FreeRng_fips(rng);
    }

    /**
     * Outputs block of random data from RNG object.
     *
     * @param rng the RNG object.
     * @param buf the output buffer.
     * @param bufSz the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RNG_GenerateBlock_fips(Rng rng, ByteBuffer buf,
        long bufSz) {

        runAllCast_fips();

        return wc_RNG_GenerateBlock_fips(rng, buf, bufSz);
    }

    /**
     * Outputs block of random data from RNG object.
     *
     * @param rng the RNG object.
     * @param buf the output buffer.
     * @param bufSz the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RNG_GenerateBlock_fips(Rng rng, byte[] buf, long bufSz) {

        runAllCast_fips();

        return wc_RNG_GenerateBlock_fips(rng, buf, bufSz);
    }

    /**
     * When reseed is 0, tests the output of a temporary instance of an RNG
     * against the expected output of size in bytes outputSz using the seed
     * buffer entropyA of size in bytes entropyASz, where entropyB and
     * entropyBSz are ignored. When reseed is 1, the test also reseeds the
     * temporary instance of the RNG with the seed buffer entropyB of size in
     * bytes entropyBSz and then tests the RNG against the expected output of
     * size in bytes outputSz.
     *
     * @param reseed the reseed flag.
     * @param entropyA the entropyA buffer.
     * @param entropyASz the entropyA length.
     * @param entropyB the entropyB buffer.
     * @param entropyBSz the entropyB length.
     * @param output the output buffer.
     * @param outputSz the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RNG_HealthTest_fips(int reseed, ByteBuffer entropyA,
        long entropyASz, ByteBuffer entropyB, long entropyBSz,
        ByteBuffer output, long outputSz) {

        runAllCast_fips();

        return wc_RNG_HealthTest_fips(reseed, entropyA, entropyASz,
            entropyB, entropyBSz, output, outputSz);
    }

    /**
     * When reseed is 0, tests the output of a temporary instance of an RNG
     * against the expected output of size in bytes outputSz using the seed
     * buffer entropyA of size in bytes entropyASz, where entropyB and
     * entropyBSz are ignored. When reseed is 1, the test also reseeds the
     * temporary instance of the RNG with the seed buffer entropyB of size in
     * bytes entropyBSz and then tests the RNG against the expected output of
     * size in bytes outputSz.
     *
     * @param reseed the reseed flag.
     * @param entropyA the entropyA buffer.
     * @param entropyASz the entropyA length.
     * @param entropyB the entropyB buffer.
     * @param entropyBSz the entropyB length.
     * @param output the output buffer.
     * @param outputSz the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RNG_HealthTest_fips(int reseed, byte[] entropyA,
        long entropyASz, byte[] entropyB, long entropyBSz, byte[] output,
        long outputSz) {

        runAllCast_fips();

        return wc_RNG_HealthTest_fips(reseed, entropyA, entropyASz,
            entropyB, entropyBSz, output, outputSz);
    }

    /*
     * wolfCrypt FIPS API - Digital signature and Key transport Services
     */

    /* RSA */

    /**
     * Initializes Rsa object for use with optional heap hint p. FreeRsaKey_fips
     * must be called for resources deallocation.
     *
     * @param key the Rsa object.
     * @param heap the (optional) heap.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitRsaKey_fips(Rsa key, ByteBuffer heap) {

        runAllCast_fips();

        return wc_InitRsaKey_fips(key, heap);
    }

    /**
     * Releases Rsa object's resources.
     *
     * @param key the Rsa object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int FreeRsaKey_fips(Rsa key) {

        runAllCast_fips();

        return wc_FreeRsaKey_fips(key);
    }

    /**
     * Performs RSA sign operation.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     * @param rng the random source for padding.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaSSL_Sign_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key, Rng rng) {

        runAllCast_fips();

        return wc_RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);
    }

    /**
     * Performs RSA sign operation.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     * @param rng the random source for padding.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaSSL_Sign_fips(byte[] in, long inLen, byte[] out,
        long outLen, Rsa key, Rng rng) {

        runAllCast_fips();

        return wc_RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);
    }

    /**
     * Performs RSA signature verification.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaSSL_Verify_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key) {

        runAllCast_fips();

        return wc_RsaSSL_Verify_fips(in, inLen, out, outLen, key);
    }

    /**
     * Performs RSA signature verification.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaSSL_Verify_fips(byte[] in, long inLen, byte[] out,
        long outLen, Rsa key) {

        runAllCast_fips();

        return wc_RsaSSL_Verify_fips(in, inLen, out, outLen, key);
    }

    /**
     * Retrieves RSA output size.
     *
     * @param key the Rsa object.
     *
     * @return key output size {@literal >} 0 on success, {@literal <} 0 on
     *         error.
     */
    public static int RsaEncryptSize_fips(Rsa key) {

        runAllCast_fips();

        return wc_RsaEncryptSize_fips(key);
    }

    /**
     * Decodes RSA private key from buffer.
     *
     * @param input the input buffer.
     * @param inOutIdx the key's starting index in the input.
     * @param key the Rsa object.
     * @param inSz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPrivateKeyDecode_fips(ByteBuffer input,
        long[] inOutIdx, Rsa key, long inSz) {

        runAllCast_fips();

        return wc_RsaPrivateKeyDecode_fips(input, inOutIdx, key, inSz);
    }

    /**
     * Decodes RSA private key from buffer.
     *
     * @param input the input buffer.
     * @param inOutIdx the key's starting index in the input.
     * @param key the Rsa object.
     * @param inSz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPrivateKeyDecode_fips(byte[] input, long[] inOutIdx,
        Rsa key, long inSz) {

        runAllCast_fips();

        return wc_RsaPrivateKeyDecode_fips(input, inOutIdx, key, inSz);
    }

    /**
     * Decodes RSA public key from buffer.
     *
     * @param input the input buffer.
     * @param inOutIdx the key's starting index in the input.
     * @param key the Rsa object.
     * @param inSz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPublicKeyDecode_fips(ByteBuffer input, long[] inOutIdx,
        Rsa key, long inSz) {

        runAllCast_fips();

        return wc_RsaPublicKeyDecode_fips(input, inOutIdx, key, inSz);
    }

    /**
     * Decodes RSA public key from buffer.
     *
     * @param input the input buffer.
     * @param inOutIdx the key's starting index in the input.
     * @param key the Rsa object.
     * @param inSz the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPublicKeyDecode_fips(byte[] input, long[] inOutIdx,
        Rsa key, long inSz) {

        runAllCast_fips();

        return wc_RsaPublicKeyDecode_fips(input, inOutIdx, key, inSz);
    }

    /* wolfCrypt FIPS API - Message digest Service */

    /* SHA */

    /**
     * Initializes Sha object for use.
     *
     * @param sha the Sha object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitSha_fips(Sha sha) {

        runAllCast_fips();

        return wc_InitSha_fips(sha);
    }

    /**
     * Updates Sha object with data.
     *
     * @param sha the Sha object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ShaUpdate_fips(Sha sha, ByteBuffer data, long len) {

        runAllCast_fips();

        return wc_ShaUpdate_fips(sha, data, len);
    }

    /**
     * Updates Sha object with data.
     *
     * @param sha the Sha object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ShaUpdate_fips(Sha sha, byte[] data, long len) {

        runAllCast_fips();

        return wc_ShaUpdate_fips(sha, data, len);
    }

    /**
     * Outputs Sha digest to hash.
     *
     * @param sha the Sha object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ShaFinal_fips(Sha sha, ByteBuffer hash) {

        runAllCast_fips();

        return wc_ShaFinal_fips(sha, hash);
    }

    /**
     * Outputs Sha digest to hash.
     *
     * @param sha the Sha object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ShaFinal_fips(Sha sha, byte[] hash) {

        runAllCast_fips();

        return wc_ShaFinal_fips(sha, hash);
    }

    /* SHA256 */

    /**
     * Initializes Sha256 object for use.
     *
     * @param sha the Sha256 object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitSha256_fips(Sha256 sha) {

        runAllCast_fips();

        return wc_InitSha256_fips(sha);
    }

    /**
     * Updates Sha256 object with data.
     *
     * @param sha the Sha256 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha256Update_fips(Sha256 sha, ByteBuffer data,
        long len) {

        runAllCast_fips();

        return wc_Sha256Update_fips(sha, data, len);
    }

    /**
     * Updates Sha256 object with data.
     *
     * @param sha the Sha256 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha256Update_fips(Sha256 sha, byte[] data, long len) {

        runAllCast_fips();

        return wc_Sha256Update_fips(sha, data, len);
    }

    /**
     * Outputs Sha256 digest to hash.
     *
     * @param sha the Sha256 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha256Final_fips(Sha256 sha, ByteBuffer hash) {

        runAllCast_fips();

        return wc_Sha256Final_fips(sha, hash);
    }

    /**
     * Outputs Sha256 digest to hash.
     *
     * @param sha the Sha256 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha256Final_fips(Sha256 sha, byte[] hash) {

        runAllCast_fips();

        return wc_Sha256Final_fips(sha, hash);
    }

    /* SHA384 */

    /**
     * Initializes Sha384 object for use.
     *
     * @param sha the Sha384 object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitSha384_fips(Sha384 sha) {

        runAllCast_fips();

        return wc_InitSha384_fips(sha);
    }

    /**
     * Updates Sha384 object with data.
     *
     * @param sha the Sha384 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha384Update_fips(Sha384 sha, ByteBuffer data,
        long len) {

        runAllCast_fips();

        return wc_Sha384Update_fips(sha, data, len);
    }

    /**
     * Updates Sha384 object with data.
     *
     * @param sha the Sha384 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha384Update_fips(Sha384 sha, byte[] data, long len) {

        runAllCast_fips();

        return wc_Sha384Update_fips(sha, data, len);
    }

    /**
     * Outputs Sha384 digest to hash.
     *
     * @param sha the Sha384 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha384Final_fips(Sha384 sha, ByteBuffer hash) {

        runAllCast_fips();

        return wc_Sha384Final_fips(sha, hash);
    }

    /**
     * Outputs Sha384 digest to hash.
     *
     * @param sha the Sha384 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha384Final_fips(Sha384 sha, byte[] hash) {

        runAllCast_fips();

        return wc_Sha384Final_fips(sha, hash);
    }

    /* SHA512 */

    /**
     * Initializes Sha512 object for use.
     *
     * @param sha the Sha512 object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitSha512_fips(Sha512 sha) {

        runAllCast_fips();

        return wc_InitSha512_fips(sha);
    }

    /**
     * Updates Sha512 object with data.
     *
     * @param sha the Sha512 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha512Update_fips(Sha512 sha, ByteBuffer data,
        long len) {

        runAllCast_fips();

        return wc_Sha512Update_fips(sha, data, len);
    }

    /**
     * Updates Sha512 object with data.
     *
     * @param sha the Sha512 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha512Update_fips(Sha512 sha, byte[] data, long len) {

        runAllCast_fips();

        return wc_Sha512Update_fips(sha, data, len);
    }

    /**
     * Outputs Sha512 digest to hash.
     *
     * @param sha the Sha512 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha512Final_fips(Sha512 sha, ByteBuffer hash) {

        runAllCast_fips();

        return wc_Sha512Final_fips(sha, hash);
    }

    /**
     * Outputs Sha512 digest to hash.
     *
     * @param sha the Sha512 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Sha512Final_fips(Sha512 sha, byte[] hash) {

        runAllCast_fips();

        return wc_Sha512Final_fips(sha, hash);
    }

    /* -----------------------------------------------------------------------*/
    /* FIPS Allowed Security Methods                                          */
    /* -----------------------------------------------------------------------*/

    /* wolfCrypt FIPS API - Key Transport Service */

    /**
     * Performs RSA public encryption.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     * @param rng the random source for padding.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPublicEncrypt_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key, Rng rng) {

        runAllCast_fips();

        return wc_RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);
    }

    /**
     * Performs RSA public encryption.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     * @param rng the random source for padding.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPublicEncrypt_fips(byte[] in, long inLen, byte[] out,
        long outLen, Rsa key, Rng rng) {

        runAllCast_fips();

        return wc_RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);
    }

    /**
     * Performs RSA private decryption.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPrivateDecrypt_fips(ByteBuffer in, long inLen,
        ByteBuffer out, long outLen, Rsa key) {

        runAllCast_fips();

        return wc_RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);
    }

    /**
     * Performs RSA private decryption.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param out the output buffer.
     * @param outLen the output length.
     * @param key the Rsa object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int RsaPrivateDecrypt_fips(byte[] in, long inLen, byte[] out,
        long outLen, Rsa key) {

        runAllCast_fips();

        return wc_RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);
    }

    /* wolfCrypt FIPS API - Message digest MD5 Service */

    /**
     * Initializes Md5 object for use.
     *
     * @param md5 the Md5 object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int InitMd5(Md5 md5) {

        runAllCast_fips();

        return wc_InitMd5(md5);
    }

    /**
     * Updates Md5 object with data.
     *
     * @param md5 the Md5 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Md5Update(Md5 md5, ByteBuffer data, long len) {

        runAllCast_fips();

        return wc_Md5Update(md5, data, len);
    }

    /**
     * Updates Md5 object with data.
     *
     * @param md5 the Md5 object.
     * @param data the input buffer.
     * @param len the input length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Md5Update(Md5 md5, byte[] data, long len) {

        runAllCast_fips();

        return wc_Md5Update(md5, data, len);
    }

    /**
     * Outputs Md5 digest to hash.
     *
     * @param md5 the Md5 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Md5Final(Md5 md5, ByteBuffer hash) {

        runAllCast_fips();

        return wc_Md5Final(md5, hash);
    }

    /**
     * Outputs Md5 digest to hash.
     *
     * @param md5 the Md5 object.
     * @param hash the output buffer.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int Md5Final(Md5 md5, byte[] hash) {

        runAllCast_fips();

        return wc_Md5Final(md5, hash);
    }

    /* wolfCrypt FIPS API - Key Agreement Service */

    /**
     * Initializes Dh object for use. FreeDhKey must be called for resources
     * deallocation.
     *
     * @param key the Dh object.
     */
    public static void InitDhKey(Dh key) {

        runAllCast_fips();

        wc_InitDhKey(key);
    }

    /**
     * Releases Dh object's resources.
     *
     * @param key the Dh object.
     */
    public static void FreeDhKey(Dh key) {

        runAllCast_fips();

        wc_FreeDhKey(key);
    }

    /**
     * Generates the public part pub of size pubSz, private part priv of size
     * privSz using rng for Dh key.
     *
     * @param key the Dh object.
     * @param rng the random source.
     * @param priv the private part buffer.
     * @param privSz the private part length.
     * @param pub the public part buffer.
     * @param pubSz the the public part length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhGenerateKeyPair(Dh key, Rng rng, ByteBuffer priv,
        long[] privSz, ByteBuffer pub, long[] pubSz) {

        runAllCast_fips();

        return wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz);
    }

    /**
     * Generates the public part pub of size pubSz, private part priv of size
     * privSz using rng for Dh key.
     *
     * @param key the Dh object.
     * @param rng the random source.
     * @param priv the private part buffer.
     * @param privSz the private part length.
     * @param pub the public part buffer.
     * @param pubSz the the public part length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhGenerateKeyPair(Dh key, Rng rng, byte[] priv,
        long[] privSz, byte[] pub, long[] pubSz) {

        runAllCast_fips();

        return wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz);
    }

    /**
     * Creates the agreement agree of size agreeSz using Dh key private priv of
     * size privSz and peer's public key otherPub of size pubSz.
     *
     * @param key the Dh object.
     * @param agree the agree buffer.
     * @param agreeSz the agree length.
     * @param priv the private part buffer.
     * @param privSz the private part length.
     * @param otherPub the peer's public part buffer.
     * @param pubSz the the public part length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhAgree(Dh key, ByteBuffer agree, long[] agreeSz,
        ByteBuffer priv, long privSz, ByteBuffer otherPub, long pubSz) {

        runAllCast_fips();

        return wc_DhAgree(key, agree, agreeSz, priv, privSz, otherPub, pubSz);
    }

    /**
     * Creates the agreement agree of size agreeSz using Dh key private priv of
     * size privSz and peer's public key otherPub of size pubSz.
     *
     * @param key the Dh object.
     * @param agree the agree buffer.
     * @param agreeSz the agree length.
     * @param priv the private part buffer.
     * @param privSz the private part length.
     * @param otherPub the peer's public part buffer.
     * @param pubSz the the public part length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhAgree(Dh key, byte[] agree, long[] agreeSz, byte[] priv,
        long privSz, byte[] otherPub, long pubSz) {

        runAllCast_fips();

        return wc_DhAgree(key, agree, agreeSz, priv, privSz, otherPub, pubSz);
    }

    /**
     * Decodes the DER group parameters from buffer input starting at index
     * inOutIdx of size inSz into Dh key.
     *
     * @param input the parameters buffer.
     * @param inOutIdx the parameters' starting index.
     * @param key the Dh object.
     * @param inSz the parameters buffer length. (not from inOutIdx)
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhKeyDecode(ByteBuffer input, long[] inOutIdx, Dh key,
        long inSz) {

        runAllCast_fips();

        return wc_DhKeyDecode(input, inOutIdx, key, inSz);
    }

    /**
     * Decodes the DER group parameters from buffer input starting at index
     * inOutIdx of size inSz into Dh key.
     *
     * @param input the parameters buffer.
     * @param inOutIdx the parameters' starting index.
     * @param key the Dh object.
     * @param inSz the parameters buffer length. (not from inOutIdx)
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhKeyDecode(byte[] input, long[] inOutIdx, Dh key,
        long inSz) {

        runAllCast_fips();

        return wc_DhKeyDecode(input, inOutIdx, key, inSz);
    }

    /**
     * Sets the group parameters for the Dh key from the unsigned binary inputs
     * p of size pSz and g of size gSz.
     *
     * @param key the Dh object.
     * @param p the prime buffer.
     * @param pSz the prime length.
     * @param g the primitive root molulo p buffer.
     * @param gSz the primitive root modulo p length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhSetKey(Dh key, ByteBuffer p, long pSz, ByteBuffer g,
        long gSz) {

        runAllCast_fips();

        return wc_DhSetKey(key, p, pSz, g, gSz);
    }

    /**
     * Sets the group parameters for the Dh key from the unsigned binary inputs
     * p of size pSz and g of size gSz.
     *
     * @param key the Dh object.
     * @param p the prime buffer.
     * @param pSz the prime length.
     * @param g the primitive root molulo p buffer.
     * @param gSz the primitive root modulo p length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhSetKey(Dh key, byte[] p, long pSz, byte[] g, long gSz) {

        runAllCast_fips();

        return wc_DhSetKey(key, p, pSz, g, gSz);
    }

    /**
     * Loads the DH group parameters.
     *
     * @param input the parameters buffer.
     * @param inSz the parameters size.
     * @param p the prime buffer.
     * @param pInOutSz the prime length.
     * @param g the primitive root molulo p buffer.
     * @param gInOutSz the primitive root modulo p length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhParamsLoad(ByteBuffer input, long inSz,
        ByteBuffer p, long[] pInOutSz, ByteBuffer g, long[] gInOutSz) {

        runAllCast_fips();

        return wc_DhParamsLoad(input, inSz, p, pInOutSz, g, gInOutSz);
    }

    /**
     * Loads the DH group parameters.
     *
     * @param input the parameters buffer.
     * @param inSz the parameters size.
     * @param p the prime buffer.
     * @param pInOutSz the prime length.
     * @param g the primitive root molulo p buffer.
     * @param gInOutSz the primitive root modulo p length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int DhParamsLoad(byte[] input, long inSz, byte[] p,
        long[] pInOutSz, byte[] g, long[] gInOutSz) {

        runAllCast_fips();

        return wc_DhParamsLoad(input, inSz, p, pInOutSz, g, gInOutSz);
    }

    /**
     * Initializes Ecc object for use. ecc_free must be called for resources
     * deallocation.
     *
     * @param key the Ecc object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_init(Ecc key) {

        runAllCast_fips();

        return wc_ecc_init(key);
    }

    /**
     * Releases Ecc object's resources.
     *
     * @param key the Ecc object.
     */
    public static void ecc_free(Ecc key) {

        runAllCast_fips();

        wc_ecc_free(key);
    }

    /**
     * Generates a new ECC key of size keysize using rng.
     *
     * @param rng the random source.
     * @param keysize the key length.
     * @param key the Ecc object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_make_key(Rng rng, int keysize, Ecc key) {

        runAllCast_fips();

        return wc_ecc_make_key(rng, keysize, key);
    }

    /**
     * Creates the shared secret out of size outlen using ecc private_key and
     * the peer's ecc public_key.
     *
     * @param private_key the Ecc object for the private key.
     * @param public_key the Ecc object for the peer's public key.
     * @param out the output buffer.
     * @param outlen the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_shared_secret(Ecc private_key, Ecc public_key,
        ByteBuffer out, long[] outlen) {

        runAllCast_fips();

        return wc_ecc_shared_secret(private_key, public_key, out, outlen);
    }

    /**
     * Creates the shared secret out of size outlen using ecc private_key and
     * the peer's ecc public_key.
     *
     * @param private_key the Ecc object for the private key.
     * @param public_key the Ecc object for the peer's public key.
     * @param out the output buffer.
     * @param outlen the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_shared_secret(Ecc private_key, Ecc public_key,
        byte[] out, long[] outlen) {

        runAllCast_fips();

        return wc_ecc_shared_secret(private_key, public_key, out, outlen);
    }

    /**
     * Imports the public ecc key from in of length inLen in x963 format.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param key the Ecc object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_import_x963(ByteBuffer in, long inLen, Ecc key) {

        runAllCast_fips();

        return wc_ecc_import_x963(in, inLen, key);
    }

    /**
     * Imports the public ecc key from in of length inLen in x963 format.
     *
     * @param in the input buffer.
     * @param inLen the input length.
     * @param key the Ecc object.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_import_x963(byte[] in, long inLen, Ecc key) {

        runAllCast_fips();

        return wc_ecc_import_x963(in, inLen, key);
    }

    /**
     * Exports the public ecc key into out of length outLen in x963 format.
     *
     * @param key the Ecc object.
     * @param out the output buffer.
     * @param outLen the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_export_x963(Ecc key, ByteBuffer out, long[] outLen) {

        runAllCast_fips();

        return wc_ecc_export_x963(key, out, outLen);
    }

    /**
     * Exports the public ecc key into out of length outLen in x963 format.
     *
     * @param key the Ecc object.
     * @param out the output buffer.
     * @param outLen the output length.
     *
     * @return 0 on success, {@literal <} 0 on error.
     */
    public static int ecc_export_x963(Ecc key, byte[] out, long[] outLen) {

        runAllCast_fips();

        return wc_ecc_export_x963(key, out, outLen);
    }
}
