/* Fips.java
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

import com.wolfssl.wolfcrypt.Aes;

/**
 * Main wrapper for the native WolfCrypt implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class Fips extends WolfObject {

	private Fips() {
	}

	public interface ErrorCallback {
		public void errorCallback(int ok, int err, String hash);
	}

	/**
	 * Sets an callback class for handling fips errors.
	 * 
	 * @param callback
	 *            the callback class.
	 */
	public static native void wolfCrypt_SetCb_fips(ErrorCallback callback);

	/**
	 * The current inCore hash of the wolfCrypt fips code.
	 * 
	 * @return current inCore hash.
	 */
	public static native String wolfCrypt_GetCoreHash_fips();

	/*
	 * ### FIPS Aprooved Security Methods ######################################
	 */

	/*
	 * wolfCrypt FIPS API - Symmetric encrypt/decrypt Service
	 */

	/* AES */

	/**
	 * Initializes Aes object for CBC mode with key and iv.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param userKey
	 *            the key to be set.
	 * @param keylen
	 *            the key length.
	 * @param iv
	 *            the initialization vector (optional).
	 * @param dir
	 *            the direction (encryption|decryption).
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesSetKey_fips(Aes aes, ByteBuffer userKey,
			long keylen, ByteBuffer iv, int dir);

	/**
	 * Initializes Aes object for CBC mode with key and iv.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param userKey
	 *            the key to be set.
	 * @param keylen
	 *            the key length.
	 * @param iv
	 *            the initialization vector (optional).
	 * @param dir
	 *            the direction (encryption|decryption).
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesSetKey_fips(Aes aes, byte[] userKey,
			long keylen, byte[] iv, int dir);

	/**
	 * Initializes Aes object with iv.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param iv
	 *            the initialization vector.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesSetIV_fips(Aes aes, ByteBuffer iv);

	/**
	 * Initializes Aes object with iv.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param iv
	 *            the initialization vector.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesSetIV_fips(Aes aes, byte[] iv);

	/**
	 * Performs Aes Cbc Encryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesCbcEncrypt_fips(Aes aes, ByteBuffer out,
			ByteBuffer in, long sz);

	/**
	 * Performs Aes Cbc Encryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesCbcEncrypt_fips(Aes aes, byte[] out, byte[] in,
			long sz);

	/**
	 * Performs Aes Cbc Decryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesCbcDecrypt_fips(Aes aes, ByteBuffer out,
			ByteBuffer in, long sz);

	/**
	 * Performs Aes Cbc Decryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesCbcDecrypt_fips(Aes aes, byte[] out, byte[] in,
			long sz);

	/**
	 * Initializes Aes object for GCM mode with key.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param userKey
	 *            the key to be set.
	 * @param keylen
	 *            the key length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmSetKey_fips(Aes aes, ByteBuffer userKey,
			long keylen);

	/**
	 * Initializes Aes object for GCM mode with key.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param userKey
	 *            the key to be set.
	 * @param keylen
	 *            the key length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmSetKey_fips(Aes aes, byte[] userKey,
			long keylen);

	/**
	 * Performs aes GCM Encryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * @param iv
	 *            the initialization vector buffer.
	 * @param ivSz
	 *            the initialization vector length.
	 * @param authTag
	 *            the authTag buffer.
	 * @param authTagSz
	 *            the authTag length.
	 * @param authIn
	 *            the authIn buffer.
	 * @param authInSz
	 *            the authIn length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmEncrypt_fips(Aes aes, ByteBuffer out,
			ByteBuffer in, long sz, ByteBuffer iv, long ivSz,
			ByteBuffer authTag, long authTagSz, ByteBuffer authIn, long authInSz);

	/**
	 * Performs aes GCM Encryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * @param iv
	 *            the initialization vector buffer.
	 * @param ivSz
	 *            the initialization vector length.
	 * @param authTag
	 *            the authTag buffer.
	 * @param authTagSz
	 *            the authTag length.
	 * @param authIn
	 *            the authIn buffer.
	 * @param authInSz
	 *            the authIn length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmEncrypt_fips(Aes aes, byte[] out,
			byte[] in, long sz, byte[] iv, long ivSz,
			byte[] authTag, long authTagSz, byte[] authIn, long authInSz);

	/**
	 * Performs aes GCM Decryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * @param iv
	 *            the initialization vector buffer.
	 * @param ivSz
	 *            the initialization vector length.
	 * @param authTag
	 *            the authTag buffer.
	 * @param authTagSz
	 *            the authTag length.
	 * @param authIn
	 *            the authIn buffer.
	 * @param authInSz
	 *            the authIn length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmDecrypt_fips(Aes aes, ByteBuffer out,
			ByteBuffer in, long sz, ByteBuffer iv, long ivSz,
			ByteBuffer authTag, long authTagSz, ByteBuffer authIn, long authInSz);

	/**
	 * Performs aes GCM Decryption.
	 * 
	 * @param aes
	 *            the Aes object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * @param iv
	 *            the initialization vector buffer.
	 * @param ivSz
	 *            the initialization vector length.
	 * @param authTag
	 *            the authTag buffer.
	 * @param authTagSz
	 *            the authTag length.
	 * @param authIn
	 *            the authIn buffer.
	 * @param authInSz
	 *            the authIn length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int AesGcmDecrypt_fips(Aes aes, byte[] out,
			byte[] in, long sz, byte[] iv, long ivSz,
			byte[] authTag, long authTagSz, byte[] authIn, long authInSz);

	/* DES3 */

	/**
	 * Initializes Des3 object for CBC mode with key and iv.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param userKey
	 *            the key to be set.
	 * @param iv
	 *            the initialization vector (optional).
	 * @param dir
	 *            the direction (encryption|decryption).
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_SetKey_fips(Des3 des, ByteBuffer userKey,
			ByteBuffer iv, int dir);

	/**
	 * Initializes Des3 object for CBC mode with key and iv.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param userKey
	 *            the key to be set.
	 * @param iv
	 *            the initialization vector (optional).
	 * @param dir
	 *            the direction (encryption|decryption).
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_SetKey_fips(Des3 des, byte[] userKey,
			byte[] iv, int dir);

	/**
	 * Initializes Des3 object with iv.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param iv
	 *            the initialization vector.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_SetIV_fips(Des3 des, ByteBuffer iv);

	/**
	 * Initializes Des3 object with iv.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param iv
	 *            the initialization vector.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_SetIV_fips(Des3 des, byte[] iv);

	/**
	 * Performs Des3 CBC Encryption.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_CbcEncrypt_fips(Des3 des, ByteBuffer out,
			ByteBuffer in, long sz);

	/**
	 * Performs Des3 CBC Encryption.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_CbcEncrypt_fips(Des3 des, byte[] out,
			byte[] in, long sz);

	/**
	 * Performs des3 CBC Decryption.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_CbcDecrypt_fips(Des3 des, ByteBuffer out,
			ByteBuffer in, long sz);

	/**
	 * Performs des3 CBC Decryption.
	 * 
	 * @param des
	 *            the Des3 object.
	 * @param out
	 *            the output buffer.
	 * @param in
	 *            the input buffer.
	 * @param sz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Des3_CbcDecrypt_fips(Des3 des, byte[] out,
			byte[] in, long sz);

	/*
	 * wolfCrypt FIPS API - Keyed hash Service
	 */

	/* HMAC */

	/**
	 * Initializes Hmac object with type and key.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param type
	 *            the digest id.
	 * @param key
	 *            the key buffer.
	 * @param keySz
	 *            the key length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacSetKey_fips(Hmac hmac, int type,
			ByteBuffer key, long keySz);

	/**
	 * Initializes Hmac object with type and key.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param type
	 *            the digest id.
	 * @param key
	 *            the key buffer.
	 * @param keySz
	 *            the key length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacSetKey_fips(Hmac hmac, int type,
			byte[] key, long keySz);

	/**
	 * Updates Hmac object with data.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacUpdate_fips(Hmac hmac, ByteBuffer data,
			long len);

	/**
	 * Updates Hmac object with data.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacUpdate_fips(Hmac hmac, byte[] data,
			long len);

	/**
	 * Outputs Hmac digest to hash.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacFinal_fips(Hmac hmac, ByteBuffer hash);

	/**
	 * Outputs Hmac digest to hash.
	 * 
	 * @param hmac
	 *            the Hmac object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int HmacFinal_fips(Hmac hmac, byte[] hash);

	/*
	 * wolfCrypt FIPS API - Random number generation Service
	 */

	/* RNG */

	/**
	 * Initializes RNG object's resources and state. FreeRng_fips must be called
	 * for resources deallocation.
	 * 
	 * @param rng
	 *            the RNG object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitRng_fips(Rng rng);

	/**
	 * Releases RNG object's resources and zeros out state.
	 * 
	 * @param rng
	 *            the RNG object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error. Also part of Zeroize
	 *         Service.
	 */
	public static native int FreeRng_fips(Rng rng);

	/**
	 * Outputs block of random data from RNG object.
	 * 
	 * @param rng
	 *            the RNG object.
	 * @param buf
	 *            the output buffer.
	 * @param bufSz
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RNG_GenerateBlock_fips(Rng rng, ByteBuffer buf,
			long bufSz);

	/**
	 * Outputs block of random data from RNG object.
	 * 
	 * @param rng
	 *            the RNG object.
	 * @param buf
	 *            the output buffer.
	 * @param bufSz
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RNG_GenerateBlock_fips(Rng rng, byte[] buf,
			long bufSz);

	/**
	 * When reseed is 0, tests the output of a temporary instance of an RNG
	 * against the expected output of size in bytes outputSz using the seed
	 * buffer entropyA of size in bytes entropyASz, where entropyB and
	 * entropyBSz are ignored. When reseed is 1, the test also reseeds the
	 * temporary instance of the RNG with the seed buffer entropyB of size in
	 * bytes entropyBSz and then tests the RNG against the expected output of
	 * size in bytes outputSz.
	 * 
	 * @param reseed
	 *            the reseed flag.
	 * @param entropyA
	 *            the entropyA buffer.
	 * @param entropyASz
	 *            the entropyA length.
	 * @param entropyB
	 *            the entropyB buffer.
	 * @param entropyBSz
	 *            the entropyB length.
	 * @param output
	 *            the output buffer.
	 * @param outputSz
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RNG_HealthTest_fips(int reseed,
			ByteBuffer entropyA, long entropyASz, ByteBuffer entropyB,
			long entropyBSz, ByteBuffer output, long outputSz);

	/**
	 * When reseed is 0, tests the output of a temporary instance of an RNG
	 * against the expected output of size in bytes outputSz using the seed
	 * buffer entropyA of size in bytes entropyASz, where entropyB and
	 * entropyBSz are ignored. When reseed is 1, the test also reseeds the
	 * temporary instance of the RNG with the seed buffer entropyB of size in
	 * bytes entropyBSz and then tests the RNG against the expected output of
	 * size in bytes outputSz.
	 * 
	 * @param reseed
	 *            the reseed flag.
	 * @param entropyA
	 *            the entropyA buffer.
	 * @param entropyASz
	 *            the entropyA length.
	 * @param entropyB
	 *            the entropyB buffer.
	 * @param entropyBSz
	 *            the entropyB length.
	 * @param output
	 *            the output buffer.
	 * @param outputSz
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RNG_HealthTest_fips(int reseed,
			byte[] entropyA, long entropyASz, byte[] entropyB,
			long entropyBSz, byte[] output, long outputSz);

	/*
	 * wolfCrypt FIPS API - Digital signature and Key transport Services
	 */

	/* RSA */

	/**
	 * Initializes Rsa object for use with optional heap hint p. FreeRsaKey_fips
	 * must be called for resources deallocation.
	 * 
	 * @param key
	 *            the Rsa object.
	 * @param heap
	 *            the (optional) heap.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitRsaKey_fips(Rsa key, ByteBuffer heap);

	/**
	 * Releases Rsa object's resources.
	 * 
	 * @param key
	 *            the Rsa object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int FreeRsaKey_fips(Rsa key);

	/**
	 * Performs Rsa Signing Operation.
	 * 
	 * @param in
	 *            the input buffer.
	 * @param inLen
	 *            the input length.
	 * @param out
	 *            the output buffer.
	 * @param outLen
	 *            the output length.
	 * @param key
	 *            the Rsa object.
	 * @param rng
	 *            the random source for padding.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaSSL_Sign_fips(ByteBuffer in, long inLen,
			ByteBuffer out, long outLen, Rsa key, Rng rng);

	/**
	 * Performs Rsa Signature Verification.
	 * 
	 * @param in
	 *            the input buffer.
	 * @param inLen
	 *            the input length.
	 * @param out
	 *            the output buffer.
	 * @param outLen
	 *            the output length.
	 * @param key
	 *            the Rsa object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaSSL_Verify_fips(ByteBuffer in, long inLen,
			ByteBuffer out, long outLen, Rsa key);

	/**
	 * Retrieves Rsa Output Size.
	 * 
	 * @param key
	 *            the Rsa object.
	 * 
	 * @return key output size {@literal >} 0 on success, {@literal <} 0 on
	 *         error.
	 */
	public static native int RsaEncryptSize_fips(Rsa key);

	/**
	 * Decodes Rsa Private Key from buffer.
	 * 
	 * @param input
	 *            the input buffer.
	 * @param inOutIdx
	 *            the key's starting index in the input.
	 * @param key
	 *            the Rsa object.
	 * @param inSz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaPrivateKeyDecode_fips(ByteBuffer input,
			long[] inOutIdx, Rsa key, long inSz);

	/**
	 * Decodes Rsa Public Key from buffer.
	 * 
	 * @param input
	 *            the input buffer.
	 * @param inOutIdx
	 *            the key's starting index in the input.
	 * @param key
	 *            the Rsa object.
	 * @param inSz
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaPublicKeyDecode_fips(ByteBuffer input,
			long[] inOutIdx, Rsa key, long inSz);

	/*
	 * wolfCrypt FIPS API - Message digest Service
	 */

	/* SHA */

	/**
	 * Initializes Sha object for use.
	 * 
	 * @param sha
	 *            the Sha object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitSha_fips(Sha sha);

	/**
	 * Updates Sha object with data.
	 * 
	 * @param sha
	 *            the Sha object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ShaUpdate_fips(Sha sha, ByteBuffer data, long len);

	/**
	 * Updates Sha object with data.
	 * 
	 * @param sha
	 *            the Sha object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ShaUpdate_fips(Sha sha, byte[] data, long len);

	/**
	 * Outputs Sha digest to hash.
	 * 
	 * @param sha
	 *            the Sha object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ShaFinal_fips(Sha sha, ByteBuffer hash);

	/**
	 * Outputs Sha digest to hash.
	 * 
	 * @param sha
	 *            the Sha object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ShaFinal_fips(Sha sha, byte[] hash);

	/* SHA256 */

	/**
	 * Initializes Sha256 object for use.
	 * 
	 * @param sha
	 *            the Sha256 object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitSha256_fips(Sha256 sha);

	/**
	 * Updates Sha256 object with data.
	 * 
	 * @param sha
	 *            the Sha256 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha256Update_fips(Sha256 sha, ByteBuffer data,
			long len);

	/**
	 * Updates Sha256 object with data.
	 * 
	 * @param sha
	 *            the Sha256 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha256Update_fips(Sha256 sha, byte[] data,
			long len);

	/**
	 * Outputs Sha256 digest to hash.
	 * 
	 * @param sha
	 *            the Sha256 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha256Final_fips(Sha256 sha, ByteBuffer hash);

	/**
	 * Outputs Sha256 digest to hash.
	 * 
	 * @param sha
	 *            the Sha256 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha256Final_fips(Sha256 sha, byte[] hash);

	/* SHA384 */

	/**
	 * Initializes Sha384 object for use.
	 * 
	 * @param sha
	 *            the Sha384 object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitSha384_fips(Sha384 sha);

	/**
	 * Updates Sha384 object with data.
	 * 
	 * @param sha
	 *            the Sha384 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha384Update_fips(Sha384 sha, ByteBuffer data,
			long len);

	/**
	 * Updates Sha384 object with data.
	 * 
	 * @param sha
	 *            the Sha384 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha384Update_fips(Sha384 sha, byte[] data,
			long len);

	/**
	 * Outputs Sha384 digest to hash.
	 * 
	 * @param sha
	 *            the Sha384 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha384Final_fips(Sha384 sha, ByteBuffer hash);

	/**
	 * Outputs Sha384 digest to hash.
	 * 
	 * @param sha
	 *            the Sha384 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha384Final_fips(Sha384 sha, byte[] hash);

	/* SHA512 */

	/**
	 * Initializes Sha512 object for use.
	 * 
	 * @param sha
	 *            the Sha512 object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitSha512_fips(Sha512 sha);

	/**
	 * Updates Sha512 object with data.
	 * 
	 * @param sha
	 *            the Sha512 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha512Update_fips(Sha512 sha, ByteBuffer data,
			long len);

	/**
	 * Updates Sha512 object with data.
	 * 
	 * @param sha
	 *            the Sha512 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha512Update_fips(Sha512 sha, byte[] data,
			long len);

	/**
	 * Outputs Sha512 digest to hash.
	 * 
	 * @param sha
	 *            the Sha512 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha512Final_fips(Sha512 sha, ByteBuffer hash);
	
	/**
	 * Outputs Sha512 digest to hash.
	 * 
	 * @param sha
	 *            the Sha512 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Sha512Final_fips(Sha512 sha, byte[] hash);

	/*
	 * wolfCrypt FIPS API - Show status Service
	 */

	/**
	 * @return The current status of the module. A return code of 0 means the
	 *         module is in a state without errors. Any other return code is the
	 *         specific error state of the module.
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

	/*
	 * ### FIPS Allowed Security Methods #######################################
	 */

	/*
	 * wolfCrypt FIPS API - Key transport Service
	 */

	/**
	 * Performs Rsa Public Encryption.
	 * 
	 * @param in
	 *            the input buffer.
	 * @param inLen
	 *            the input length.
	 * @param out
	 *            the output buffer.
	 * @param outLen
	 *            the output length.
	 * @param key
	 *            the Rsa object.
	 * @param rng
	 *            the random source for padding.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaPublicEncrypt_fips(ByteBuffer in, long inLen,
			ByteBuffer out, long outLen, Rsa key, Rng rng);

	/**
	 * Performs Rsa Private Decryption.
	 * 
	 * @param in
	 *            the input buffer.
	 * @param inLen
	 *            the input length.
	 * @param out
	 *            the output buffer.
	 * @param outLen
	 *            the output length.
	 * @param key
	 *            the Rsa object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int RsaPrivateDecrypt_fips(ByteBuffer in, long inLen,
			ByteBuffer out, long outLen, Rsa key);

	/*
	 * wolfCrypt FIPS API - Message digest MD5 Service
	 */

	/**
	 * Initializes Md5 object for use.
	 * 
	 * @param md5
	 *            the Md5 object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int InitMd5(Md5 md5);

	/**
	 * Updates Md5 object with data.
	 * 
	 * @param md5
	 *            the Md5 object.
	 * @param data
	 *            the input buffer.
	 * @param len
	 *            the input length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Md5Update(Md5 md5, ByteBuffer data, long len);

	/**
	 * Outputs Md5 digest to hash.
	 * 
	 * @param md5
	 *            the Md5 object.
	 * @param hash
	 *            the output buffer.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int Md5Final(Md5 md5, ByteBuffer hash);

	/*
	 * wolfCrypt FIPS API - Key agreement Service
	 */

	/**
	 * Initializes Dh object for use. FreeDhKey must be called for resources
	 * deallocation.
	 * 
	 * @param key
	 *            the Dh object.
	 */
	public static native void InitDhKey(Dh key);

	/**
	 * Releases Dh object's resources.
	 * 
	 * @param key
	 *            the Dh object.
	 */
	public static native void FreeDhKey(Dh key);

	/**
	 * Generates the public part pub of size pubSz, private part priv of size
	 * privSz using rng for Dh key.
	 * 
	 * @param key
	 *            the Dh object.
	 * @param rng
	 *            the random source.
	 * @param priv
	 *            the private part buffer.
	 * @param privSz
	 *            the private part length.
	 * @param pub
	 *            the public part buffer.
	 * @param pubSz
	 *            the the public part length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int DhGenerateKeyPair(Dh key, Rng rng,
			ByteBuffer priv, long[] privSz, ByteBuffer pub, long[] pubSz);

	/**
	 * Creates the agreement agree of size agreeSz using Dh key private priv of
	 * size privSz and peer’s public key otherPub of size pubSz.
	 * 
	 * @param key
	 *            the Dh object.
	 * @param agree
	 *            the agree buffer.
	 * @param agreeSz
	 *            the agree length.
	 * @param priv
	 *            the private part buffer.
	 * @param privSz
	 *            the private part length.
	 * @param otherPub
	 *            the peer's public part buffer.
	 * @param pubSz
	 *            the the public part length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int DhAgree(Dh key, ByteBuffer agree, long[] agreeSz,
			ByteBuffer priv, long privSz, ByteBuffer otherPub, long pubSz);

	/**
	 * Decodes the DER group parameters from buffer input starting at index
	 * inOutIdx of size inSz into Dh key.
	 * 
	 * @param input
	 *            the parameters buffer.
	 * @param inOutIdx
	 *            the parameters' starting index.
	 * @param key
	 *            the Dh object.
	 * @param inSz
	 *            the parameters buffer length. (not from inOutIdx)
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int DhKeyDecode(ByteBuffer input, long[] inOutIdx,
			Dh key, long inSz);

	/**
	 * Sets the group parameters for the Dh key from the unsigned binary inputs
	 * p of size pSz and g of size gSz.
	 * 
	 * @param key
	 *            the Dh object.
	 * @param p
	 *            the prime buffer.
	 * @param pSz
	 *            the prime length.
	 * @param g
	 *            the primitive root molulo p buffer.
	 * @param gSz
	 *            the primitive root modulo p length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int DhSetKey(Dh key, ByteBuffer p, long pSz,
			ByteBuffer g, long gSz);

	/**
	 * Loads the Dh group parameters.
	 * 
	 * @param input
	 *            the parameters buffer.
	 * @param inSz
	 *            the parameters size.
	 * @param p
	 *            the prime buffer.
	 * @param pInOutSz
	 *            the prime length.
	 * @param g
	 *            the primitive root molulo p buffer.
	 * @param gInOutSz
	 *            the primitive root modulo p length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int DhParamsLoad(ByteBuffer input, long inSz,
			ByteBuffer p, long[] pInOutSz, ByteBuffer g, long[] gInOutSz);

	/**
	 * Initializes Ecc object for use. ecc_free must be called for resources
	 * deallocation.
	 * 
	 * @param key
	 *            the Ecc object.
	 *
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ecc_init(Ecc key);

	/**
	 * Releases Ecc object's resources.
	 * 
	 * @param key
	 *            the Ecc object.
	 */
	public static native void ecc_free(Ecc key);

	/**
	 * Generates a new ecc key of size keysize using rng.
	 * 
	 * @param rng
	 *            the random source.
	 * @param keysize
	 *            the key length.
	 * @param key
	 *            the Ecc object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ecc_make_key(Rng rng, int keysize, Ecc key);

	/**
	 * Creates the shared secret out of size outlen using ecc private_key and
	 * the peer’s ecc public_key.
	 * 
	 * @param private_key
	 *            the Ecc object for the private key.
	 * @param public_key
	 *            the Ecc object for the peer's public key.
	 * @param out
	 *            the output buffer.
	 * @param outlen
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ecc_shared_secret(Ecc private_key, Ecc public_key,
			ByteBuffer out, long[] outlen);

	/**
	 * Imports the public ecc key from in of length inLen in x963 format.
	 * 
	 * @param in
	 *            the input buffer.
	 * @param inLen
	 *            the input length.
	 * @param key
	 *            the Ecc object.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ecc_import_x963(ByteBuffer in, long inLen, 
			Ecc key);

	/**
	 * Exports the public ecc key into out of length outLen in x963 format.
	 * 
	 * @param key
	 *            the Ecc object.
	 * @param out
	 *            the output buffer.
	 * @param outLen
	 *            the output length.
	 * 
	 * @return 0 on success, {@literal <} 0 on error.
	 */
	public static native int ecc_export_x963(Ecc key, ByteBuffer out,
			long[] outLen);
}
