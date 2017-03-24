/* Rsa.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
 * Wrapper for the native WolfCrypt Rsa implementation.
 *
 * @author Moisés Guimarães
 * @version 2.0, March 2017
 */
public class Rsa extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;
	private boolean hasPrivateKey = false;
	private Rng rng;

	protected native long mallocNativeStruct() throws OutOfMemoryError;

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

	public Rsa() {
		/* Lazy init for Fips compatibility */
	}

	public Rsa(byte[] key) {
		decodePrivateKey(key);
	}

	public Rsa(byte[] n, byte[] e) {
		decodeRawPublicKey(n, e);
	}

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

	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_InitRsaKey();
			state = WolfCryptState.INITIALIZED;
		}
	}

	protected void willSetKey() {
		init();

		if (state != WolfCryptState.INITIALIZED)
			throw new IllegalStateException("Object already has a key.");
	}

	protected void willUseKey(boolean priv) {
		if (priv && !hasPrivateKey)
			throw new IllegalStateException(
					"No available key to perform the opperation.");

		if (state != WolfCryptState.READY)
			throw new IllegalStateException(
					"No available key to perform the opperation.");
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_FreeRsaKey();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void makeKey(int size, long e, Rng rng) {
		willSetKey();

		MakeRsaKey(size, e, rng);

		state = WolfCryptState.READY;
		hasPrivateKey = true;
	}

    public void decodePublicKey(byte[] key) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_RsaPublicKeyDecode(key);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

	public void decodePrivateKey(byte[] key) {
		willSetKey();

		wc_RsaPrivateKeyDecode(key);
		state = WolfCryptState.READY;
		hasPrivateKey = true;
	}

    public void decodePrivateKeyPKCS8(byte[] key) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_RsaPrivateKeyDecodePKCS8(key);
            state = WolfCryptState.READY;
            hasPrivateKey = true;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

	public void decodeRawPublicKey(byte[] n, byte[] e) {
		decodeRawPublicKey(n, n.length, e, e.length);
	}

	public void decodeRawPublicKey(byte[] n, long nSize, byte[] e, long eSize) {
		willSetKey();

		wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize);
		state = WolfCryptState.READY;
	}

	public void decodeRawPublicKey(ByteBuffer n, ByteBuffer e) {
		decodeRawPublicKey(n, n.limit(), e, e.limit());
	}

	public void decodeRawPublicKey(ByteBuffer n, long nSz, ByteBuffer e,
			long eSz) {
		willSetKey();

		wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz);
		state = WolfCryptState.READY;
	}

	public void exportRawPublicKey(byte[] n, long[] nSz, byte[] e, long[] eSz) {
		willUseKey(false);

		RsaFlattenPublicKey(n, nSz, e, eSz);
	}

	public void exportRawPublicKey(ByteBuffer n, ByteBuffer e) {
		willUseKey(false);

		RsaFlattenPublicKey(n, e);
	}

    public int getEncryptSize() {
        if (state == WolfCryptState.READY) {
            return wc_RsaEncryptSize();
        } else {
            throw new IllegalStateException(
                "No available key to perform the opperation.");
        }
    }

	public byte[] encrypt(byte[] plain, Rng rng) {
		willUseKey(false);

		return wc_RsaPublicEncrypt(plain, rng);
	}

	public byte[] decrypt(byte[] ciphertext) {
		willUseKey(true);

		return wc_RsaPrivateDecrypt(ciphertext);
	}

	public byte[] sign(byte[] data, Rng rng) {
		willUseKey(true);

		return wc_RsaSSL_Sign(data, rng);
	}

	public byte[] verify(byte[] signature) {
		willUseKey(false);

		return wc_RsaSSL_Verify(signature);
	}
}
