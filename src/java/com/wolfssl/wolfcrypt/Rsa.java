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

	private native void wc_RsaPrivateKeyDecode(byte[] key);

	private native byte[] wc_RsaPublicEncrypt(byte[] data, Rng rng);

	private native byte[] wc_RsaPrivateDecrypt(byte[] data);

	private native byte[] wc_RsaSSL_Sign(byte[] data, Rng rng);

	private native byte[] wc_RsaSSL_Verify(byte[] data);

	public Rsa() {
		init();
	}

	public Rsa(byte[] key) {
		init();
		decodePrivateKey(key);
	}

	public Rsa(byte[] n, byte[] e) {
		init();
		decodeRawPublicKey(n, e);
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
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_FreeRsaKey();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void makeKey(int size, long e, Rng rng) {
		if (state == WolfCryptState.INITIALIZED) {
			MakeRsaKey(size, e, rng);
			state = WolfCryptState.READY;
			hasPrivateKey = true;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public void decodePrivateKey(byte[] key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_RsaPrivateKeyDecode(key);
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
		if (state == WolfCryptState.INITIALIZED) {
			wc_RsaPublicKeyDecodeRaw(n, nSize, e, eSize);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public void decodeRawPublicKey(ByteBuffer n, ByteBuffer e) {
		decodeRawPublicKey(n, n.limit(), e, e.limit());
	}

	public void decodeRawPublicKey(ByteBuffer n, long nSz, ByteBuffer e,
			long eSz) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public void exportRawPublicKey(byte[] n, long[] nSz, byte[] e, long[] eSz) {
		if (state == WolfCryptState.READY) {
			RsaFlattenPublicKey(n, nSz, e, eSz);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void exportRawPublicKey(ByteBuffer n, ByteBuffer e) {
		if (state == WolfCryptState.READY) {
			RsaFlattenPublicKey(n, e);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] encrypt(byte[] plain, Rng rng) {
		if (state == WolfCryptState.READY) {
			return wc_RsaPublicEncrypt(plain, rng);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] decrypt(byte[] ciphertext) {
		if (hasPrivateKey) {
			return wc_RsaPrivateDecrypt(ciphertext);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] sign(byte[] data, Rng rng) {
		if (hasPrivateKey) {
			return wc_RsaSSL_Sign(data, rng);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] verify(byte[] signature) {
		if (state == WolfCryptState.READY) {
			return wc_RsaSSL_Verify(signature);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}
}
