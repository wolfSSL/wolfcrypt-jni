/* Curve25519.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.EllipticCurve;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECFieldFp;

/**
 * Wrapper for the native WolfCrypt curve25519 implementation.
 *
 * @author Daniele Lacamera
 * @version 1.0, March 2018
 */
public class Curve25519 extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	public Curve25519() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_curve25519_init();

	private native void wc_curve25519_free();

	private native void wc_curve25519_make_key(Rng rng, int size);

	private native void wc_curve25519_make_key_ex(Rng rng, int size, int endian);

	private native void wc_curve25519_check_key();

	private native byte[] wc_curve25519_shared_secret(Curve25519 pubKey);

	private native void wc_curve25519_import_private(byte[] privKey, byte[] x963Key);

	private native byte[] wc_curve25519_export_private();

	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_curve25519_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_curve25519_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void makeKey(Rng rng, int size) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_make_key(rng, size);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    public void makeKeyWithEndian(Rng rng, int size, int endian) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_curve25519_make_key_ex(rng, size, endian);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

	public void checkKey() {
		if (state == WolfCryptState.READY) {
			wc_curve25519_check_key();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void importPrivate(byte[] privKey, byte[] x963Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_import_private(privKey, x963Key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] exportPrivate() {
		if (state == WolfCryptState.READY) {
			return wc_curve25519_export_private();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] makeSharedSecret(Curve25519 pubKey) {
		if (state == WolfCryptState.READY) {
			return wc_curve25519_shared_secret(pubKey);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

}

