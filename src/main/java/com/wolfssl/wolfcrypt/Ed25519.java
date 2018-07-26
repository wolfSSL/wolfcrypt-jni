/* Ed25519.java
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

/**
 * Wrapper for the native WolfCrypt ed25519 implementation.
 *
 * @author Daniele Lacamera
 * @version 1.0, March 2018
 */
public class Ed25519 extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	public Ed25519() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_ed25519_init();

	private native void wc_ed25519_free();

	private native void wc_ed25519_make_key(Rng rng, int size);

	private native void wc_ed25519_check_key();

	private native void wc_ed25519_import_private(byte[] privKey, byte[] key);
	private native void wc_ed25519_import_private_only(byte[] privKey);
	private native void wc_ed25519_import_public(byte[] privKey);

    private native byte[] wc_ed25519_sign_msg(byte[] msg);
	private native boolean wc_ed25519_verify_msg(byte[] sig, byte[] msg);

	private native byte[] wc_ed25519_export_private();
	private native byte[] wc_ed25519_export_private_only();
	private native byte[] wc_ed25519_export_public();

	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_ed25519_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_ed25519_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void makeKey(Rng rng, int size) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ed25519_make_key(rng, size);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public void checkKey() {
		if (state == WolfCryptState.READY) {
			wc_ed25519_check_key();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

	public void importPrivate(byte[] privKey, byte[] Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ed25519_import_private(privKey, Key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    public void importPrivateOnly(byte[] privKey) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ed25519_import_private_only(privKey);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    public void importPublic(byte[] Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_ed25519_import_public(Key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

	public byte[] exportPrivate() {
		if (state == WolfCryptState.READY) {
			return wc_ed25519_export_private();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

    public byte[] exportPrivateOnly() {
		if (state == WolfCryptState.READY) {
			return wc_ed25519_export_private_only();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

    public byte[] exportPublic() {
		if (state == WolfCryptState.READY) {
			return wc_ed25519_export_public();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

	public byte[] sign_msg(byte[] msg_in) {

		byte[] msg_out = null;
		if (state == WolfCryptState.READY) {
			msg_out = wc_ed25519_sign_msg(msg_in);
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}

		return msg_out;
	}

	public boolean verify_msg(byte[] msg, byte[] signature) {
		boolean result = false;

		if (state == WolfCryptState.READY) {
			result = wc_ed25519_verify_msg(signature, msg);
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}

		return result;
	}
}

