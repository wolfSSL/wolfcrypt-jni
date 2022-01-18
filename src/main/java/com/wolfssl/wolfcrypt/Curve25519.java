/* Curve25519.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.EllipticCurve;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECFieldFp;

/**
 * Wrapper for the native WolfCrypt curve25519 implementation.
 */
public class Curve25519 extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /**
     * Create new Curve25519 object
     */
	public Curve25519() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

    /**
     * Malloc native JNI Curve25519 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_curve25519_init();

	private native void wc_curve25519_free();

	private native void wc_curve25519_make_key(Rng rng, int size);

	private native void wc_curve25519_make_key_ex(Rng rng, int size, int endian);

	private native void wc_curve25519_check_key();

	private native byte[] wc_curve25519_make_shared_secret(Curve25519 pubKey);

	private native void wc_curve25519_import_private(byte[] privKey, byte[] key);
	private native void wc_curve25519_import_private_only(byte[] privKey);
	private native void wc_curve25519_import_public(byte[] pubKey);

	private native byte[] wc_curve25519_export_private();
	private native byte[] wc_curve25519_export_public();

    /**
     * Initialize Curve25519 object
     */
	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_curve25519_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

    /**
     * Free Curve25519 object
     */
	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_curve25519_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

    /**
     * Generate new Curve25519 key
     *
     * @param rng Initialized Rng object to use for randomness
     * @param size size of key to generate
     */
	public void makeKey(Rng rng, int size) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_make_key(rng, size);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    /**
     * Generate new Curve25519 key with specified endianness
     *
     * @param rng initialized Rng object to use for randomness
     * @param size size of key to generate
     * @param endian endianness of key
     */
    public void makeKeyWithEndian(Rng rng, int size, int endian) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_curve25519_make_key_ex(rng, size, endian);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

    /**
     * Check Curve25519 key for correctness
     *
     * @throws WolfCryptException if key is not correct
     * @throws IllegalStateException if no key available
     */
	public void checkKey() {
		if (state == WolfCryptState.READY) {
			wc_curve25519_check_key();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

    /**
     * Import private and public key
     *
     * @param privKey private Curve25519 key array
     * @param xKey public Curve25519 key array
     *
     * @throws WolfCryptException if error occurs during key import
     * @throws IllegalArgumentException if object is already initialized
     */
	public void importPrivate(byte[] privKey, byte[] xKey) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_import_private(privKey, xKey);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}
	
    /**
     * Import private key
     *
     * @param privKey private Curve25519 key array
     *
     * @throws WolfCryptException if error occurs during key import
     * @throws IllegalArgumentException if object is already initialized
     */
    public void importPrivateOnly(byte[] privKey) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_import_private_only(privKey);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}
	
    /**
     * Import public key
     *
     * @param pubKey public Curve25519 key array
     *
     * @throws WolfCryptException if error occurs during key import
     * @throws IllegalArgumentException if object is already initialized
     */
    public void importPublic(byte[] pubKey) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_curve25519_import_public(pubKey);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    /**
     * Export private key
     *
     * @return byte array of private Curve25519 key
     *
     * @throws WolfCryptException if error occurs during key export
     * @throws IllegalArgumentException if object has no key to export
     */
	public byte[] exportPrivate() {
		if (state == WolfCryptState.READY) {
			return wc_curve25519_export_private();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}
	
    /**
     * Export public key
     *
     * @return byte array of public Curve25519 key
     *
     * @throws WolfCryptException if error occurs during key export
     * @throws IllegalArgumentException if object has no key to export
     */
    public byte[] exportPublic() {
		if (state == WolfCryptState.READY) {
			return wc_curve25519_export_public();
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

    /**
     * Generate shared secret between this object and specified public key
     *
     * @param pubKey public key to use for secret generation
     *
     * @return shared secret as byte array
     *
     * @throws WolfCryptException if error occurs during secret generation
     * @throws IllegalArgumentException if object has no key
     */
	public byte[] makeSharedSecret(Curve25519 pubKey) {
		if (state == WolfCryptState.READY) {
			return wc_curve25519_make_shared_secret(pubKey);
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}

}

