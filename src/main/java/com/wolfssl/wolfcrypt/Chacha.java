/* Chacha.java
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

/**
 * Wrapper for the native WolfCrypt Chacha implementation.
 */
public class Chacha extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /**
     * Create new Chacha object
     */
	public Chacha() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

    /**
     * Malloc native JNI ChaCha structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_Chacha_init();

	private native void wc_Chacha_free();

	private native byte[] wc_Chacha_process(byte in[]);

	private native void wc_Chacha_setKey(byte[] Key);

	private native void wc_Chacha_setIV(byte[] IV);

    /**
     * Initialize Chacha object
     */
	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_Chacha_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

    /**
     * Free Chacha object
     */
	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_Chacha_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

    /**
     * Set ChaCha key
     *
     * @param Key ChaCha key array
     */
	public void setKey(byte[] Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_Chacha_setKey(Key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}

    /**
     * Set ChaCha initialization vector
     *
     * @param IV ChaCha IV array
     */
    public void setIV(byte[] IV) {
        wc_Chacha_setIV(IV);
	}

    /**
     * Process data with ChaCha
     *
     * @param in input data to process
     *
     * @return resulting byte array
     */
    public byte[] process(byte[] in) {
		if (state == WolfCryptState.READY) {
			return wc_Chacha_process(in);
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}
}

