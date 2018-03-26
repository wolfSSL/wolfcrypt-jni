/* Chacha.java
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
 * Wrapper for the native WolfCrypt Chacha implementation.
 *
 * @author Daniele Lacamera
 * @version 1.0, March 2018
 */
public class Chacha extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	public Chacha() {
		init();
	}

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	private native void wc_Chacha_init();

	private native void wc_Chacha_free();

	private native byte[] wc_Chacha_process(byte in[]);

	private native void wc_Chacha_setKey(byte[] Key);

	private native void wc_Chacha_setIV(byte[] IV);




	protected void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			wc_Chacha_init();
			state = WolfCryptState.INITIALIZED;
		} else {
			throw new IllegalStateException(
					"Native resources already initialized.");
		}
	}

	protected void free() {
		if (state != WolfCryptState.UNINITIALIZED) {
			wc_Chacha_free();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void setKey(byte[] Key) {
		if (state == WolfCryptState.INITIALIZED) {
			wc_Chacha_setKey(Key);
			state = WolfCryptState.READY;
		} else {
			throw new IllegalStateException("Object already has a key.");
		}
	}
	
    public void setIV(byte[] IV) {
        wc_Chacha_setIV(IV);
	}

    public byte[] process(byte[] in) {
		if (state == WolfCryptState.READY) {
			return wc_Chacha_process(in);
		} else {
			throw new IllegalStateException(
					"No available key to perform the operation.");
		}
	}
}

