/* Hmac.java
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
 * Wrapper for the native WolfCrypt Hmac implementation.
 *
 * @author Moisés Guimarães
 * @version 2.0, March 2017
 */
public class Hmac extends NativeStruct {

	public static final int MD5 = 3;
	public static final int SHA = 4;
	public static final int SHA224 = 5;
	public static final int SHA256 = 6;
	public static final int SHA384 = 7;
	public static final int SHA512 = 8;
	public static final int BLAKE2b = 14;

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;
	private int type = -1;
	private byte[] key;

	public Hmac() {
	}

	public Hmac(int type, byte[] key) {
		setKey(type, key);
	}

	private native void wc_HmacSetKey(int type, byte[] key);

	private native void wc_HmacUpdate(byte data);

	private native void wc_HmacUpdate(byte[] data, int offset, int length);

	private native void wc_HmacUpdate(ByteBuffer data, int offset, int length);

	private native byte[] wc_HmacFinal();

	private native int wc_HmacSizeByType(int type);

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	public void setKey(int type, byte[] key) {
		wc_HmacSetKey(type, key);

		this.type = type;
		this.key = key;

		state = WolfCryptState.READY;
	}

	public void reset() {
		if (state == WolfCryptState.READY) {
			setKey(type, key);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void update(byte data) {
		if (state == WolfCryptState.READY) {
			wc_HmacUpdate(data);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void update(byte[] data) {
		if (state == WolfCryptState.READY) {
			wc_HmacUpdate(data, 0, data.length);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void update(byte[] data, int offset, int length) {
		if (state == WolfCryptState.READY) {
			wc_HmacUpdate(data, offset, length);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public void update(ByteBuffer data) {
		if (state == WolfCryptState.READY) {
			int offset = data.position();
			int length = data.remaining();

			wc_HmacUpdate(data, offset, length);

			data.position(offset + length);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] doFinal() {
		if (state == WolfCryptState.READY) {
			return wc_HmacFinal();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public byte[] doFinal(byte[] data) {
		if (state == WolfCryptState.READY) {
			update(data);
			return wc_HmacFinal();
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public String getAlgorithm() {
		if (state == WolfCryptState.READY) {
			switch (type) {
				case MD5:
					return "HmacMD5";
				case SHA224:
					return "HmacSHA224";
				case SHA256:
					return "HmacSHA256";
				case SHA384:
					return "HmacSHA384";
				case SHA512:
					return "HmacSHA512";
				case BLAKE2b:
					return "HmacBLAKE2b";
			}
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}

		return "";
	}

	public int getMacLength() {
		if (state == WolfCryptState.READY) {
			return wc_HmacSizeByType(type);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}
}
