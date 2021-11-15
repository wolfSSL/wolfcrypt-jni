/* Des3.java
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

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt Des3 implementation.
 */
public class Des3 extends BlockCipher {

	public static final int KEY_SIZE = 24;
	public static final int BLOCK_SIZE = 8;
	public static final int ENCRYPT_MODE = 0;
	public static final int DECRYPT_MODE = 1;

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	private int opmode;

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	protected native void native_set_key(byte[] key, byte[] iv, int opmode);

	protected native int native_update(int opmode, byte[] input, int offset,
			int length, byte[] output, int outputOffset);

	protected native int native_update(int opmode, ByteBuffer input,
			int offset, int length, ByteBuffer output, int outputOffset);

	public Des3() {
	}

	public Des3(byte[] key, byte[] iv, int opmode) {
		setKey(key, iv, opmode);
	}
}
