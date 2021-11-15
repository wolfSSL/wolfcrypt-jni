/* Sha256.java
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
 * Wrapper for the native WolfCrypt SHA2-256 implementation.
 */
public class Sha256 extends MessageDigest {

	public static final int TYPE = 2; /* hash type unique */
	public static final int DIGEST_SIZE = 32;

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	protected native void native_init();

	protected native void native_update(ByteBuffer data, int offset, int len);

	protected native void native_update(byte[] data, int offset, int len);

	protected native void native_final(ByteBuffer hash, int offset);

	protected native void native_final(byte[] hash);

	public Sha256() {
		init();
	}

	public Sha256(byte[] data) {
		init();
		update(data);
	}

	public int digestSize() {
		return DIGEST_SIZE;
	}
}

