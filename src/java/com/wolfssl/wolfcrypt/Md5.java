/* Md5.java
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
 * Wrapper for the native WolfCrypt Md5 implementation.
 *
 * @author Moisés Guimarães
 * @version 2.0, March 2017
 */
public class Md5 extends MessageDigest {

	public static final int TYPE = 0; /* hash type unique */
	public static final int DIGEST_SIZE = 16;

	protected native long mallocNativeStruct() throws OutOfMemoryError;

	protected native void native_init();

	protected native void native_update(ByteBuffer data, int offset, int len);

	protected native void native_update(byte[] data, int offset, int len);

	protected native void native_final(ByteBuffer hash, int offset);

	protected native void native_final(byte[] hash);

	public Md5() {
		init();
	}

	public Md5(byte[] data) {
		init();
		update(data);
	}

	public int digestSize() {
		return DIGEST_SIZE;
	}
}
