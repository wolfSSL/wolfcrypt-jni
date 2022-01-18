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
 * Wrapper for the native WolfCrypt 3DES implementation.
 */
public class Des3 extends BlockCipher {

    /** 3DES key size */
	public static final int KEY_SIZE = 24;
    /** 3DES block size */
	public static final int BLOCK_SIZE = 8;
    /** 3DES encrypt mode */
	public static final int ENCRYPT_MODE = 0;
    /** 3DES decrypt mode */
	public static final int DECRYPT_MODE = 1;

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;
	private int opmode;

    /**
     * Malloc native JNI Des3 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
	protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Set native Des3 key
     *
     * @param key byte array holding 3DES key
     * @param iv byte array holding 3DES IV
     * @param opmode 3DES mode, either Des3.ENCRYPT_MODE or
     *        Des3.DECRYPT_MODE
     */
	protected native void native_set_key(byte[] key, byte[] iv, int opmode);

    /**
     * Native Des3 encrypt/decrypt update operation
     *
     * @param opmode 3DES operation mode: Des3.ENCRYPT_MODE or
     *        Des3.DECRYPT_MODE
     * @param input input data for Des3 update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output array
     * @param outputOffset offset into output array to write data
     *
     * @return number of bytes stored in output
     */
	protected native int native_update(int opmode, byte[] input, int offset,
			int length, byte[] output, int outputOffset);

    /**
     * Native Des3 encrypt/decrypt update operation
     *
     * @param opmode 3DES operation mode: Des3.ENCRYPT_MODE or
     *        Des3.DECRYPT_MODE
     * @param input input data for Des3 update
     * @param offset offset into input array to start update
     * @param length length of data in input to update
     * @param output output buffer
     * @param outputOffset offset into output buffer to write data
     *
     * @return number of bytes stored in output
     */
	protected native int native_update(int opmode, ByteBuffer input,
			int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Create new Des3 object
     */
	public Des3() {
	}

    /**
     * Create new Des3 object
     *
     * @param key 3DES key
     * @param iv 3DES initialization vector (IV)
     * @param opmode 3DES mode: Des3.ENCRYPT_MODE or Des3.DECRYPT_MODE
     */
	public Des3(byte[] key, byte[] iv, int opmode) {
		setKey(key, iv, opmode);
	}
}

