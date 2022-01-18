/* Aes.java
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
 * Wrapper for the native WolfCrypt Aes implementation.
 *
 * @author wolfSSL Inc.
 */
public class Aes extends BlockCipher {

    /** AES-128 key size */
    public static final int KEY_SIZE_128 = 16;
    /** AES-192 key size */
    public static final int KEY_SIZE_192 = 24;
    /** AES-256 key size */
    public static final int KEY_SIZE_256 = 32;
    /** AES block size */
    public static final int BLOCK_SIZE = 16;
    /** AES encrypt mode */
    public static final int ENCRYPT_MODE = 0;
    /** AES decrypt mode */
    public static final int DECRYPT_MODE = 1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    private int opmode;

    /**
     * Malloc native JNI AES structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    /**
     * Set native AES key
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES IV
     * @param opmode AES mode, either Aes.ENCRYPT_MODE or
     *        Aes.DECRYPT_MODE
     */
    protected native void native_set_key(byte[] key, byte[] iv, int opmode);

    /**
     * Native AES encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: Aes.ENCRYPT_MODE or
     *        Aes.DECRYPT_MODE
     * @param input input data for AES update
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
     * Native AES encrypt/decrypt update operation
     *
     * @param opmode AES operation mode: Aes.ENCRYPT_MODE or
     *        Aes.DECRYPT_MODE
     * @param input input data for AES update
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
     * Create new Aes object
     */
    public Aes() {
    }

    /**
     * Create new Aes object
     *
     * @param key AES key
     * @param iv AES initialization vector (IV)
     * @param opmode AES mode: Aes.ENCRYPT_MODE or Aes.DECRYPT_MODE
     */
    public Aes(byte[] key, byte[] iv, int opmode) {
        setKey(key, iv, opmode);
    }
}

