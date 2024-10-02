/* Aes.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt AES implementation.
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

    /* Native JNI methods, internally reach back and grab/use pointer from
     * NativeStruct.java. We wrap calls to these below in order to
     * synchronize access to native pointer between threads */
    private native long mallocNativeStruct_internal() throws OutOfMemoryError;
    private native void native_set_key_internal(byte[] key, byte[] iv,
        int opmode);
    private native int native_update_internal(int opmode, byte[] input,
        int offset, int length, byte[] output, int outputOffset);
    private native int native_update_internal(int opmode, ByteBuffer input,
        int offset, int length, ByteBuffer output, int outputOffset);

    /**
     * Malloc native JNI AES structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected long mallocNativeStruct()
        throws OutOfMemoryError {

        synchronized (pointerLock) {
            return mallocNativeStruct_internal();
        }
    }

    /**
     * Set native AES key
     *
     * @param key byte array holding AES key
     * @param iv byte array holding AES IV
     * @param opmode AES mode, either Aes.ENCRYPT_MODE or
     *        Aes.DECRYPT_MODE
     */
    protected void native_set_key(byte[] key, byte[] iv, int opmode) {

        synchronized (pointerLock) {
            native_set_key_internal(key, iv, opmode);
        }
    }

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
    protected int native_update(int opmode, byte[] input, int offset,
            int length, byte[] output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset);
        }
    }

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
    protected int native_update(int opmode, ByteBuffer input,
            int offset, int length, ByteBuffer output, int outputOffset) {

        synchronized (pointerLock) {
            return native_update_internal(opmode, input, offset, length,
                output, outputOffset);
        }
    }

    /**
     * Create new Aes object.
     *
     * @throws WolfCryptException if AES has not been compiled into native
     *         wolfCrypt library.
     */
    public Aes() {
        if (!FeatureDetect.AesEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
    }

    /**
     * Create new Aes object
     *
     * @param key AES key
     * @param iv AES initialization vector (IV)
     * @param opmode AES mode: Aes.ENCRYPT_MODE or Aes.DECRYPT_MODE
     *
     * @throws WolfCryptException to indicate this constructor has been
     *         deprecated, along with instructions on what API to call
     *
     * @deprecated This constructor has been deprecated to avoid storage
     *             of the AES key inside this Aes class at the Java level.
     *             Please refactor existing code to call
     *             Aes.setKey(byte[] key, byte[] iv, int opmode) after this
     *             object has been created with the default Aes() constructor.
     */
    @Deprecated
    public Aes(byte[] key, byte[] iv, int opmode) {

        throw new WolfCryptException(
            "Constructor deprecated, use " +
            "Aes.setKey(byte[] key, byte[] iv, int opmode) " +
            "after object creation with Aes()");
    }
}

