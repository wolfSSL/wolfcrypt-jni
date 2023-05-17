/* Rng.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 * Wrapper for the native WolfCrypt RNG implementation
 */
public class Rng extends NativeStruct {

    /**
     * Malloc native JNI Rng structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /* native wrappers called by public functions below */
    private native void initRng();
    private native void freeRng();
    private native void rngGenerateBlock(ByteBuffer buffer, int offset,
            int length);
    private native void rngGenerateBlock(byte[] buffer, int offset, int length);

    /* Lock to prevent concurrent access to native WC_RNG */
    private final Object rngLock = new Object();

    /** Default Rng constructor */
    public Rng() { }

    @Override
    public synchronized void releaseNativeStruct() {
        free();
        super.releaseNativeStruct();
    }

    /**
     * Initialize Rng object
     */
    public synchronized void init() {
        synchronized (rngLock) {
            if (state == WolfCryptState.UNINITIALIZED) {
                initRng();
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    /**
     * Free Rng object
     */
    public synchronized void free() {
        synchronized (rngLock) {
            if (state == WolfCryptState.INITIALIZED) {
                freeRng();
                state = WolfCryptState.UNINITIALIZED;
            }
        }
    }

    /**
     * Generate random block of data
     *
     * Data size will be buffer.remaining() - buffer.position()
     *
     * @param buffer output buffer to place random data, should be direct
     *               ByteBuffer (ie: ByteBuffer.allocateDirect())
     *
     * @throws WolfCryptException if native operation fails or input
     *         ByteBuffer is not direct.
     */
    public synchronized void generateBlock(ByteBuffer buffer) {
        init();

        if (buffer.isDirect() == false) {
            throw new WolfCryptException("Input ByteBuffer is not direct");
        }

        synchronized (rngLock) {
            rngGenerateBlock(buffer, buffer.position(), buffer.remaining());
        }

        buffer.position(buffer.position() + buffer.remaining());
    }

    /**
     * Generate random block of data
     *
     * @param buffer output buffer to place random data
     * @param offset input into buffer to start writing
     * @param length length of random data to generate
     *
     * @throws WolfCryptException if native operation fails
     */
    public synchronized void generateBlock(byte[] buffer, int offset, int length) {
        init();

        synchronized (rngLock) {
            rngGenerateBlock(buffer, offset, length);
        }
    }

    /**
     * Generate random block of data
     *
     * Data size will be buffer.length
     *
     * @param buffer output buffer to place random data
     *
     * @throws WolfCryptException if native operation fails
     */
    public synchronized void generateBlock(byte[] buffer) {

        /* rngLock acquired inside generateBlock() sub call */
        generateBlock(buffer, 0, buffer.length);
    }

    /**
     * Generate random block of data
     *
     * @param length length of random data to generate
     *
     * @return byte array of random data
     *
     * @throws WolfCryptException if native operation fails
     */
    public synchronized byte[] generateBlock(int length) {
        byte[] buffer = new byte[length];

        /* rngLock acquired inside generateBlock() sub call */
        generateBlock(buffer, 0, length);

        return buffer;
    }
}

