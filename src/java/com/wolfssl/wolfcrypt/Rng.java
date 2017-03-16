/* Rng.java
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
 * Wrapper for the native WolfCrypt Rng implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Rng extends NativeStruct {

	protected native long mallocNativeStruct() throws OutOfMemoryError;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /* native wrappers called by public functions below */
	private native void initRng();
	private native void freeRng();
	private native void rngGenerateBlock(ByteBuffer buf, long bufSz);
	private native void rngGenerateBlock(byte[] buf, long bufSz);

    public void init() throws IllegalStateException {

        if (state == WolfCryptState.UNINITIALIZED) {
            initRng();
            state = WolfCryptState.INITIALIZED;
        } else {
            throw new IllegalStateException(
                "Object has already been initialized");
        }
    }

    public void free() throws IllegalStateException {

        if (state == WolfCryptState.INITIALIZED) {
            freeRng();
            state = WolfCryptState.UNINITIALIZED;
        } else {
            throw new IllegalStateException(
                "Object has been freed");
        }
    }

    public void generateBlock(ByteBuffer buf, long bufSz)
        throws IllegalStateException {

        if (state == WolfCryptState.INITIALIZED) {
            rngGenerateBlock(buf, bufSz);
        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }

    public void generateBlock(byte[] buf, long bufSz)
        throws IllegalStateException {

        if (state == WolfCryptState.INITIALIZED) {
            rngGenerateBlock(buf, bufSz);
        } else {
            throw new IllegalStateException(
                "Object must be initialized before use");
        }
    }
}

