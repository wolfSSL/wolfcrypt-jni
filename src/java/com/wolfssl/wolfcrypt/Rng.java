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

	private native void rngGenerateBlock(ByteBuffer buffer, int offset,
			int length);

	private native void rngGenerateBlock(byte[] buffer, int offset, int length);

	@Override
	public void releaseNativeStruct() {
		free();

		super.releaseNativeStruct();
	}

	public void init() {
		if (state == WolfCryptState.UNINITIALIZED) {
			initRng();
			state = WolfCryptState.INITIALIZED;
		}
	}

	public void free() {
		if (state == WolfCryptState.INITIALIZED) {
			freeRng();
			state = WolfCryptState.UNINITIALIZED;
		}
	}

	public void generateBlock(ByteBuffer buffer) {
		init();

		rngGenerateBlock(buffer, buffer.position(), buffer.remaining());
		buffer.position(buffer.position() + buffer.remaining());
	}
	
	public void generateBlock(byte[] buffer, int offset, int length) {
		init();
		
		rngGenerateBlock(buffer, offset, length);
	}

	public void generateBlock(byte[] buffer) {
		generateBlock(buffer, 0, buffer.length);
	}

	public byte[] generateBlock(int length) {
		byte[] buffer = new byte[length];

		generateBlock(buffer, 0, length);

		return buffer;
	}
}
