/* BlockCipher.java
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

import javax.crypto.ShortBufferException;

/**
 * Common API for block ciphers.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2017
 */
public abstract class BlockCipher extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	private int opmode;

	protected abstract void native_set_key(byte[] key, byte[] iv, int opmode);

	protected abstract int native_update(int opmode, byte[] input, int offset,
			int length, byte[] output, int outputOffset);

	protected abstract int native_update(int opmode, ByteBuffer plain,
			int offset, int length, ByteBuffer cipher);

	public void setKey(byte[] key, byte[] iv, int opmode) {
		native_set_key(key, iv, opmode);

		this.opmode = opmode;
		state = WolfCryptState.READY;
	}

	public byte[] update(byte[] input) {
		return update(input, 0, input.length);
	}

	public byte[] update(byte[] input, int offset, int length) {
		byte[] output;

		if (state == WolfCryptState.READY) {
			output = new byte[input.length];

			native_update(opmode, input, offset, length, output, 0);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}

		return output;
	}

	public int update(byte[] input, int offset, int length, byte[] output,
			int outputOffset) throws ShortBufferException {
		if (state == WolfCryptState.READY) {
			if (outputOffset + length > output.length)
				throw new ShortBufferException(
						"output buffer is too small to hold the result.");

			return native_update(opmode, input, offset, length, output,
					outputOffset);
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}
	}

	public int update(ByteBuffer input, ByteBuffer output)
			throws ShortBufferException {
		int ret = 0;

		if (state == WolfCryptState.READY) {
			if (output.remaining() < input.remaining())
				throw new ShortBufferException(
						"output buffer is too small to hold the result.");

			ret = native_update(opmode, input, input.position(),
					input.remaining(), output);

			output.position(output.position() + input.remaining());
			input.position(input.position() + input.remaining());
		} else {
			throw new IllegalStateException(
					"No available key to perform the opperation.");
		}

		return ret;
	}
}
