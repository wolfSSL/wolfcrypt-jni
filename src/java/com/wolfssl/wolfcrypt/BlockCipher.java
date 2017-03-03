package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

public abstract class BlockCipher extends NativeStruct {

	private WolfCryptState state = WolfCryptState.UNINITIALIZED;

	private int opmode;
	
	protected abstract void native_set_key(byte[] key, byte[] iv, int opmode);

	protected abstract int native_update(int opmode, byte[] input, int offset,
			int length, byte[] output, int outputOffset);

	protected abstract int native_update(int opmode, ByteBuffer plain, int offset,
			int length, ByteBuffer cipher);

	
	public void setKey(byte[] key, byte[] iv, int opmode) {
		native_set_key(key, iv, opmode);

		this.opmode = opmode;
		state = WolfCryptState.READY;
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
