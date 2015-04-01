package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Aes implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class Aes extends NativeStruct {

	public static final int KEY_SIZE_128 = 16;
	public static final int KEY_SIZE_192 = 24;
	public static final int KEY_SIZE_256 = 32;
	public static final int BLOCK_SIZE = 16;
	public static final int ENCRYPT_MODE = 0;
	public static final int DECRYPT_MODE = 1;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
