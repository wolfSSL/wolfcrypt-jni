package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Des3 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class Des3 extends NativeStruct {

	public static final int KEY_SIZE = 24;
	public static final int BLOCK_SIZE = 8;
	public static final int ENCRYPT_MODE = 0;
	public static final int DECRYPT_MODE = 1;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
