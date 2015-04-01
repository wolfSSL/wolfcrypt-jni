package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Hmac implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Hmac extends NativeStruct {
	
	public static final int MD5 = 0;
	public static final int SHA = 1;
	public static final int SHA256 = 2;
	public static final int SHA384 = 5;
	public static final int SHA512 = 4;
	public static final int BLAKE2b = 7;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
