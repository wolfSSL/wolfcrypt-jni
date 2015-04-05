package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Sha implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, April 2015
 */
public class Md5 extends NativeStruct {

	public static final int TYPE = 0; /* hash type unique */
	public static final int DIGEST_SIZE = 16;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
