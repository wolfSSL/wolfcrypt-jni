package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Sha512 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Sha512 extends NativeStruct {

	public static final int TYPE = 4; /* hash type unique */
	public static final int DIGEST_SIZE = 64;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
