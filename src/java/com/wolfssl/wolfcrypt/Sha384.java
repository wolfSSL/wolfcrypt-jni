package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Sha384 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Sha384 extends NativeStruct {

	public static final int TYPE = 5; /* hash type unique */
	public static final int DIGEST_SIZE = 48;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
