package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Sha256 implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Sha256 extends NativeStruct {

	public static final int TYPE = 2; /* hash type unique */
	public static final int DIGEST_SIZE = 32;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
