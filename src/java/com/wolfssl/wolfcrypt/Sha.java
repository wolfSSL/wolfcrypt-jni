package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Sha implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class Sha extends NativeStruct {

	public static final int TYPE = 1; /* hash type unique */
	public static final int DIGEST_SIZE = 20;

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
