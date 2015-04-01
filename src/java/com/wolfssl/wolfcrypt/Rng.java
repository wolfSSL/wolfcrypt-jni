package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt Rng implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Rng extends NativeStruct {

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
