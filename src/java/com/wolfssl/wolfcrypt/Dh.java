package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt DH implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, April 2015
 */
public class Dh extends NativeStruct {

	protected native long mallocNativeStruct() throws OutOfMemoryError;
}
