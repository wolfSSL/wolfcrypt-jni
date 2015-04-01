package com.wolfssl.wolfcrypt;

/**
 * Main wrapper for the native WolfCrypt implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, February 2015
 */
public class WolfCrypt extends WolfObject {

	public static final int SUCCESS = 0;

	public static final int SIZE_OF_128_BITS = 16;
	public static final int SIZE_OF_160_BITS = 20;
	public static final int SIZE_OF_192_BITS = 24;
	public static final int SIZE_OF_256_BITS = 32;
	public static final int SIZE_OF_384_BITS = 48;
	public static final int SIZE_OF_512_BITS = 64;
	public static final int SIZE_OF_1024_BITS = 128;
	public static final int SIZE_OF_2048_BITS = 256;

	private WolfCrypt() {
	}
}
