package com.wolfssl.wolfcrypt;

/**
 * Loader for the native WolfCrypt implementation.
 * All classes in this package must inherit from it.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class WolfObject {

	static {
		System.loadLibrary("wolfcryptjni");
	}

	protected WolfObject() {
	}

}
