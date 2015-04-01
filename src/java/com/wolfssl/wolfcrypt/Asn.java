package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt Asn implementation.
 *
 * @author Moisés Guimarães
 * @version 1.0, March 2015
 */
public class Asn extends WolfObject {

	public static final int MAX_ENCODED_SIG_SIZE = 512;

	public static native void encodeSignature(ByteBuffer encoded,
			ByteBuffer hash, long hashSize, int hashOID);

	public static native int getCTC_HashOID(int type);
}
