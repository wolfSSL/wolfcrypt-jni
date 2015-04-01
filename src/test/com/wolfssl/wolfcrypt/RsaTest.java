package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Rsa;

public class RsaTest {

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Rsa().getNativeStruct());
	}
	
	@Test
	public void decodeRawPublicKeyShouldNotRaiseExceptions() {
		/*
		 * TODO Rsa init needed for this test.
		 */
	}

}
