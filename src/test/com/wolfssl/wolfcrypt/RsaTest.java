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

	@Test
	public void makeKeyShouldNotRaiseExceptions() {
		Rsa key = new Rsa();
		Rng rng = new Rng();
		
		assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(key, null));
		assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
		
		key.makeKey(1024, 65537, rng);
		
		assertEquals(WolfCrypt.SUCCESS, Fips.FreeRng_fips(rng));
		assertEquals(WolfCrypt.SUCCESS, Fips.FreeRsaKey_fips(key));
	}
}
