package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.Test;

import com.wolfssl.wolfcrypt.Ecc;

public class EccTest {

	@Test
	public void constructorShouldInitializeNativeStruct() {

		try {
			Ecc nativeStruct = new Ecc();

			assertNotEquals(NativeStruct.NULL, nativeStruct.getNativeStruct());
		} catch (Exception e) {
			Assume.assumeNoException(e);
		}
	}

}
