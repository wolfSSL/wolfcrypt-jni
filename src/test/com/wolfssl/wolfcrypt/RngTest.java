package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Rng;

public class RngTest {

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Rng().getNativeStruct());
	}

}
