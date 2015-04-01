package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Des3;

public class Des3Test {

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Des3().getNativeStruct());
	}

}
