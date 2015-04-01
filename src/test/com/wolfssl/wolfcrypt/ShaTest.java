package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Sha;

public class ShaTest {

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Sha().getNativeStruct());
	}

}
