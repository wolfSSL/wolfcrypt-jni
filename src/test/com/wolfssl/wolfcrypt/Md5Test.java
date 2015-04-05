package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Md5;

public class Md5Test {

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Md5().getNativeStruct());
	}

}
