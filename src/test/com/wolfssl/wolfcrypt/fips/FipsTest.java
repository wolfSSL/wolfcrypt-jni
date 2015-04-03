package com.wolfssl.wolfcrypt.fips;

import static org.junit.Assert.*;

import org.junit.Test;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

public class FipsTest {
	@Test
	public void wolfCrypt_GetStatus_fipsShouldReturnZero() {
		assertEquals(WolfCrypt.SUCCESS, Fips.wolfCrypt_GetStatus_fips());
	}
}
