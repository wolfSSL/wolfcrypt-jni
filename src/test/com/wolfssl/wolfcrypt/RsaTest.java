/* RsaTest.java
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

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

	@Test
	public void ExportRawPublicKeyShouldNotRaiseExceptions() {
		Rsa key = new Rsa();
		Rng rng = new Rng();
		ByteBuffer n = ByteBuffer.allocateDirect(WolfCrypt.SIZE_OF_1024_BITS);
		ByteBuffer e = ByteBuffer.allocateDirect(WolfCrypt.SIZE_OF_1024_BITS);

		assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(key, null));
		assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));

		key.makeKey(1024, 65537, rng);
		key.exportRawPublicKey(n, e);
		
		assertEquals(WolfCrypt.SUCCESS, Fips.FreeRng_fips(rng));
		assertEquals(WolfCrypt.SUCCESS, Fips.FreeRsaKey_fips(key));
	}
}
