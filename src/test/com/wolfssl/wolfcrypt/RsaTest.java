/* RsaTest.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

	private ByteBuffer n = ByteBuffer
			.allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);
	private ByteBuffer e = ByteBuffer
			.allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Rsa().getNativeStruct());
	}

	@Test
	public void decodeRawPublicKeyShouldNotRaiseExceptions() {
		Rsa key = new Rsa();

		n.put(Util
				.h2b("aff5f9e2e2622320d44dbf54f2274a0f96fa7d70a63ddaa563f48811"
						+ "43112bb3c36fe65ba0c9ad99d6fb6e53cb08e3938ee415b3a8cb"
						+ "7f9602f2154fab83dd160fa6f509ba2c41295af9eea8787d333e"
						+ "961461447fc60b3c61616ef5b94e822114e6fad44d1f2c476bc2"
						+ "3bc03609e2e70a483d826409fdb7c50a91269a773976ef137e7f"
						+ "a477c3951e8fbcb48f2378aa5e430e8c60b481beeb63df9abe10"
						+ "c7ccf266e394fbd925e8725e4675fb6ad895caed4b31d751c871"
						+ "2533e1c42ebefe9166e1aa20631521858c7548c61626ede105f2"
						+ "812632bac96eb769c9be560beef4200b86409727a5a61d1cc583"
						+ "1785ba4d42f02dd298a56bbbd6c479ce724d5bb5")).rewind();
		e.put(Util
				.h2b("00000000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000000000000000000000"
						+ "0000000000000000000000000000000000d0ee61")).rewind();

		assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(key, null));
		key.decodeRawPublicKey(n, n.limit(), e, e.limit());

		assertEquals(WolfCrypt.SUCCESS, Fips.FreeRsaKey_fips(key));
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
