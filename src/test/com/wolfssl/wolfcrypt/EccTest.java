/* EccTest.java
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

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.wolfcrypt.Ecc;

public class EccTest {
	private Ecc key;
	private static Rng rng = new Rng();

	@BeforeClass
	public static void setUpRng() {
		Fips.InitRng_fips(rng);
	}

	@AfterClass
	public static void tearDownRng() {
		Fips.FreeRng_fips(rng);
	}

	@Before
	public void setUpEcc() {
		try {
			key = new Ecc();
		} catch (WolfCryptException e) {
			if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
				System.out.println("Ecc test skipped: " + e.getError());
			Assume.assumeNoException(e);
		}
	}

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, key.getNativeStruct());
	}

	@Test
	public void sharedSecretShouldMatch() {
		Ecc pub = new Ecc();
		Ecc peer = new Ecc();

		key.makeKey(rng, 66);
		peer.makeKey(rng, 66);
		pub.importX963(key.exportX963());
		
		byte[] sharedSecretA = key.makeSharedSecret(peer);
		byte[] sharedSecretB = peer.makeSharedSecret(pub);

		assertArrayEquals(sharedSecretA, sharedSecretB);
	}

	@Test
	public void signatureShouldMatchDecodingKeys() {
		Ecc pub = new Ecc();
		Ecc peer = new Ecc();
		
		byte[] prvKey = Util.h2b("30770201010420F8CF92"
				+ "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
				+ "F88F974DAF568965C7A00A06082A8648CE3D0301"
				+ "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
				+ "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
				+ "EFA2351243847616C6569506CC01A9BDF6751A42"
				+ "F7BDA9B236225FC75D7FB4");

		byte[] pubKey = Util.h2b("3059301306072A8648CE"
				+ "3D020106082A8648CE3D0301070342000455BFF4"
				+ "0F44509A3DCE9BB7F0C54DF5707BD4EC248E1980"
				+ "EC5A4CA22403622C9BDAEFA2351243847616C656"
				+ "9506CC01A9BDF6751A42F7BDA9B236225FC75D7FB4");

		key.privateKeyDecode(prvKey);
		peer.publicKeyDecode(pubKey);

		byte[] hash = "Everyone gets Friday off. ecc p".getBytes();

		byte[] signature = key.sign(hash, rng);

		assertTrue(peer.verify(hash, signature));
		
		pub.importX963(key.exportX963());

		assertTrue(pub.verify(hash, signature));
		
		assertArrayEquals(prvKey, key.privateKeyEncode());
		assertArrayEquals(pubKey, key.publicKeyEncode());
		assertArrayEquals(pubKey, pub.publicKeyEncode());
		assertArrayEquals(pubKey, peer.publicKeyEncode());
	}
}
