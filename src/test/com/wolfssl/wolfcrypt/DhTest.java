/* DhTest.java
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
import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.wolfcrypt.Dh;

public class DhTest {
	private static Rng rng = new Rng();

	@BeforeClass
	public static void setUpRng() {
		Fips.InitRng_fips(rng);
	}

	@AfterClass
	public static void tearDownRng() {
		Fips.FreeRng_fips(rng);
	}

	@BeforeClass
	public static void checkAvailability() {
		try {
			new Dh();
		} catch (WolfCryptException e) {
			if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
				System.out.println("Dh test skipped: " + e.getError());
			Assume.assumeNoException(e);
		}
	}

	@Test
	public void sharedSecretShouldMatch() {
		byte[] p = Util.h2b("E6969D3D495BE32C7CF180C3BDD4798E91B7818251BB055E"
				+ "2A2064904A79A770FA15A259CBD523A6A6EF09C43048D5A22F971F3C20"
				+ "129B48000E6EDD061CBC053E371D794E5327DF611EBBBE1BAC9B5C6044"
				+ "CF023D76E05EEA9BAD991B13A63C974E9EF1839EB5DB125136F7262E56"
				+ "A8871538DFD823C6505085E21F0DD5C86B");
		
		byte[] g = Util.h2b("02");

		Dh alice = new Dh(p, g);
		Dh bob = new Dh();

		bob.setParams(p, g);

		assertNull(alice.getPublicKey());
		assertNull(bob.getPublicKey());
		
		alice.makeKey(rng, 256);
		bob.makeKey(rng, 256);

		assertNotNull(alice.getPublicKey());
		assertNotNull(bob.getPublicKey());

		byte[] sharedSecretA = alice.makeSharedSecret(bob);
		byte[] sharedSecretB = bob.makeSharedSecret(alice);

		assertNotNull(sharedSecretA);
		assertNotNull(sharedSecretB);
		assertArrayEquals(sharedSecretA, sharedSecretB);
	}
}
