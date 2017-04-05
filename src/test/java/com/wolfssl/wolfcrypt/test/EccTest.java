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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class EccTest {
	private static Rng rng = new Rng();

	@BeforeClass
	public static void setUpRng() {
		rng.init();
	}

	@BeforeClass
	public static void checkAvailability() {
		try {
			new Ecc();
		} catch (WolfCryptException e) {
			if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
				System.out.println("Ecc test skipped: " + e.getError());
			Assume.assumeNoException(e);
		}
	}

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Ecc().getNativeStruct());
	}

	@Test
	public void sharedSecretShouldMatch() {
		Ecc alice = new Ecc();
		Ecc bob = new Ecc();
		Ecc aliceX963 = new Ecc();

		alice.makeKey(rng, 66);
		bob.makeKey(rng, 66);
		aliceX963.importX963(alice.exportX963());

		byte[] sharedSecretA = alice.makeSharedSecret(bob);
		byte[] sharedSecretB = bob.makeSharedSecret(aliceX963);

		assertArrayEquals(sharedSecretA, sharedSecretB);

		Ecc alice2 = new Ecc();

		alice2.importPrivate(alice.exportPrivate(), alice.exportX963());

		assertArrayEquals(sharedSecretA, alice2.makeSharedSecret(bob));
	}

	@Test
	public void signatureShouldMatchDecodingKeys() {
		Ecc alice = new Ecc();
		Ecc bob = new Ecc();
		Ecc aliceX963 = new Ecc();

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

		alice.privateKeyDecode(prvKey);
		bob.publicKeyDecode(pubKey);

		byte[] hash = "Everyone gets Friday off. ecc p".getBytes();

		byte[] signature = alice.sign(hash, rng);

		assertTrue(bob.verify(hash, signature));

		aliceX963.importX963(alice.exportX963());

		assertTrue(aliceX963.verify(hash, signature));

		assertArrayEquals(prvKey, alice.privateKeyEncode());
		assertArrayEquals(pubKey, alice.publicKeyEncode());
		assertArrayEquals(pubKey, bob.publicKeyEncode());
		assertArrayEquals(pubKey, aliceX963.publicKeyEncode());

		Ecc alice2 = new Ecc();

		alice2.importPrivate(alice.exportPrivate(), alice.exportX963());

		assertTrue(alice2.verify(hash, signature));
	}

    @Test
    public void eccCurveSizeFromName() {
        Ecc alice = new Ecc();
        int size = 0;

        /* valid case */
        size = Ecc.getCurveSizeFromName("secp256r1");
        assertEquals(size, 32);

        /* mixed case should work */
        size = Ecc.getCurveSizeFromName("SeCp256R1");
        assertEquals(size, 32);

        /* bad curve should return -1 */
        size = Ecc.getCurveSizeFromName("BADCURVE");
        assertEquals(size, -1);

        /* null should return BAD_FUNC_ARG */
        size = Ecc.getCurveSizeFromName(null);
        assertEquals(size, -173);
    }

    @Test
    public void eccMakeKeyOnCurve() {
        Ecc alice = new Ecc();
        alice.makeKeyOnCurve(rng, 32, "secp256r1");

        try {
            alice = new Ecc();
            alice.makeKeyOnCurve(rng, 32, "BADCURVE");
        } catch (WolfCryptException e) {
            /* should throw exception here */
        }
    }

    @Test
    public void eccPrivateToPkcs8() {
        Ecc alice = new Ecc();
        byte[] pkcs8;
        int size;

        byte[] prvKey = Util.h2b("30770201010420F8CF92"
                + "6BBD1E28F1A8ABA1234F3274188850AD7EC7EC92"
                + "F88F974DAF568965C7A00A06082A8648CE3D0301"
                + "07A1440342000455BFF40F44509A3DCE9BB7F0C5"
                + "4DF5707BD4EC248E1980EC5A4CA22403622C9BDA"
                + "EFA2351243847616C6569506CC01A9BDF6751A42"
                + "F7BDA9B236225FC75D7FB4");

        byte[] expectedPkcs8 = Util.h2b("304D02010030130607"
                + "2A8648CE3D020106082A8648CE3D030107043330"
                + "310201010420F8CF926BBD1E28F1A8ABA1234F32"
                + "74188850AD7EC7EC92F88F974DAF568965C7A00A"
                + "06082A8648CE3D030107");

		alice.privateKeyDecode(prvKey);

        pkcs8 = alice.privateKeyEncodePKCS8();
        assertArrayEquals(pkcs8, expectedPkcs8);
    }
}
