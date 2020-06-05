/* Sha384Test.java
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

import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;

import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;

public class Sha384Test {
	private ByteBuffer data = ByteBuffer.allocateDirect(32);
	private ByteBuffer result = ByteBuffer.allocateDirect(Sha384.DIGEST_SIZE);
	private ByteBuffer expected = ByteBuffer.allocateDirect(Sha384.DIGEST_SIZE);

    @BeforeClass
    public static void checkSha384IsAvailable() {
        try {
            Sha384 sha = new Sha384();
        } catch (WolfCryptException e) {
			if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
				System.out.println("Sha384Test skipped: " + e.getError());
                Assume.assumeTrue(false);
            }
        }
    }

	@Test
	public void constructorShouldInitializeNativeStruct() {
		assertNotEquals(NativeStruct.NULL, new Sha384().getNativeStruct());
	}

	@Test
	public void hashShouldMatchUsingByteBuffer() throws ShortBufferException {
		String[] dataVector = new String[] { "", "c2edba56a6b82cc3",
				"2b1632b74a1c34b58af23274599a3aa1",
				"4a4c09366fb6772637d9e696f1d0d0a98005ca33bc01062a",
				"50b9952a9da3a1e704d22c414b4055a7b0866513dafd5f481023d958a9400b68" };
		String[] hashVector = new String[] {
				"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc"
						+ "7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
				"03ca8e9a0da972814137eb37c5b8a59a7a0166c62f5d7eb643147"
						+ "2f79a33412cd3fa6c483da48e758fbc70027d132edf",
				"419a34764a30d5becda0d5eb33c67719b0d030fb2596b12d6207b"
						+ "329d45718cebd2c965b52ab538fbe68c90fab2878d7",
				"5388214cfa96289ac37b365226accf8b4022e5b931095ddfc4f59"
						+ "c47cb45e8a8fbd0c77f52eeacd2afaa61d653b40351",
				"7bcd20725ece37b040aa497832f3138e179da1a673714321fcba9"
						+ "7169a47199586dcb6599cf3f7d7497b85349f6f7b88" };

		for (int i = 0; i < dataVector.length; i++) {
			Sha384 sha = new Sha384();

			data.put(Util.h2b(dataVector[i])).rewind();
			expected.put(Util.h2b(hashVector[i])).rewind();

			sha.update(data, dataVector[i].length() / 2);
			sha.digest(result);
			data.rewind();
			result.rewind();

			assertEquals(expected, result);
		}
	}

	@Test
	public void hashShouldMatchUsingByteArray() {
		String[] dataVector = new String[] { "", "c2edba56a6b82cc3",
				"2b1632b74a1c34b58af23274599a3aa1",
				"4a4c09366fb6772637d9e696f1d0d0a98005ca33bc01062a",
				"50b9952a9da3a1e704d22c414b4055a7b0866513dafd5f481023d958a9400b68" };
		String[] hashVector = new String[] {
				"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc"
						+ "7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
				"03ca8e9a0da972814137eb37c5b8a59a7a0166c62f5d7eb643147"
						+ "2f79a33412cd3fa6c483da48e758fbc70027d132edf",
				"419a34764a30d5becda0d5eb33c67719b0d030fb2596b12d6207b"
						+ "329d45718cebd2c965b52ab538fbe68c90fab2878d7",
				"5388214cfa96289ac37b365226accf8b4022e5b931095ddfc4f59"
						+ "c47cb45e8a8fbd0c77f52eeacd2afaa61d653b40351",
				"7bcd20725ece37b040aa497832f3138e179da1a673714321fcba9"
						+ "7169a47199586dcb6599cf3f7d7497b85349f6f7b88" };

		for (int i = 0; i < dataVector.length; i++) {
			Sha384 sha = new Sha384();

			byte[] data = Util.h2b(dataVector[i]);
			byte[] expected = Util.h2b(hashVector[i]);

			sha.update(data);
			byte[] result = sha.digest();
			
			assertArrayEquals(expected, result);
		}
	}

    @Test
    public void releaseAndReInitObject() {

        Sha384 sha = new Sha384();
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("561C16404A1B592406301780C0C2DF6A" +
                                   "A0555F504F35BFBEAC810AE36A343B77" +
                                   "6858C5E0DE56BB79607A34D2F67108F2");
        byte[] result = null;

        sha.update(data);
        result = sha.digest();
        assertArrayEquals(expected, result);
        sha.releaseNativeStruct();

        /* test re-initializing object */
        sha = new Sha384();
        result = null;
        sha.update(data);
        result = sha.digest();
        sha.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        Sha384 sha = new Sha384();
        byte[] data  = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };
        byte[] expected = Util.h2b("561C16404A1B592406301780C0C2DF6A" +
                                   "A0555F504F35BFBEAC810AE36A343B77" +
                                   "6858C5E0DE56BB79607A34D2F67108F2");
        byte[] expected2 = Util.h2b("7EC3520B5D75D61F1F0586A0D00CDBF5" +
                                    "D0BD67C1046F3A4DB37637792F7C683A" +
                                    "83FB1A61A5562E28826686C14474CC2C");
        byte[] result = null;
        byte[] result2 = null;

        sha.update(data);
        result = sha.digest();
        assertArrayEquals(expected, result);

        /* test reusing existing object after a call to digest() */
        sha.update(data2);
        result2 = sha.digest();
        assertArrayEquals(expected2, result2);

        sha.releaseNativeStruct();
    }
}
