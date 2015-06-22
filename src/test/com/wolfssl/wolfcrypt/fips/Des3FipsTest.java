/* Des3FipsTest.java
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

package com.wolfssl.wolfcrypt.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.wolfcrypt.Util;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

public class Des3FipsTest {
	private ByteBuffer vector = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
	private ByteBuffer result = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
	private ByteBuffer cipher = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
	private ByteBuffer plain = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
	private ByteBuffer key = ByteBuffer.allocateDirect(Des3.KEY_SIZE);
	private ByteBuffer iv = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);

	@Test
	public void setKeyWithNullIVShouldReturnZero() {
		key.put(Util.h2b("000111222333444555666777888999aaabbbcccdddeeefff"))
				.rewind();

		assertEquals(WolfCrypt.SUCCESS,
				Fips.Des3_SetKey_fips(new Des3(), key, null, Des3.ENCRYPT_MODE));
	}

	@Test
	public void setIVShouldReturnZero() {
		vector.put(Util.h2b("0123456789abcdef")).rewind();

		assertEquals(WolfCrypt.SUCCESS, Fips.Des3_SetIV_fips(new Des3(), iv));
	}

	@Test
	public void cbcEncryptDecryptShouldMatch() {
		String[] keysVector = new String[] {
				"e61a38548694f1fd8cef251c518cc70bb613751c1ce52aa8",
				"2ff4e5c1cda84946798cc4ea8a1cf8df579e8a70f438b554",
				"9151232c854cf7977562a4e098d9d6ce892a80f79b408934",
				"9715c173b0a89292b3a88acbc7522085d5a1522f32109ea1" };
		String[] initVector = new String[] { "48a8ceb8551fd4ad",
				"76b779525bb0d1c0", "0e04ab4e1171451d", "19e6a2b2a690f026" };
		String[] testVector = new String[] { "e8fb0ceb4e912e16",
				"77340331c9c8e4f4", "2dab916e1b72c578", "7a3d5228d200e322" };
		String[] cipherText = new String[] { "d2190e296a0bfc56",
				"b7f1fd226680a6ee", "f50d41fc9fe9ba71", "5e124bc1d28414e7" };

		for (int i = 0; i < testVector.length; i++) {
			Des3 enc = new Des3();
			Des3 dec = new Des3();

			key.put(Util.h2b(keysVector[i])).rewind();
			iv.put(Util.h2b(initVector[i])).rewind();
			vector.put(Util.h2b(testVector[i])).rewind();
			cipher.put(Util.h2b(cipherText[i])).rewind();

			assertEquals(WolfCrypt.SUCCESS,
					Fips.Des3_SetKey_fips(enc, key, iv, Des3.ENCRYPT_MODE));
			assertEquals(WolfCrypt.SUCCESS,
					Fips.Des3_SetKey_fips(dec, key, iv, Des3.DECRYPT_MODE));

			assertEquals(WolfCrypt.SUCCESS, Fips.Des3_CbcEncrypt_fips(enc,
					result, vector, Des3.BLOCK_SIZE));
			assertEquals(WolfCrypt.SUCCESS, Fips.Des3_CbcDecrypt_fips(dec,
					plain, result, Des3.BLOCK_SIZE));

			assertEquals(result, cipher);
			assertEquals(plain, vector);
		}
	}
}
