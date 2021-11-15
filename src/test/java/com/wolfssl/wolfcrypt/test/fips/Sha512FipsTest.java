/* Sha512FipsTest.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt.test.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.Util;

public class Sha512FipsTest extends FipsTest {
	private ByteBuffer data = ByteBuffer.allocateDirect(32);
	private ByteBuffer result = ByteBuffer.allocateDirect(Sha512.DIGEST_SIZE);
	private ByteBuffer expected = ByteBuffer.allocateDirect(Sha512.DIGEST_SIZE);

	@Test
	public void initShouldReturnZero() {
		assertEquals(WolfCrypt.SUCCESS, Fips.InitSha512_fips(new Sha512()));
	}

	@Test
	public void hashShouldMatchUsingByteBuffer() {
		String[] dataVector = new String[] { "", "20580a530f01e771",
				"f4be10fcc53147e49c3ac0fb14da0cda",
				"6377e356cb3319bac8f9c6f1b0de83b995b994dc69c22662",
				"805bd99e436ae027083476d01634378e17be35fec9e54a61f69bade4a61ac426" };
		String[] hashVector = new String[] {
				"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d"
						+ "13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
				"f3c5257278d189af8e68cebe64a8ead462a577df25d770d4bfc8b2285fd60a370d836"
						+ "80871a16f2d3828e2d0a7de0eec4a1dbd6922bbdd71ac2e5ac0dfa41bf4",
				"bc6f9552456006d89038b6d1c347ba02590e663ab9f65e5a129f654d272cb4b225853"
						+ "37df92ef005fda7da2b86c04155db1eb66d6daa5611eaf6e60c03c859b9",
				"7298bbe4a960ad987685f056dcc5fffe855bb903c61de9fb73f305a875035d88a06ca"
						+ "d10239af89f0d993ff5a1dbbfa9fdf18453be23a25a43474948dfa877d7",
				"9de0ab4a241d6de77efe158a69d2caef41c11224e7b7f82426b7ba231bd02ef31f184"
						+ "72220636e48f708872c1ce8c05c53a2c47731d332ee43d7866ca01b26cf" };

		for (int i = 0; i < dataVector.length; i++) {
			Sha512 sha = new Sha512();

			data.put(Util.h2b(dataVector[i])).rewind();
			expected.put(Util.h2b(hashVector[i])).rewind();

			assertEquals(WolfCrypt.SUCCESS, Fips.InitSha512_fips(sha));

			assertEquals(WolfCrypt.SUCCESS, Fips.Sha512Update_fips(sha, data,
					dataVector[i].length() / 2));

			assertEquals(WolfCrypt.SUCCESS, Fips.Sha512Final_fips(sha, result));

			assertEquals(expected, result);
		}
	}

	@Test
	public void hashShouldMatchUsingByteArray() {
		String[] dataVector = new String[] { "", "20580a530f01e771",
				"f4be10fcc53147e49c3ac0fb14da0cda",
				"6377e356cb3319bac8f9c6f1b0de83b995b994dc69c22662",
				"805bd99e436ae027083476d01634378e17be35fec9e54a61f69bade4a61ac426" };
		String[] hashVector = new String[] {
				"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d"
						+ "13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
				"f3c5257278d189af8e68cebe64a8ead462a577df25d770d4bfc8b2285fd60a370d836"
						+ "80871a16f2d3828e2d0a7de0eec4a1dbd6922bbdd71ac2e5ac0dfa41bf4",
				"bc6f9552456006d89038b6d1c347ba02590e663ab9f65e5a129f654d272cb4b225853"
						+ "37df92ef005fda7da2b86c04155db1eb66d6daa5611eaf6e60c03c859b9",
				"7298bbe4a960ad987685f056dcc5fffe855bb903c61de9fb73f305a875035d88a06ca"
						+ "d10239af89f0d993ff5a1dbbfa9fdf18453be23a25a43474948dfa877d7",
				"9de0ab4a241d6de77efe158a69d2caef41c11224e7b7f82426b7ba231bd02ef31f184"
						+ "72220636e48f708872c1ce8c05c53a2c47731d332ee43d7866ca01b26cf" };

		for (int i = 0; i < dataVector.length; i++) {
			Sha512 sha = new Sha512();

			byte[] data     = Util.h2b(dataVector[i]);
			byte[] result   = new byte[Sha512.DIGEST_SIZE];
			byte[] expected = Util.h2b(hashVector[i]);

			assertEquals(WolfCrypt.SUCCESS, Fips.InitSha512_fips(sha));

			assertEquals(WolfCrypt.SUCCESS, Fips.Sha512Update_fips(sha, data,
					dataVector[i].length() / 2));

			assertEquals(WolfCrypt.SUCCESS, Fips.Sha512Final_fips(sha, result));

			assertArrayEquals(expected, result);
		}
	}
}
