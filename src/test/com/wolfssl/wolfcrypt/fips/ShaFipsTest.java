/* ShaFipsTest.java
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

import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.wolfcrypt.Util;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

public class ShaFipsTest {
	private ByteBuffer data = ByteBuffer.allocateDirect(32);
	private ByteBuffer result = ByteBuffer.allocateDirect(Sha.DIGEST_SIZE);
	private ByteBuffer expected = ByteBuffer.allocateDirect(Sha.DIGEST_SIZE);

	@Test
	public void initShouldReturnZero() {
		assertEquals(WolfCrypt.SUCCESS, Fips.InitSha_fips(new Sha()));
	}

	@Test
	public void hashShouldMatch() {
		String[] dataVector = new String[] { "", "226833eca43edeab",
				"01ae37df5128cb6059b57a904e834ca9",
				"421b944a38f03450b21d1c8c6514461fb82ef846cc9eebe7",
				"9f1daf4748d7aa20a359a7d8a220446de1a918e6dad68bda5894eb312ebbbc2e" };
		String[] hashVector = new String[] {
				"da39a3ee5e6b4b0d3255bfef95601890afd80709",
				"69e8fb462869452f0387733b03045dc0835531e5",
				"6849e5d39ac08f5daec25b91c4f4160cd921f8b7",
				"7e328a4e252a2d901a7f79365953a5e0682a8a9d",
				"22bbfc22a78aef3e356a32066eee78fc2ce28d8c" };

		for (int i = 0; i < dataVector.length; i++) {
			Sha sha = new Sha();

			data.put(Util.h2b(dataVector[i])).rewind();
			expected.put(Util.h2b(hashVector[i])).rewind();

			assertEquals(WolfCrypt.SUCCESS, Fips.InitSha_fips(sha));

			assertEquals(WolfCrypt.SUCCESS,
					Fips.ShaUpdate_fips(sha, data, dataVector[i].length() / 2));

			assertEquals(WolfCrypt.SUCCESS, Fips.ShaFinal_fips(sha, result));

			assertEquals(expected, result);
		}
	}
}
