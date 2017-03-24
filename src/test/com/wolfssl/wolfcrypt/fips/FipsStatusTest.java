/* FipsStatusTest.java
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

package com.wolfssl.wolfcrypt.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Fips.ErrorCallback;

public class FipsStatusTest extends FipsTest {
	@Test
	public void wolfCrypt_GetStatus_fipsShouldReturnZero() {
		assertEquals(WolfCrypt.SUCCESS, Fips.wolfCrypt_GetStatus_fips());
	}

	@Test
	public void wolfCrypt_SetStatus_fipsShouldReturnZero() {
		assertEquals(WolfCryptError.NOT_COMPILED_IN.getCode(),
				Fips.wolfCrypt_SetStatus_fips(
						WolfCryptError.DRBG_CONT_FIPS_E.getCode()));
	}

	public class MyCallback implements ErrorCallback {
		public void errorCallback(int ok, int err, String hash) {
			System.out.println(
					"in my Fips callback, ok =" + ok + " err = " + err);
			System.out.println("hash = " + hash);

			if (err == -203) {
				System.out.println(
						"In core integrity hash check failure, copy above hash");
				System.out.println(
						"into verifyCore[] in fips_test.c and rebuild");
			}
		}

	}

	@Test
	public void setErrorCallbackShouldNotRaise() {
		MyCallback callback = new MyCallback();

		Fips.wolfCrypt_SetCb_fips(callback);

		Fips.AesSetKey_fips(new Aes(),
				ByteBuffer.allocateDirect(Aes.KEY_SIZE_256), Aes.KEY_SIZE_128,
				null, Aes.ENCRYPT_MODE);
	}

	@Test
	public void getCoreHashShouldNotRaise() {
		System.out.println(Fips.wolfCrypt_GetCoreHash_fips());
	}
}
