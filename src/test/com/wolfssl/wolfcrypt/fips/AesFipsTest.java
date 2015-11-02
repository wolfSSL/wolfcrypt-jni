/* AesFipsTest.java
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

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Util;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

public class AesFipsTest {
	private ByteBuffer input = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer output = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer cipher = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer plain = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer key = ByteBuffer.allocateDirect(Aes.KEY_SIZE_256);
	private ByteBuffer iv = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer aad = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer tag = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
	private ByteBuffer expected = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);

	@Test
	public void setKeyShouldReturnZeroUsingByteBuffer() {
		key.put(Util.h2b("00112233445566778899aabbccddeeff")).rewind();
		iv.put(Util.h2b("ffeeddccbbaa99887766554433221100")).rewind();

		assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(new Aes(), key,
				Aes.KEY_SIZE_128, iv, Aes.ENCRYPT_MODE));
	}

	@Test
	public void setKeyShouldReturnZeroUsingByteArray() {
		assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(new Aes(),
				Util.h2b("00112233445566778899aabbccddeeff"), Aes.KEY_SIZE_128,
				Util.h2b("ffeeddccbbaa99887766554433221100"), Aes.ENCRYPT_MODE));
	}

	@Test
	public void setKeyWithNullIVShouldReturnZeroUsingByteBuffer() {
		key.put(Util.h2b("00112233445566778899aabbccddeeff")).rewind();

		assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(new Aes(), key,
				Aes.KEY_SIZE_128, null, Aes.ENCRYPT_MODE));
	}

	@Test
	public void setKeyWithNullIVShouldReturnZeroUsingByteArray() {
		assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(new Aes(),
				Util.h2b("00112233445566778899aabbccddeeff"), Aes.KEY_SIZE_128,
				null, Aes.ENCRYPT_MODE));
	}

	@Test
	public void setIVShouldReturnZeroUsingByteBuffer() {
		iv.put(Util.h2b("00112233445566778899aabbccddeeff")).rewind();

		assertEquals(WolfCrypt.SUCCESS, Fips.AesSetIV_fips(new Aes(), iv));
	}

	@Test
	public void setIVShouldReturnZeroUsingByteArray() {
		assertEquals(
				WolfCrypt.SUCCESS,
				Fips.AesSetIV_fips(new Aes(),
						Util.h2b("00112233445566778899aabbccddeeff")));
	}

	@Test
	public void cbcEncryptDecryptShouldMatchUsingByteByffer() {
		String[] keys = new String[] {
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", };
		String[] ivs = new String[] { "000102030405060708090A0B0C0D0E0F",
				"7649ABAC8119B246CEE98E9B12E9197D",
				"5086CB9B507219EE95DB113A917678B2",
				"73BED6B8E3C1743B7116E69E22229516",
				"000102030405060708090A0B0C0D0E0F",
				"4F021DB243BC633D7178183A9FA071E8",
				"B4D9ADA9AD7DEDF4E5E738763F69145A",
				"571B242012FB7AE07FA9BAAC3DF102E0",
				"000102030405060708090A0B0C0D0E0F",
				"F58C4C04D6E5F1BA779EABFB5F7BFBD6",
				"9CFC4E967EDB808D679F777BC6702C7D",
				"39F23369A9D9BACFA530E26304231461" };
		String[] inputs = new String[] { "6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710",
				"6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710",
				"6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710" };
		String[] outputs = new String[] { "7649abac8119b246cee98e9b12e9197d",
				"5086cb9b507219ee95db113a917678b2",
				"73bed6b8e3c1743b7116e69e22229516",
				"3ff1caa1681fac09120eca307586e1a7",
				"4f021db243bc633d7178183a9fa071e8",
				"b4d9ada9ad7dedf4e5e738763f69145a",
				"571b242012fb7ae07fa9baac3df102e0",
				"08b0e27988598881d920a9e64f5615cd",
				"f58c4c04d6e5f1ba779eabfb5f7bfbd6",
				"9cfc4e967edb808d679f777bc6702c7d",
				"39f23369a9d9bacfa530e26304231461",
				"b2eb05e2c39be9fcda6c19078c6a9d1b" };

		for (int i = 0; i < inputs.length; i++) {
			Aes enc = new Aes();
			Aes dec = new Aes();

			key.put(Util.h2b(keys[i])).rewind();
			iv.put(Util.h2b(ivs[i])).rewind();
			input.put(Util.h2b(inputs[i])).rewind();
			output.put(Util.h2b(outputs[i])).rewind();

			if (i % 2 == 0) {
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, key,
						keys[i].length() / 2, iv, Aes.ENCRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, key,
						keys[i].length() / 2, iv, Aes.DECRYPT_MODE));
			} else {
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, key,
						keys[i].length() / 2, null, Aes.ENCRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetIV_fips(enc, iv));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, key,
						keys[i].length() / 2, null, Aes.DECRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetIV_fips(dec, iv));
			}

			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcEncrypt_fips(enc, cipher, input, Aes.BLOCK_SIZE));
			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcDecrypt_fips(dec, plain, output, Aes.BLOCK_SIZE));

			assertEquals(output, cipher);
			assertEquals(input, plain);
		}
	}

	@Test
	public void cbcEncryptDecryptShouldMatchUsingByteArray() {
		String[] keys = new String[] {
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"2b7e151628aed2a6abf7158809cf4f3c",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", };
		String[] ivs = new String[] { "000102030405060708090A0B0C0D0E0F",
				"7649ABAC8119B246CEE98E9B12E9197D",
				"5086CB9B507219EE95DB113A917678B2",
				"73BED6B8E3C1743B7116E69E22229516",
				"000102030405060708090A0B0C0D0E0F",
				"4F021DB243BC633D7178183A9FA071E8",
				"B4D9ADA9AD7DEDF4E5E738763F69145A",
				"571B242012FB7AE07FA9BAAC3DF102E0",
				"000102030405060708090A0B0C0D0E0F",
				"F58C4C04D6E5F1BA779EABFB5F7BFBD6",
				"9CFC4E967EDB808D679F777BC6702C7D",
				"39F23369A9D9BACFA530E26304231461" };
		String[] inputs = new String[] { "6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710",
				"6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710",
				"6bc1bee22e409f96e93d7e117393172a",
				"ae2d8a571e03ac9c9eb76fac45af8e51",
				"30c81c46a35ce411e5fbc1191a0a52ef",
				"f69f2445df4f9b17ad2b417be66c3710" };
		String[] outputs = new String[] { "7649abac8119b246cee98e9b12e9197d",
				"5086cb9b507219ee95db113a917678b2",
				"73bed6b8e3c1743b7116e69e22229516",
				"3ff1caa1681fac09120eca307586e1a7",
				"4f021db243bc633d7178183a9fa071e8",
				"b4d9ada9ad7dedf4e5e738763f69145a",
				"571b242012fb7ae07fa9baac3df102e0",
				"08b0e27988598881d920a9e64f5615cd",
				"f58c4c04d6e5f1ba779eabfb5f7bfbd6",
				"9cfc4e967edb808d679f777bc6702c7d",
				"39f23369a9d9bacfa530e26304231461",
				"b2eb05e2c39be9fcda6c19078c6a9d1b" };

		for (int i = 0; i < inputs.length; i++) {
			Aes enc = new Aes();
			Aes dec = new Aes();

			byte[] key = Util.h2b(keys[i]);
			byte[] iv = Util.h2b(ivs[i]);
			byte[] input = Util.h2b(inputs[i]);
			byte[] output = Util.h2b(outputs[i]);
			byte[] cipher = new byte[Aes.BLOCK_SIZE];
			byte[] plain = new byte[Aes.BLOCK_SIZE];

			if (i % 2 == 0) {
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, key,
						keys[i].length() / 2, iv, Aes.ENCRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, key,
						keys[i].length() / 2, iv, Aes.DECRYPT_MODE));
			} else {
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, key,
						keys[i].length() / 2, null, Aes.ENCRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetIV_fips(enc, iv));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, key,
						keys[i].length() / 2, null, Aes.DECRYPT_MODE));
				assertEquals(WolfCrypt.SUCCESS, Fips.AesSetIV_fips(dec, iv));
			}

			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcEncrypt_fips(enc, cipher, input, Aes.BLOCK_SIZE));
			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcDecrypt_fips(dec, plain, output, Aes.BLOCK_SIZE));

			assertArrayEquals(output, cipher);
			assertArrayEquals(input, plain);
		}
	}

	@Test
	public void cbcGFSboxShouldMatchUsingByteByffer() {
		ByteBuffer null_key = ByteBuffer.allocateDirect(Aes.KEY_SIZE_128);
		ByteBuffer null_iv = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);

		String[] testinput = new String[] { "f34481ec3cc627bacd5dc3fb08f273e6",
				"9798c4640bad75c7c3227db910174e72",
				"96ab5c2ff612d9dfaae8c31f30c42168",
				"6a118a874519e64e9963798a503f1d35",
				"cb9fceec81286ca3e989bd979b0cb284",
				"b26aeb1874e47ca8358ff22378f09144",
				"58c8e00b2631686d54eab84b91f0aca1" };
		String[] cipherText = new String[] {
				"0336763e966d92595a567cc9ce537f5e",
				"a9a1631bf4996954ebc093957b234589",
				"ff4f8391a6a40ca5b25d23bedd44a597",
				"dc43be40be0e53712f7e2bf5ca707209",
				"92beedab1895a94faa69b632e5cc47ce",
				"459264f4798f6a78bacb89c15ed3d601",
				"08a4e2efec8a8e3312ca7460b9040bbf" };

		for (int i = 0; i < testinput.length; i++) {
			Aes enc = new Aes();
			Aes dec = new Aes();

			assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, null_key,
					Aes.KEY_SIZE_128, null_iv, Aes.ENCRYPT_MODE));

			assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, null_key,
					Aes.KEY_SIZE_128, null_iv, Aes.DECRYPT_MODE));

			input.put(Util.h2b(testinput[i])).rewind();
			cipher.put(Util.h2b(cipherText[i])).rewind();

			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcEncrypt_fips(enc, output, input, Aes.BLOCK_SIZE));
			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcDecrypt_fips(dec, plain, output, Aes.BLOCK_SIZE));

			assertEquals(output, cipher);
			assertEquals(plain, input);
		}
	}

	@Test
	public void cbcGFSboxShouldMatchUsingByteArray() {
		byte[] null_key = new byte[Aes.KEY_SIZE_128];
		byte[] null_iv = new byte[Aes.BLOCK_SIZE];

		String[] testinput = new String[] { "f34481ec3cc627bacd5dc3fb08f273e6",
				"9798c4640bad75c7c3227db910174e72",
				"96ab5c2ff612d9dfaae8c31f30c42168",
				"6a118a874519e64e9963798a503f1d35",
				"cb9fceec81286ca3e989bd979b0cb284",
				"b26aeb1874e47ca8358ff22378f09144",
				"58c8e00b2631686d54eab84b91f0aca1" };
		String[] cipherText = new String[] {
				"0336763e966d92595a567cc9ce537f5e",
				"a9a1631bf4996954ebc093957b234589",
				"ff4f8391a6a40ca5b25d23bedd44a597",
				"dc43be40be0e53712f7e2bf5ca707209",
				"92beedab1895a94faa69b632e5cc47ce",
				"459264f4798f6a78bacb89c15ed3d601",
				"08a4e2efec8a8e3312ca7460b9040bbf" };

		for (int i = 0; i < testinput.length; i++) {
			Aes enc = new Aes();
			Aes dec = new Aes();

			assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(enc, null_key,
					Aes.KEY_SIZE_128, null_iv, Aes.ENCRYPT_MODE));

			assertEquals(WolfCrypt.SUCCESS, Fips.AesSetKey_fips(dec, null_key,
					Aes.KEY_SIZE_128, null_iv, Aes.DECRYPT_MODE));

			byte[] input = Util.h2b(testinput[i]);
			byte[] output = new byte[Aes.BLOCK_SIZE];
			byte[] cipher = Util.h2b(cipherText[i]);
			byte[] plain = new byte[Aes.BLOCK_SIZE];

			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcEncrypt_fips(enc, output, input, Aes.BLOCK_SIZE));
			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesCbcDecrypt_fips(dec, plain, output, Aes.BLOCK_SIZE));

			assertArrayEquals(output, cipher);
			assertArrayEquals(plain, input);
		}
	}

	@Test
	public void gcmEncrypShouldMatchUsingByteByffer() {
		String[] keys = new String[] {
				"96f309d0f15ba970e114a9216e75a14f89e28948ce7d98bd37f0beefe36803b0",
				"3872431f89eba694cbc9b12d10d11b707a4248e7ff90a4bbcd271df7ff33c3a8",
				"aa36f0adfc3ad79db40d38afdc33bf571ea96eb7089663e554ac566c55e33dc1",
				"1f2d3edaaf6e24001bb69473a79dc16751c3dab75614f884a6da8f46e1f808b6",

				"513d69b62ccc6cb6b131e03492573629",
				"04dbdd3f6ebc283f37fe36de20e63698",
				"95941019ce0633ddaac39d68af55bf18",
				"e9035018a50f6d2cb214aa15eca13126",

				"f8c95f4a4f44f92016d20d4a8ee1b47f",
				"f77762d953ef07850ab8b3ea3dffa99c",
				"64d649c62c8de598147d9017d48b7d0c",
				"e9bbcbbad3a20de306849cd4181d1c21",

				"1efd683cd9a6e3fd068d00a2086428d9",
				"b53b39c72229968600981245c3902a5b",
				"33edf6422d6ee7a6f1a2c62c6aa80623",
				"50b9ab1a45cff2b4ac61acbb91748d81",

				"3ef0c62ba7b10cc6e0d01fc854c4609f",
				"8226a43fbfb627931ae9a3f0fff1eff6",
				"5bbc573d4321d87fe0fae055e51cd802",
				"e4028e15a43405906157983504cfe178" };

		String[] ivs = new String[] { "811c5a119f1970526314ef17",
				"b4d3d1fb3f2a55822c38c345", "8bff1992ae8cf8245eb04d0d",
				"021d039481a4712f38b72310",

				"a82cac133e4275214db28e23", "81829bce889b58e5699d1d30",
				"81d6e884204d1c2ffbbc5281", "6c40b2da03098cd8fae9d284",

				"d14e58a20ab9cfdb9c99c948", "babcba15888e47b4ae465fbb",
				"2c03617cc30ab9ad74e1625e", "b5a59cea040d1c5f847b8aa6",

				"502a695532b76998a07619e1", "b7e2fa5f3ff3c93d2b4520a3",
				"3d28f90d13864a877d6b28ab", "63d4165ec16f7ec664957685",

				"5c7ef507f57213c8b3bccd80", "298b3aa17bc1d522119801a0",
				"a754307e21bd8830bf8e0494", "1dd60ff9a9ff83e50b25c5a0" };
		String[] inputs = new String[] { "", "", "", "",

		"", "", "", "",

		"", "", "", "",

		"8e05e5f209b6d46825bd8e72184807d7", "b018e93ddedb38ffbf37418eb558d358",
				"96b670847652abf972d0c577cc6a13d4",
				"d0699f6f202211d31078265a5a590ae9",

				"8e611f5465a95e51ea994b423d308c52",
				"6adb192878975ce52b747039018af60b",
				"77302190044e1d3bcb8036c10fab4591",
				"3287a23fac53b1639dcda92c2aefe195" };
		String[] outputs = new String[] { "", "", "", "",

		"", "", "", "",

		"", "", "", "",

		"bb4141881dd0c0df656fdf6d6f916809", "1b99b39eabcdb1dd565fa6c653762eca",
				"fba1cdcdaaa30015ec73ad958bff8de5",
				"4d75780fb52c2210b2dce23e0a607961",

				"0d9a84e2d05a66fae22736f28e2b95af",
				"2376bc94980bd00b371fca9b577d6066",
				"8e8e0d23e5428e17f0dd5098aa8f8cf4",
				"04cf6283c6e07abb37dd2165b71fbc12" };
		String[] aads = new String[] { "", "", "", "",

		"", "", "", "",

		"014988a49cd6db5822c7747d44ce6984", "8aaec71a1a6f3ca115852da562bfe193",
				"0a9268d9f2a0fa55222c4189079c7853",
				"ba7b822fb592e4e07b7cdb848acb82c3",

				"", "", "", "",

				"1eebc1ba027aa7d50ea8b41ac32c4e30",
				"d2986fca8fae3099a23a00460e92ab69",
				"00a9374ccaa5daf1377b7baf24ca6b5e",
				"e7cd6994591b7e01ecc0c238becc5922", };
		String[] tags = new String[] { "0721bfff18ffd1d609dc20e098fa70a7",
				"0d58d2774c552fc03cb45b580b4d3c8a",
				"01956880ce3e7b3bdbab6d9fbb691e41",
				"ed074dc1d766f54ddbaddce9c63f1212",

				"6242db189f62e0ae57954c6885c07b94",
				"b094a8f4583d41dd1eb6ae6701bb1017",
				"a1be2cb5bc80569ff4168112315b24d9",
				"1d11b3eaf1e8606d1d0577e0c8867e9f",

				"82c81a197a76807b3ea6edce89c39027",
				"20e124243540872d6adc4aef5415fcf4",
				"a3f9767e82f8427fc45af8337938967d",
				"75ce87c22470d988c7dd9ed9261a6091",

				"36918c3eb5361630b688cb8c01f8503f",
				"a940164de93740514e4d55a1ed94989c",
				"518e12768a606656f82e59d44e72e0da",
				"2d0234814f68f2190335df7974a99959",

				"954391c2a4c0dd61ed04ef1c81c3f137",
				"c3b76f298cffa0357122492e26beec49",
				"75e96073645aca257413f333f2de1e1d",
				"87e193b79faf3757ccb0ff1396df5e81" };

		for (int i = 0; i < keys.length; i++) {
			Aes enc = new Aes();

			key.put(Util.h2b(keys[i])).rewind();
			iv.put(Util.h2b(ivs[i])).rewind();
			input.put(Util.h2b(inputs[i])).rewind();
			output.put(Util.h2b(outputs[i])).rewind();
			aad.put(Util.h2b(aads[i])).rewind();
			expected.put(Util.h2b(tags[i])).rewind();

			assertEquals(WolfCrypt.SUCCESS,
					Fips.AesGcmSetKey_fips(enc, key, keys[i].length() / 2));

			assertEquals(WolfCrypt.SUCCESS, Fips.AesGcmEncrypt_fips(enc,
					cipher, input, inputs[i].length() / 2, iv,
					ivs[i].length() / 2, tag, tags[i].length() / 2, aad,
					aads[i].length() / 2));

			assertEquals(expected, tag);
			assertEquals(output, cipher);
		}
	}
}
