package com.wolfssl.wolfcrypt.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Fips.ErrorCallback;

public class FipsTest {
	@Test
	public void wolfCrypt_GetStatus_fipsShouldReturnZero() {
		assertEquals(WolfCrypt.SUCCESS, Fips.wolfCrypt_GetStatus_fips());
	}

	@Test
	public void wolfCrypt_SetStatus_fipsShouldReturnZero() {
		assertEquals(WolfCryptError.NOT_COMPILED_IN.getCode(),
				Fips.wolfCrypt_SetStatus_fips(WolfCryptError.DRBG_CONT_FIPS_E
						.getCode()));
	}

	public class MyCallback implements ErrorCallback {
		@Override
		public void errorCallback(int ok, int err, String hash) {
			System.out.println("in my Fips callback, ok =" + ok + " err = "
					+ err);
			System.out.println("hash = " + hash);

			if (err == -203) {
				System.out
						.println("In core integrity hash check failure, copy above hash");
				System.out
						.println("into verifyCore[] in fips_test.c and rebuild");
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
