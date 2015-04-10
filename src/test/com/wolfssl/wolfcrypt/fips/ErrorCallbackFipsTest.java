package com.wolfssl.wolfcrypt.fips;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Fips.ErrorCallback;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Fips;

public class ErrorCallbackFipsTest {

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

		Fips.setErrorCallback(callback);

		Fips.AesSetKey_fips(new Aes(),
				ByteBuffer.allocateDirect(Aes.KEY_SIZE_256), Aes.KEY_SIZE_128,
				null, Aes.ENCRYPT_MODE);
	}
}
