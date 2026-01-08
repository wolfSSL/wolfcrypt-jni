/* FipsStatusTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.wolfcrypt.test.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Fips.ErrorCallback;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class FipsStatusTest extends FipsTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI FIPS Status Tests");
    }

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
        String coreHash = Fips.wolfCrypt_GetCoreHash_fips();
        if (coreHash != null) {
            System.out.println("\tFIPS core hash: " + coreHash);
        }
        else {
            System.out.println("\tFIPS core hash was null");
        }
    }
}
