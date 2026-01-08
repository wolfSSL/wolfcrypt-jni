/* Sha256FipsTest.java
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

import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.Util;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class Sha256FipsTest extends FipsTest {
    private ByteBuffer data = ByteBuffer.allocateDirect(32);
    private ByteBuffer result = ByteBuffer.allocateDirect(Sha256.DIGEST_SIZE);
    private ByteBuffer expected = ByteBuffer.allocateDirect(Sha256.DIGEST_SIZE);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI FIPS SHA2-256 Tests");
    }

    @Test
    public void initShouldReturnZero() {
        assertEquals(WolfCrypt.SUCCESS, Fips.InitSha256_fips(new Sha256()));
    }

    @Test
    public void hashShouldMatchUsingByteBuffer() {
        String[] dataVector = new String[] { "", "8bf43fbc59b1cefb",
                "68596a39b6b1dbbce92983d0c87811f9",
                "695f0bcfd8b1799a7519c182c55baaffe66a664ac5d06ad7",
                "b9c325ed83e582d315a03d191d3a99c5178d1a1dc4aa9669d8c28ffaf347c06b" };
        String[] hashVector = new String[] {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "47291036995e041cd53d640190002ab9b56fec8faf647a8df3b278fe445ab05e",
                "041f246778af35809a4e8d06d41ba3e3c73f54050149d13e821e5ca45178e88b",
                "afa01304f7356d5d946304c7aef0c5190716eeacee6a837edd431906aa50e5ec",
                "731cf20719a0838dc15a33293ad977855bd28f5d2c768e7c0b632bf65d6c84e0" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha256 sha = new Sha256();

            data.put(Util.h2b(dataVector[i])).rewind();
            expected.put(Util.h2b(hashVector[i])).rewind();

            assertEquals(WolfCrypt.SUCCESS, Fips.InitSha256_fips(sha));

            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Update_fips(sha, data,
                    dataVector[i].length() / 2));

            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Final_fips(sha, result));

            assertEquals(expected, result);
        }
    }

    @Test
    public void hashShouldMatchUsingByteArray() {
        String[] dataVector = new String[] { "", "8bf43fbc59b1cefb",
                "68596a39b6b1dbbce92983d0c87811f9",
                "695f0bcfd8b1799a7519c182c55baaffe66a664ac5d06ad7",
                "b9c325ed83e582d315a03d191d3a99c5178d1a1dc4aa9669d8c28ffaf347c06b" };
        String[] hashVector = new String[] {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "47291036995e041cd53d640190002ab9b56fec8faf647a8df3b278fe445ab05e",
                "041f246778af35809a4e8d06d41ba3e3c73f54050149d13e821e5ca45178e88b",
                "afa01304f7356d5d946304c7aef0c5190716eeacee6a837edd431906aa50e5ec",
                "731cf20719a0838dc15a33293ad977855bd28f5d2c768e7c0b632bf65d6c84e0" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha256 sha = new Sha256();

            byte[] data     = Util.h2b(dataVector[i]);
            byte[] result   = new byte[Sha256.DIGEST_SIZE];
            byte[] expected = Util.h2b(hashVector[i]);

            assertEquals(WolfCrypt.SUCCESS, Fips.InitSha256_fips(sha));

            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Update_fips(sha, data,
                    dataVector[i].length() / 2));

            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Final_fips(sha, result));

            assertArrayEquals(expected, result);
        }
    }
}
