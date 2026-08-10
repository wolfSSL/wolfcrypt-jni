/* DhFipsTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
import java.util.Arrays;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.Util;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class DhFipsTest extends FipsTest {

    /* 2048-bit DH prime p, generator g is 2 */
    private static final String DH_P_2048_HEX =
        "8E7EC04F98E157D62585624B5283FFD8D33B5EC35F0812FE79227319974A3517" +
        "6F858116030A97494618413BB82E87BBCFF26A24DF32CAEEF40BE3FBBC18C709" +
        "A167423BEE8C84539B0FADEBD305039AA800C3AA4A4E3C6B775FAD8E11E30FF9" +
        "B1E1CA138C9DC9947751A5EE935AC54BB4B045D0CE6BA1AB4D40701D62F4990E" +
        "A1CB9783CC3769171C8FFDC1AE7A10EC1C82AF9240B67CC667A00F70F2FE9B3B" +
        "4BDABE25EB42FBEC5533E53A4BA5B60B32B7CBF326D42F620757A11C554B91DF" +
        "C67B54403807E1A228B858B8D2614BF9D0E08B840F5CA95BA0ADDD641F2481B9" +
        "0A7C47583D2F14E9C3A5C80440E74B7AA41BBD71025B9F754F424BF382BB5817";

    /* DER group parameters for the prime above, SEQUENCE of
     * INTEGER p and INTEGER g */
    private static final String DH_PARAMS_DER_HEX =
        "30820108" + "0282010100" + DH_P_2048_HEX + "020102";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to skip tests when native wolfSSL is built without DH */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule dhAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    Assume.assumeTrue("DH not compiled in native wolfSSL",
                        FeatureDetect.DhEnabled());
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI FIPS DH Tests");

        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }

    @Test
    public void GenerateKeyPairAndAgreeUsingByteArray() {
        byte[] p = Util.h2b(DH_P_2048_HEX);
        byte[] g = Util.h2b("02");
        Dh alice = new Dh();
        Dh bob = new Dh();
        Rng rng = new Rng();

        byte[] alicePriv = new byte[256];
        byte[] alicePub = new byte[256];
        byte[] bobPriv = new byte[256];
        byte[] bobPub = new byte[256];
        long[] alicePrivSz = { alicePriv.length };
        long[] alicePubSz = { alicePub.length };
        long[] bobPrivSz = { bobPriv.length };
        long[] bobPubSz = { bobPub.length };

        byte[] aliceSecret = new byte[256];
        byte[] bobSecret = new byte[256];
        long[] aliceSecretSz = { aliceSecret.length };
        long[] bobSecretSz = { bobSecret.length };

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));

        Fips.InitDhKey(alice);
        Fips.InitDhKey(bob);

        assertEquals(WolfCrypt.SUCCESS,
            Fips.DhSetKey(alice, p, p.length, g, g.length));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.DhSetKey(bob, p, p.length, g, g.length));

        assertEquals(WolfCrypt.SUCCESS, Fips.DhGenerateKeyPair(alice, rng,
            alicePriv, alicePrivSz, alicePub, alicePubSz));
        assertTrue(alicePrivSz[0] > 0 && alicePrivSz[0] <= alicePriv.length);
        assertTrue(alicePubSz[0] > 0 && alicePubSz[0] <= alicePub.length);

        assertEquals(WolfCrypt.SUCCESS, Fips.DhGenerateKeyPair(bob, rng,
            bobPriv, bobPrivSz, bobPub, bobPubSz));
        assertTrue(bobPrivSz[0] > 0 && bobPrivSz[0] <= bobPriv.length);
        assertTrue(bobPubSz[0] > 0 && bobPubSz[0] <= bobPub.length);

        assertEquals(WolfCrypt.SUCCESS, Fips.DhAgree(alice, aliceSecret,
            aliceSecretSz, alicePriv, alicePrivSz[0], bobPub, bobPubSz[0]));
        assertEquals(WolfCrypt.SUCCESS, Fips.DhAgree(bob, bobSecret,
            bobSecretSz, bobPriv, bobPrivSz[0], alicePub, alicePubSz[0]));

        assertTrue(aliceSecretSz[0] > 0);
        assertEquals(aliceSecretSz[0], bobSecretSz[0]);
        assertArrayEquals(
            Arrays.copyOf(aliceSecret, (int)aliceSecretSz[0]),
            Arrays.copyOf(bobSecret, (int)bobSecretSz[0]));

        Fips.FreeDhKey(alice);
        Fips.FreeDhKey(bob);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void GenerateKeyPairAndAgreeUsingByteBuffer() {
        byte[] p = Util.h2b(DH_P_2048_HEX);
        byte[] g = Util.h2b("02");
        Dh alice = new Dh();
        Dh bob = new Dh();
        Rng rng = new Rng();

        ByteBuffer alicePriv = ByteBuffer.allocateDirect(256);
        ByteBuffer alicePub = ByteBuffer.allocateDirect(256);
        ByteBuffer bobPriv = ByteBuffer.allocateDirect(256);
        ByteBuffer bobPub = ByteBuffer.allocateDirect(256);
        long[] alicePrivSz = { alicePriv.capacity() };
        long[] alicePubSz = { alicePub.capacity() };
        long[] bobPrivSz = { bobPriv.capacity() };
        long[] bobPubSz = { bobPub.capacity() };

        ByteBuffer aliceSecret = ByteBuffer.allocateDirect(256);
        ByteBuffer bobSecret = ByteBuffer.allocateDirect(256);
        long[] aliceSecretSz = { aliceSecret.capacity() };
        long[] bobSecretSz = { bobSecret.capacity() };

        byte[] aliceSecretBytes = null;
        byte[] bobSecretBytes = null;

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));

        Fips.InitDhKey(alice);
        Fips.InitDhKey(bob);

        assertEquals(WolfCrypt.SUCCESS,
            Fips.DhSetKey(alice, p, p.length, g, g.length));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.DhSetKey(bob, p, p.length, g, g.length));

        assertEquals(WolfCrypt.SUCCESS, Fips.DhGenerateKeyPair(alice, rng,
            alicePriv, alicePrivSz, alicePub, alicePubSz));
        assertTrue(alicePrivSz[0] > 0 &&
            alicePrivSz[0] <= alicePriv.capacity());
        assertTrue(alicePubSz[0] > 0 && alicePubSz[0] <= alicePub.capacity());

        assertEquals(WolfCrypt.SUCCESS, Fips.DhGenerateKeyPair(bob, rng,
            bobPriv, bobPrivSz, bobPub, bobPubSz));
        assertTrue(bobPrivSz[0] > 0 && bobPrivSz[0] <= bobPriv.capacity());
        assertTrue(bobPubSz[0] > 0 && bobPubSz[0] <= bobPub.capacity());

        assertEquals(WolfCrypt.SUCCESS, Fips.DhAgree(alice, aliceSecret,
            aliceSecretSz, alicePriv, alicePrivSz[0], bobPub, bobPubSz[0]));
        assertEquals(WolfCrypt.SUCCESS, Fips.DhAgree(bob, bobSecret,
            bobSecretSz, bobPriv, bobPrivSz[0], alicePub, alicePubSz[0]));

        assertTrue(aliceSecretSz[0] > 0);
        assertEquals(aliceSecretSz[0], bobSecretSz[0]);

        aliceSecretBytes = new byte[(int)aliceSecretSz[0]];
        bobSecretBytes = new byte[(int)bobSecretSz[0]];
        aliceSecret.get(aliceSecretBytes);
        bobSecret.get(bobSecretBytes);
        assertArrayEquals(aliceSecretBytes, bobSecretBytes);

        Fips.FreeDhKey(alice);
        Fips.FreeDhKey(bob);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void ParamsLoadUsingByteArray() {
        byte[] params = Util.h2b(DH_PARAMS_DER_HEX);
        byte[] p = new byte[256];
        byte[] g = new byte[4];
        long[] pSz = { p.length };
        long[] gSz = { g.length };

        assertEquals(WolfCrypt.SUCCESS,
            Fips.DhParamsLoad(params, params.length, p, pSz, g, gSz));

        assertEquals(256, pSz[0]);
        assertEquals(1, gSz[0]);
        assertArrayEquals(Util.h2b(DH_P_2048_HEX), p);
        assertEquals(0x02, g[0]);
    }

    @Test
    public void ParamsLoadUsingByteBuffer() {
        ByteBuffer params = ByteBuffer.allocateDirect(512);
        ByteBuffer p = ByteBuffer.allocateDirect(256);
        ByteBuffer g = ByteBuffer.allocateDirect(4);
        long[] pSz = { p.capacity() };
        long[] gSz = { g.capacity() };

        byte[] pBytes = new byte[256];

        params.put(Util.h2b(DH_PARAMS_DER_HEX));
        params.limit(params.position());
        params.rewind();

        assertEquals(WolfCrypt.SUCCESS, Fips.DhParamsLoad(params,
            params.remaining(), p, pSz, g, gSz));

        assertEquals(256, pSz[0]);
        assertEquals(1, gSz[0]);

        p.get(pBytes);
        assertArrayEquals(Util.h2b(DH_P_2048_HEX), pBytes);
        assertEquals(0x02, g.get(0));
    }

    @Test
    public void KeyDecodeBadInputUsingByteArray() {
        Dh key = new Dh();
        long[] idx = { 0 };

        /* not a DER sequence */
        byte[] badKey = Util.h2b("0102030405060708");

        Fips.InitDhKey(key);

        assertTrue(Fips.DhKeyDecode(badKey, idx, key, badKey.length) < 0);

        Fips.FreeDhKey(key);
    }

    @Test
    public void KeyDecodeBadInputUsingByteBuffer() {
        Dh key = new Dh();
        long[] idx = { 0 };
        ByteBuffer badKey = ByteBuffer.allocateDirect(8);

        /* not a DER sequence */
        badKey.put(Util.h2b("0102030405060708"));
        badKey.rewind();

        Fips.InitDhKey(key);

        assertTrue(Fips.DhKeyDecode(badKey, idx, key,
            badKey.remaining()) < 0);

        Fips.FreeDhKey(key);
    }
}
