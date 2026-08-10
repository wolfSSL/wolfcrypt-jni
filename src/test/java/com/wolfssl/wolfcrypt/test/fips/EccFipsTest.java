/* EccFipsTest.java
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

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class EccFipsTest extends FipsTest {

    /* P-256 key size in bytes */
    private static final int ECC_KEY_SIZE = 32;

    /* uncompressed x963 export size for P-256, 1 + 32 + 32 */
    private static final int ECC_X963_SIZE = 65;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to skip tests when native wolfSSL is built without ECC */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule eccAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    Assume.assumeTrue("ECC not compiled in native wolfSSL",
                        FeatureDetect.EccEnabled());
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI FIPS ECC Tests");

        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }

    /* setRng is not compiled in for FIPS v2 or selftest bundles, where
     * ECC operations do not use an associated RNG */
    private static void setKeyRng(Ecc key, Rng rng) {
        try {
            key.setRng(rng);
        } catch (WolfCryptException e) {
            if (e.getError() != WolfCryptError.NOT_COMPILED_IN) {
                throw e;
            }
        }
    }

    @Test
    public void SharedSecretShouldMatchUsingByteArray() {
        Ecc alice = new Ecc();
        Ecc bob = new Ecc();
        Rng rng = new Rng();

        byte[] aliceSecret = new byte[64];
        byte[] bobSecret = new byte[64];
        long[] aliceSecretSz = { aliceSecret.length };
        long[] bobSecretSz = { bobSecret.length };

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(alice));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(bob));

        setKeyRng(alice, rng);
        setKeyRng(bob, rng);

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, alice));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, bob));

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_shared_secret(alice, bob, aliceSecret, aliceSecretSz));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_shared_secret(bob, alice, bobSecret, bobSecretSz));

        assertEquals(ECC_KEY_SIZE, aliceSecretSz[0]);
        assertEquals(ECC_KEY_SIZE, bobSecretSz[0]);
        assertArrayEquals(Arrays.copyOf(aliceSecret, (int)aliceSecretSz[0]),
            Arrays.copyOf(bobSecret, (int)bobSecretSz[0]));

        Fips.ecc_free(alice);
        Fips.ecc_free(bob);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void SharedSecretShouldMatchUsingByteBuffer() {
        Ecc alice = new Ecc();
        Ecc bob = new Ecc();
        Rng rng = new Rng();

        ByteBuffer aliceSecret = ByteBuffer.allocateDirect(64);
        ByteBuffer bobSecret = ByteBuffer.allocateDirect(64);
        long[] aliceSecretSz = { aliceSecret.capacity() };
        long[] bobSecretSz = { bobSecret.capacity() };

        byte[] aliceSecretBytes = null;
        byte[] bobSecretBytes = null;

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(alice));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(bob));

        setKeyRng(alice, rng);
        setKeyRng(bob, rng);

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, alice));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, bob));

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_shared_secret(alice, bob, aliceSecret, aliceSecretSz));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_shared_secret(bob, alice, bobSecret, bobSecretSz));

        assertEquals(ECC_KEY_SIZE, aliceSecretSz[0]);
        assertEquals(ECC_KEY_SIZE, bobSecretSz[0]);

        aliceSecretBytes = new byte[(int)aliceSecretSz[0]];
        bobSecretBytes = new byte[(int)bobSecretSz[0]];
        aliceSecret.get(aliceSecretBytes);
        bobSecret.get(bobSecretBytes);
        assertArrayEquals(aliceSecretBytes, bobSecretBytes);

        Fips.ecc_free(alice);
        Fips.ecc_free(bob);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void ExportImportX963UsingByteArray() {
        Ecc alice = new Ecc();
        Ecc bob = new Ecc();
        Ecc alicePub = new Ecc();
        Rng rng = new Rng();

        byte[] exported = new byte[128];
        long[] exportedSz = { exported.length };

        byte[] secretFromKey = new byte[64];
        byte[] secretFromImport = new byte[64];
        long[] secretFromKeySz = { secretFromKey.length };
        long[] secretFromImportSz = { secretFromImport.length };

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(alice));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(bob));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(alicePub));

        setKeyRng(bob, rng);

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, alice));
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, bob));

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_export_x963(alice, exported, exportedSz));
        assertEquals(ECC_X963_SIZE, exportedSz[0]);

        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_import_x963(
            Arrays.copyOf(exported, (int)exportedSz[0]), exportedSz[0],
            alicePub));

        /* secret from the imported public key must match the one from
         * the original key */
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_shared_secret(bob, alice,
            secretFromKey, secretFromKeySz));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_shared_secret(bob, alicePub,
            secretFromImport, secretFromImportSz));

        assertEquals(secretFromKeySz[0], secretFromImportSz[0]);
        assertArrayEquals(Arrays.copyOf(secretFromKey, (int)secretFromKeySz[0]),
            Arrays.copyOf(secretFromImport, (int)secretFromImportSz[0]));

        Fips.ecc_free(alice);
        Fips.ecc_free(bob);
        Fips.ecc_free(alicePub);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void ExportX963UsingByteBuffer() {
        Ecc alice = new Ecc();
        Rng rng = new Rng();

        ByteBuffer exportedBuf = ByteBuffer.allocateDirect(128);
        long[] exportedBufSz = { exportedBuf.capacity() };

        byte[] exportedArr = new byte[128];
        long[] exportedArrSz = { exportedArr.length };

        byte[] exportedBufBytes = null;

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.ecc_init(alice));

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_make_key(rng, ECC_KEY_SIZE, alice));

        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_export_x963(alice, exportedBuf, exportedBufSz));
        assertEquals(ECC_X963_SIZE, exportedBufSz[0]);

        /* both overloads must export the same bytes */
        assertEquals(WolfCrypt.SUCCESS,
            Fips.ecc_export_x963(alice, exportedArr, exportedArrSz));
        assertEquals(exportedArrSz[0], exportedBufSz[0]);

        exportedBufBytes = new byte[(int)exportedBufSz[0]];
        exportedBuf.get(exportedBufBytes);
        assertArrayEquals(Arrays.copyOf(exportedArr, (int)exportedArrSz[0]),
            exportedBufBytes);

        Fips.ecc_free(alice);
        Fips.FreeRng_fips(rng);
    }
}
