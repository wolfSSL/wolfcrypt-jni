/* WolfCryptSlhDsaKeyPairGeneratorTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfPQCParameterSpec;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for the SLH-DSA KeyPairGenerator service.
 */
public class WolfCryptSlhDsaKeyPairGeneratorTest {

    /* All 12 FIPS 205 parameter set service names. */
    private static final String[] PARAM_NAMES = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };

    /* Parameter set IDs, same order as PARAM_NAMES */
    private static final int[] PARAM_IDS = {
        SlhDsa.SLH_DSA_SHA2_128S,  SlhDsa.SLH_DSA_SHA2_128F,
        SlhDsa.SLH_DSA_SHA2_192S,  SlhDsa.SLH_DSA_SHA2_192F,
        SlhDsa.SLH_DSA_SHA2_256S,  SlhDsa.SLH_DSA_SHA2_256F,
        SlhDsa.SLH_DSA_SHAKE_128S, SlhDsa.SLH_DSA_SHAKE_128F,
        SlhDsa.SLH_DSA_SHAKE_192S, SlhDsa.SLH_DSA_SHAKE_192F,
        SlhDsa.SLH_DSA_SHAKE_256S, SlhDsa.SLH_DSA_SHAKE_256F
    };

    /* Fast-signing sets used for the keygen round trips. */
    private static final String[] FAST_NAMES = {
        "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"
    };

    private static boolean slhDsaEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptSlhDsaKeyPairGeneratorTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* Gate on keygen support, KeyPairGenerator.SLH-DSA services are
         * not registered on verify-only native builds. */
        slhDsaEnabled = FeatureDetect.SlhDsaKeyGenEnabled();
        if (!slhDsaEnabled) {
            System.out.println("SLH-DSA keygen test skipped: " +
                "NOT_COMPILED_IN");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("SLH-DSA keygen not compiled in", slhDsaEnabled);
    }

    private static boolean available(String name) {
        try {
            KeyPairGenerator.getInstance(name, "wolfJCE").generateKeyPair();
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    @Test
    public void getInstanceForAllNames() throws Exception {
        assumeEnabled();

        /* Umbrella generator defaults to SHA2-128f, only registered when
         * that parameter set is compiled into native wolfSSL */
        if (FeatureDetect.SlhDsaParamEnabled(SlhDsa.SLH_DSA_SHA2_128F)) {
            KeyPairGenerator.getInstance("SLH-DSA", "wolfJCE");
        }

        /* Per-set services and OID aliases (.20 - .31) are registered
         * only for parameter sets compiled into native wolfSSL */
        for (int i = 0; i < PARAM_NAMES.length; i++) {
            String oid = "2.16.840.1.101.3.4.3." + (20 + i);

            if (FeatureDetect.SlhDsaParamEnabled(PARAM_IDS[i])) {
                KeyPairGenerator.getInstance(PARAM_NAMES[i], "wolfJCE");
                KeyPairGenerator.getInstance(oid, "wolfJCE");
            }
            else {
                for (String alg : new String[] { PARAM_NAMES[i], oid }) {
                    try {
                        KeyPairGenerator.getInstance(alg, "wolfJCE");
                        fail(alg + " not compiled into native wolfSSL, " +
                            "should not be registered");
                    } catch (NoSuchAlgorithmException e) {
                        /* expected */
                    }
                }
            }
        }
    }

    @Test
    public void umbrellaDefaultsToSha2128f() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair kp = KeyPairGenerator.getInstance("SLH-DSA", "wolfJCE")
            .generateKeyPair();
        assertNotNull(kp);
        assertEquals("SLH-DSA", kp.getPublic().getAlgorithm());

        /* The umbrella default must encode as the SHA2-128f OID (.21). The
         * SubjectPublicKeyInfo carries the parameter-set OID. */
        byte[] spki = kp.getPublic().getEncoded();
        int param = SlhDsa.parseAndValidateSlhDsaPublicKeyDer(spki);
        assertEquals(SlhDsa.SLH_DSA_SHA2_128F, param);
    }

    @Test
    public void perSetKeygenRoundTrip() throws Exception {
        assumeEnabled();

        for (String n : FAST_NAMES) {
            if (!available(n)) {
                continue;
            }
            KeyPair kp = KeyPairGenerator.getInstance(n, "wolfJCE")
                .generateKeyPair();
            assertNotNull(kp);
            assertEquals("SLH-DSA", kp.getPublic().getAlgorithm());
            assertEquals("SLH-DSA", kp.getPrivate().getAlgorithm());
            assertEquals("X.509", kp.getPublic().getFormat());
            assertEquals("PKCS#8", kp.getPrivate().getFormat());
        }
    }

    @Test
    public void initializeWithIntKeySizeRejected() throws Exception {
        assumeEnabled();

        /* Umbrella generator is only registered when its SHA2-128f
         * default parameter set is compiled into native wolfSSL */
        Assume.assumeTrue("SLH-DSA-SHA2-128f not compiled in",
            FeatureDetect.SlhDsaParamEnabled(SlhDsa.SLH_DSA_SHA2_128F));

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("SLH-DSA", "wolfJCE");

        try {
            kpg.initialize(2048);
            fail("expected InvalidParameterException for integer key size");
        } catch (InvalidParameterException e) {
            /* expected, SLH-DSA has no integer key sizes */
        }
    }

    @Test
    public void perSetGeneratorLocksParam() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHAKE-128f"));

        /* A per-set generator must not be re-pointed at a different set. */
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("SLH-DSA-SHAKE-128f", "wolfJCE");

        try {
            kpg.initialize(WolfPQCParameterSpec.SLH_DSA_SHA2_256S);
            fail("expected InvalidAlgorithmParameterException for " +
                "set mismatch");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
    }
}
