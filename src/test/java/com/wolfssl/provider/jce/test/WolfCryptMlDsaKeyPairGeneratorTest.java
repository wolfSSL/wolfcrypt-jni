/* WolfCryptMlDsaKeyPairGeneratorTest.java
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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import com.wolfssl.provider.jce.WolfCryptMlDsaPrivateKey;
import com.wolfssl.provider.jce.WolfCryptMlDsaPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfPQCParameterSpec;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for ML-DSA KeyPairGenerator service.
 */
public class WolfCryptMlDsaKeyPairGeneratorTest {

    private static boolean mlDsaEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptMlDsaKeyPairGeneratorTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            new MlDsa(MlDsa.ML_DSA_44);
            mlDsaEnabled = true;
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("ML-DSA test skipped: NOT_COMPILED_IN");
                return;
            }
            throw e;
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-DSA not compiled in", mlDsaEnabled);
    }

    @Test
    public void getInstanceForAllAliases() throws Exception {

        assumeEnabled();

        KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        KeyPairGenerator.getInstance("ML-DSA-44", "wolfJCE");
        KeyPairGenerator.getInstance("ML-DSA-65", "wolfJCE");
        KeyPairGenerator.getInstance("ML-DSA-87", "wolfJCE");
        KeyPairGenerator.getInstance("2.16.840.1.101.3.4.3.17", "wolfJCE");
        KeyPairGenerator.getInstance("2.16.840.1.101.3.4.3.18", "wolfJCE");
        KeyPairGenerator.getInstance("2.16.840.1.101.3.4.3.19", "wolfJCE");
    }

    @Test
    public void genericDefaultsToMlDsa65() throws Exception {

        assumeEnabled();

        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA", "wolfJCE")
            .generateKeyPair();
        assertEquals(MlDsa.ML_DSA_65,
            ((WolfCryptMlDsaPublicKey) kp.getPublic()).getLevel());
    }

    @Test
    public void genericGeneratesAllLevelsViaWolfPqcSpec() throws Exception {

        assumeEnabled();

        for (WolfPQCParameterSpec spec : new WolfPQCParameterSpec[] {
                WolfPQCParameterSpec.ML_DSA_44,
                WolfPQCParameterSpec.ML_DSA_65,
                WolfPQCParameterSpec.ML_DSA_87 }) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
            kpg.initialize(spec);
            KeyPair kp = kpg.generateKeyPair();

            int expected =
                spec == WolfPQCParameterSpec.ML_DSA_44 ? MlDsa.ML_DSA_44 :
                spec == WolfPQCParameterSpec.ML_DSA_65 ? MlDsa.ML_DSA_65 :
                                                         MlDsa.ML_DSA_87;
            assertEquals(spec.getName(), expected,
                ((WolfCryptMlDsaPublicKey) kp.getPublic()).getLevel());
        }
    }

    @Test
    public void genericAcceptsStandardNamedParameterSpec() throws Exception {

        assumeEnabled();

        Class<?> npsCls;
        try {
            npsCls = Class.forName("java.security.spec.NamedParameterSpec");
        } catch (ClassNotFoundException e) {
            Assume.assumeNoException(e);
            return;
        }

        AlgorithmParameterSpec nps44 = (AlgorithmParameterSpec)
            npsCls.getConstructor(String.class).newInstance("ML-DSA-44");

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        kpg.initialize(nps44);
        KeyPair kp = kpg.generateKeyPair();
        assertEquals(MlDsa.ML_DSA_44,
            ((WolfCryptMlDsaPublicKey) kp.getPublic()).getLevel());
    }

    @Test
    public void perLevelGeneratorsLockLevelWithoutInit() throws Exception {

        assumeEnabled();

        for (int[] pair : new int[][] {
                { MlDsa.ML_DSA_44, 0 }, /* second is index, ignored */
                { MlDsa.ML_DSA_65, 0 },
                { MlDsa.ML_DSA_87, 0 } }) {
            String name =
                pair[0] == MlDsa.ML_DSA_44 ? "ML-DSA-44" :
                pair[0] == MlDsa.ML_DSA_65 ? "ML-DSA-65" : "ML-DSA-87";
            KeyPair kp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();
            assertEquals(name, pair[0],
                ((WolfCryptMlDsaPublicKey) kp.getPublic()).getLevel());
        }
    }

    @Test
    public void perLevelAcceptsMatchingSpec() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA-44", "wolfJCE");
        kpg.initialize(WolfPQCParameterSpec.ML_DSA_44);
        KeyPair kp = kpg.generateKeyPair();
        assertEquals(MlDsa.ML_DSA_44,
            ((WolfCryptMlDsaPrivateKey) kp.getPrivate()).getLevel());
    }

    @Test
    public void perLevelRejectsMismatchingSpec() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA-44", "wolfJCE");
        try {
            kpg.initialize(WolfPQCParameterSpec.ML_DSA_87);
            fail("expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException expected) {
            /* OK */
        }
    }

    @Test
    public void initializeIntKeysizeRejected() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        try {
            kpg.initialize(2048);
            fail("expected InvalidParameterException");
        } catch (InvalidParameterException expected) {
            /* OK */
        }
    }

    @Test
    public void initializeNullSpecRejected() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        try {
            kpg.initialize((AlgorithmParameterSpec) null);
            fail("expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException expected) {
            /* OK */
        }
    }

    @Test
    public void initializeUnsupportedSpecRejected() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        try {
            kpg.initialize(new RSAKeyGenParameterSpec(2048,
                BigInteger.valueOf(65537)));
            fail("expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException expected) {
            /* OK */
        }
    }

    @Test
    public void initializeUnknownNameRejected() throws Exception {

        assumeEnabled();

        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("ML-DSA", "wolfJCE");
        try {
            kpg.initialize(new WolfPQCParameterSpec("ML-DSA-99"));
            fail("expected InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException expected) {
            /* OK */
        }
    }
}
