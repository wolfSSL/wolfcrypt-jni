/* WolfCryptMlKemKeyPairGeneratorTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;

import java.security.Security;
import java.security.Provider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.InvalidParameterException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfPQCParameterSpec;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit tests for the wolfJCE ML-KEM KeyPairGenerator support.
 */
public class WolfCryptMlKemKeyPairGeneratorTest {

    private static boolean mlKemEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptMlKemKeyPairGeneratorTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        if (p != null && p.getService("KeyPairGenerator", "ML-KEM") != null) {
            mlKemEnabled = true;
        }
        else {
            System.out.println("ML-KEM KeyPairGenerator test skipped");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-KEM not compiled in", mlKemEnabled);
    }

    @Test
    public void testNamedGenerators() throws Exception {
        assumeEnabled();

        String[] names = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

        for (String name : names) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance(name, "wolfJCE");
            KeyPair kp = kpg.generateKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            assertEquals("ML-KEM", pub.getAlgorithm());
            assertEquals("ML-KEM", priv.getAlgorithm());
            assertEquals("X.509", pub.getFormat());
            assertEquals("PKCS#8", priv.getFormat());
            assertNotNull(pub.getEncoded());
            assertNotNull(priv.getEncoded());
            assertTrue(pub.getEncoded().length > 0);
            assertTrue(priv.getEncoded().length > 0);
        }
    }

    @Test
    public void testFamilyGeneratorWithParamSpec() throws Exception {
        assumeEnabled();

        WolfPQCParameterSpec[] specs = {
            WolfPQCParameterSpec.ML_KEM_512,
            WolfPQCParameterSpec.ML_KEM_768,
            WolfPQCParameterSpec.ML_KEM_1024
        };

        for (WolfPQCParameterSpec spec : specs) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-KEM", "wolfJCE");
            kpg.initialize(spec);
            KeyPair kp = kpg.generateKeyPair();
            assertEquals("ML-KEM", kp.getPublic().getAlgorithm());
            assertNotNull(kp.getPublic().getEncoded());
        }
    }

    @Test
    public void testInitializeWithIntKeySizeRejected() throws Exception {
        assumeEnabled();

        /* ML-KEM is selected by a named parameter set, not an integer key
         * size, matching the JDK reference implementation (and the wolfJCE
         * ML-DSA behavior). initialize(int) must be rejected for all
         * sizes. */
        int[] sizes = { 512, 768, 1024, 999 };
        for (int size : sizes) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-KEM", "wolfJCE");
            try {
                kpg.initialize(size);
                fail("Expected InvalidParameterException for initialize(" +
                    size + ")");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testDefaultFamilyIsMlKem768() throws Exception {
        assumeEnabled();

        /* Default ML-KEM (no initialize) should match ML-KEM-768 output
         * size, matching the JDK reference implementation default. */
        KeyPairGenerator kpgDefault =
            KeyPairGenerator.getInstance("ML-KEM", "wolfJCE");
        KeyPair def = kpgDefault.generateKeyPair();

        KeyPairGenerator kpg768 =
            KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE");
        KeyPair k768 = kpg768.generateKeyPair();

        assertEquals(k768.getPublic().getEncoded().length,
            def.getPublic().getEncoded().length);
    }

    @Test
    public void testLevelGeneratorsProduceDistinctSizes() throws Exception {
        assumeEnabled();

        int len512 = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
            .generateKeyPair().getPublic().getEncoded().length;
        int len768 = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair().getPublic().getEncoded().length;
        int len1024 = KeyPairGenerator.getInstance("ML-KEM-1024", "wolfJCE")
            .generateKeyPair().getPublic().getEncoded().length;

        assertTrue(len512 < len768);
        assertTrue(len768 < len1024);
    }
}
