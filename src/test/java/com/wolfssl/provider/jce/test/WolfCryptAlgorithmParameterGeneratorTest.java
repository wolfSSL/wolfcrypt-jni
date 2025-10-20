/* WolfCryptAlgorithmParameterGeneratorTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Test;
import org.junit.BeforeClass;

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptAlgorithmParameterGeneratorTest {

    private static SecureRandom rand = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        System.out.println(
            "JCE WolfCryptAlgorithmParameterGeneratorTest Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* Get single static SecureRandom for use in this class */
        rand = SecureRandom.getInstance("DEFAULT");
    }

    @Test
    public void testGetAlgorithmParameterGeneratorFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        AlgorithmParameterGenerator paramGen;

        /* DH should be available */
        paramGen = AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        /* Getting a garbage algorithm should throw an exception */
        try {
            paramGen = AlgorithmParameterGenerator.getInstance(
                "NotValid", "wolfJCE");

            fail("AlgorithmParameterGenerator.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParameterGenerationFFDHESizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               Exception {

        /* Test standard FFDHE sizes: 2048, 3072, 4096, 6144, 8192 */
        int[] ffdheSizes = { 2048, 3072, 4096, 6144, 8192 };

        for (int size : ffdheSizes) {
            AlgorithmParameterGenerator paramGen =
                AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
            assertNotNull(paramGen);

            paramGen.init(size);

            try {
                AlgorithmParameters params = paramGen.generateParameters();
                assertNotNull(params);

                /* Verify we can get DHParameterSpec from generated params */
                DHParameterSpec spec =
                    params.getParameterSpec(DHParameterSpec.class);
                assertNotNull(spec);
                assertNotNull(spec.getP());
                assertNotNull(spec.getG());

                /* Verify the prime size matches what we requested */
                int actualSize = spec.getP().bitLength();
                assertEquals("Expected " + size + " bit params, got " +
                             actualSize, size, actualSize);
            }
            catch (RuntimeException e) {
                /* Skip FFDHE sizes not compiled into native wolfSSL */
                if (e.getMessage() != null &&
                    (e.getMessage().contains("group not available") ||
                     e.getMessage().contains("Unsupported FFDHE group"))) {
                    continue;
                }
                throw e;
            }
        }
    }

    @Test
    public void testDHParameterGenerationFFDHESizesWithSecureRandom()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               Exception {

        /* Test standard FFDHE sizes with SecureRandom */
        int[] ffdheSizes = { 2048, 3072, 4096, 6144, 8192 };

        for (int size : ffdheSizes) {
            AlgorithmParameterGenerator paramGen =
                AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
            assertNotNull(paramGen);

            paramGen.init(size, rand);

            try {
                AlgorithmParameters params = paramGen.generateParameters();
                assertNotNull(params);

                DHParameterSpec spec =
                    params.getParameterSpec(DHParameterSpec.class);
                assertNotNull(spec);
                assertNotNull(spec.getP());
                assertNotNull(spec.getG());

                /* Verify the prime size matches what we requested */
                int actualSize = spec.getP().bitLength();
                assertEquals("Expected " + size + " bit params, got " +
                             actualSize, size, actualSize);
            }
            catch (RuntimeException e) {
                /* Skip FFDHE sizes not compiled into native wolfSSL */
                if (e.getMessage() != null &&
                    (e.getMessage().contains("group not available") ||
                     e.getMessage().contains("Unsupported FFDHE group"))) {
                    continue;
                }
                throw e;
            }
        }
    }

    @Test
    public void testDHParameterGenerationNonStandardSizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               Exception {

        /* Test non-standard sizes (requires dynamic generation).
         * Skip in FIPS mode as FIPS 186-4 only allows 1024, 2048,
         * and 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        int[] nonStandardSizes = { 1024, 1536 };

        for (int size : nonStandardSizes) {
            AlgorithmParameterGenerator paramGen =
                AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
            assertNotNull(paramGen);

            paramGen.init(size);

            try {
                AlgorithmParameters params = paramGen.generateParameters();
                assertNotNull(params);

                DHParameterSpec spec =
                    params.getParameterSpec(DHParameterSpec.class);
                assertNotNull(spec);
                assertNotNull(spec.getP());
                assertNotNull(spec.getG());

                /* Note: bit length may vary slightly for dynamically
                 * generated params */
                assertTrue(spec.getP().bitLength() >= size - 8 &&
                    spec.getP().bitLength() <= size + 8);
            }
            catch (RuntimeException e) {
                /* Dynamic parameter generation may not be supported for all
                 * sizes, especially in FIPS builds or when wolfSSL enforces
                 * minimum parameter sizes. Skip if generation fails. */
                if (e.getMessage() != null &&
                    e.getMessage().contains("Bad function argument")) {
                    continue;
                }
                throw e;
            }
        }
    }

    @Test
    public void testDHParameterGenerationDefaultSize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               Exception {

        /* Test that default size is 2048 bits when no size is specified */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        AlgorithmParameters params = paramGen.generateParameters();
        assertNotNull(params);

        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        assertNotNull(spec);
        assertEquals(2048, spec.getP().bitLength());
    }

    @Test
    public void testDHParameterGenerationWithDHGenParameterSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException, Exception {

        /* Test that DHGenParameterSpec is supported and properly sets
         * both prime size and exponent size */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        /* Initialize with DHGenParameterSpec: 2048-bit prime,
         * 256-bit exponent */
        DHGenParameterSpec genSpec = new DHGenParameterSpec(2048, 256);
        paramGen.init(genSpec, rand);

        AlgorithmParameters params = paramGen.generateParameters();
        assertNotNull(params);

        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        assertNotNull(spec);
        assertNotNull(spec.getP());
        assertNotNull(spec.getG());
        assertEquals(2048, spec.getP().bitLength());
        assertEquals(256, spec.getL());
    }

    @Test
    public void testDHParameterGenerationWithInvalidAlgorithmParameterSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Test that non-DHGenParameterSpec AlgorithmParameterSpec is
         * rejected */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        /* Try to initialize with a generic AlgorithmParameterSpec -
         * should throw exception */
        try {
            AlgorithmParameterSpec spec = new AlgorithmParameterSpec() {};
            paramGen.init(spec, rand);

            fail("AlgorithmParameterGenerator.init should throw " +
                 "InvalidAlgorithmParameterException when given " +
                 "non-DHGenParameterSpec");

        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParameterGenerationWithDHGenParameterSpecMultipleSizes()
        throws NoSuchProviderException, NoSuchAlgorithmException, Exception {

        /* Test DHGenParameterSpec with various FFDHE sizes and
         * exponent sizes */
        int[][] testCases = {
            {2048, 256},
            {3072, 256},
            {4096, 384},
            {2048, 160}
        };

        for (int[] testCase : testCases) {
            int primeSize = testCase[0];
            int exponentSize = testCase[1];

            AlgorithmParameterGenerator paramGen =
                AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
            assertNotNull(paramGen);

            DHGenParameterSpec genSpec =
                new DHGenParameterSpec(primeSize, exponentSize);
            paramGen.init(genSpec, rand);

            try {
                AlgorithmParameters params = paramGen.generateParameters();
                assertNotNull(params);

                DHParameterSpec spec =
                    params.getParameterSpec(DHParameterSpec.class);
                assertNotNull(spec);

                /* Verify the prime size matches what was requested */
                int actualPrimeSize = spec.getP().bitLength();
                assertEquals("Expected " + primeSize + " bit params, got " +
                             actualPrimeSize, primeSize, actualPrimeSize);

                /* Exponent size should match what was requested */
                assertEquals(exponentSize, spec.getL());
            }
            catch (RuntimeException e) {
                /* Skip FFDHE sizes not compiled into native wolfSSL */
                if (e.getMessage() != null &&
                    (e.getMessage().contains("group not available") ||
                     e.getMessage().contains("Unsupported FFDHE group"))) {
                    continue;
                }
                throw e;
            }
        }
    }

    @Test
    public void testDHParameterGenerationWithDHGenParameterSpecNullRandom()
        throws NoSuchProviderException, NoSuchAlgorithmException, Exception {

        /* Test that DHGenParameterSpec works with null SecureRandom
         * (should use default) */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        DHGenParameterSpec genSpec = new DHGenParameterSpec(2048, 256);
        paramGen.init(genSpec, null);

        AlgorithmParameters params = paramGen.generateParameters();
        assertNotNull(params);

        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        assertNotNull(spec);
        assertEquals(2048, spec.getP().bitLength());
        assertEquals(256, spec.getL());
    }

    @Test
    public void testDHParameterGenerationWithDHGenParameterSpecNullSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Test that null DHGenParameterSpec is rejected */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(paramGen);

        try {
            paramGen.init(null, rand);
            fail("AlgorithmParameterGenerator.init should throw " +
                 "InvalidAlgorithmParameterException when given null spec");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParameterGenerationInteropWithSunJCE()
        throws Exception {

        /* Test interoperability with SunJCE provider.
         * Generate parameters with wolfJCE and verify they work with
         * standard Java DH key agreement */

        AlgorithmParameterGenerator wolfParamGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(wolfParamGen);

        wolfParamGen.init(2048);
        AlgorithmParameters wolfParams = wolfParamGen.generateParameters();
        assertNotNull(wolfParams);

        DHParameterSpec spec =
            wolfParams.getParameterSpec(DHParameterSpec.class);
        assertNotNull(spec);

        /* Try to create a SunJCE KeyPairGenerator with wolfJCE params */
        try {
            KeyPairGenerator sunKpg =
                KeyPairGenerator.getInstance("DH", "SunJCE");
            sunKpg.initialize(spec);

            /* Generate a key pair using SunJCE with wolfJCE params */
            KeyPair kp = sunKpg.generateKeyPair();
            assertNotNull(kp);
            assertNotNull(kp.getPrivate());
            assertNotNull(kp.getPublic());

        } catch (NoSuchProviderException e) {
            /* SunJCE provider not available, skip interop test */
            System.out.println("\tSkipping SunJCE interop test, " +
                "provider not available");
        }
    }

    @Test
    public void testDHParametersFromWolfJCEMatchStandardProvider()
        throws Exception {

        /* Generate params with both providers and verify format
         * compatibility */
        AlgorithmParameterGenerator wolfParamGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        assertNotNull(wolfParamGen);

        wolfParamGen.init(2048);
        AlgorithmParameters wolfParams = wolfParamGen.generateParameters();
        assertNotNull(wolfParams);

        /* Get DER encoding from wolfJCE */
        byte[] wolfEncoded = wolfParams.getEncoded();
        assertNotNull(wolfEncoded);
        assertTrue(wolfEncoded.length > 0);

        /* Try to parse with standard Java AlgorithmParameters */
        try {
            AlgorithmParameters sunParams =
                AlgorithmParameters.getInstance("DH", "SunJCE");
            sunParams.init(wolfEncoded);

            /* If we get here, SunJCE successfully parsed our encoding */
            DHParameterSpec sunSpec =
                sunParams.getParameterSpec(DHParameterSpec.class);
            assertNotNull(sunSpec);

            /* Verify the parameters match */
            DHParameterSpec wolfSpec =
                wolfParams.getParameterSpec(DHParameterSpec.class);
            assertEquals(wolfSpec.getP(), sunSpec.getP());
            assertEquals(wolfSpec.getG(), sunSpec.getG());

        } catch (NoSuchProviderException e) {
            /* SunJCE provider not available, skip interop test */
            System.out.println("\tSkipping SunJCE interop test, " +
                "provider not available");
        }
    }

    @Test
    public void testDHParameterGenerationConsistency()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               Exception {

        /* For FFDHE standard sizes, parameters should be deterministic
         * (same size should produce same p and g) */
        AlgorithmParameterGenerator paramGen1 =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        AlgorithmParameterGenerator paramGen2 =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");

        paramGen1.init(2048);
        paramGen2.init(2048);

        AlgorithmParameters params1 = paramGen1.generateParameters();
        AlgorithmParameters params2 = paramGen2.generateParameters();

        DHParameterSpec spec1 =
            params1.getParameterSpec(DHParameterSpec.class);
        DHParameterSpec spec2 =
            params2.getParameterSpec(DHParameterSpec.class);

        /* For standard FFDHE_2048, p and g should be identical */
        assertEquals(spec1.getP(), spec2.getP());
        assertEquals(spec1.getG(), spec2.getG());
    }

    @Test
    public void testDHGenParameterSpecInteropWithSunJCE()
        throws Exception {

        /* Test that our DHGenParameterSpec behavior matches SunJCE.
         * Both should accept DHGenParameterSpec and generate parameters
         * with the specified prime size and exponent size. */

        try {
            /* Generate with wolfJCE using DHGenParameterSpec */
            AlgorithmParameterGenerator wolfParamGen =
                AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
            DHGenParameterSpec genSpec = new DHGenParameterSpec(2048, 256);
            wolfParamGen.init(genSpec, rand);
            AlgorithmParameters wolfParams = wolfParamGen.generateParameters();

            DHParameterSpec wolfSpec =
                wolfParams.getParameterSpec(DHParameterSpec.class);
            assertEquals(2048, wolfSpec.getP().bitLength());
            assertEquals(256, wolfSpec.getL());

            /* Verify SunJCE accepts the same DHGenParameterSpec format */
            AlgorithmParameterGenerator sunParamGen =
                AlgorithmParameterGenerator.getInstance("DH", "SunJCE");
            sunParamGen.init(genSpec, rand);
            AlgorithmParameters sunParams = sunParamGen.generateParameters();

            DHParameterSpec sunSpec =
                sunParams.getParameterSpec(DHParameterSpec.class);
            assertEquals(2048, sunSpec.getP().bitLength());
            assertEquals(256, sunSpec.getL());

        } catch (NoSuchProviderException e) {
            /* SunJCE provider not available, skip interop test */
            System.out.println("\tSkipping SunJCE DHGenParameterSpec " +
                "interop test, provider not available");
        }
    }
}

