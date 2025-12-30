/* wolfCryptKeyAgreementTest.java
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
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.BeforeClass;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicIntegerArray;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.ECGenParameterSpec;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfCryptKeyAgreementTest {

    private String wolfJCEAlgos[] = {
        "DiffieHellman",
        "ECDH"
    };

    private static String supportedCurves[] = {
        "secp192r1",
        "prime192v2",
        "prime192v3",
        "prime239v1",
        "prime239v2",
        "prime239v3",
        "secp256r1",

        "secp112r1",
        "secp112r2",
        "secp128r1",
        "secp128r2",
        "secp160r1",
        "secp224r1",
        "secp384r1",
        "secp521r1",

        "secp160k1",
        "secp192k1",
        "secp224k1",
        "secp256k1",

        "brainpoolp160r1",
        "brainpoolp192r1",
        "brainpoolp224r1",
        "brainpoolp256r1",
        "brainpoolp320r1",
        "brainpoolp384r1",
        "brainpoolp512r1"
    };

    private static ArrayList<String> enabledCurves =
        new ArrayList<String>();

    private static ArrayList<String> disabledCurves =
        new ArrayList<String>();

    /* One static SecureRandom to share */
    private static SecureRandom secureRandom = new SecureRandom();

    /*private static void printDisabledCurves() {

        if (disabledCurves.size() > 0)
            System.out.print("KeyAgreement: skipping disabled ECC curves:\n\t");

        for (int i = 1; i < disabledCurves.size()+1; i++) {

            if ((i % 4) == 0) {
                System.out.print(disabledCurves.get(i-1) + " \n\t");
            } else {
                System.out.print(disabledCurves.get(i-1) + " ");
            }
        }

        System.out.println("");
    }*/

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        System.out.println("JCE WolfCryptKeyAgreementTest Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* build list of enabled curves and key sizes,
         * getCurveSizeFromName() will return 0 if curve not found */
        for (int i = 0; i < supportedCurves.length; i++) {

            int size = Ecc.getCurveSizeFromName(
                        supportedCurves[i].toUpperCase());

            if (size > 0) {
                enabledCurves.add(supportedCurves[i]);
            } else {
                disabledCurves.add(supportedCurves[i]);
            }
        }

        /* uncomment this line and method above to print disabled curves */
        /* printDisabledCurves(); */
    }

    @Test
    public void testGetKeyAgreementFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* try to get all available options we expect to have */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            KeyAgreement.getInstance(wolfJCEAlgos[i], "wolfJCE");
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            KeyAgreement.getInstance("NotValid", "wolfJCE");

            fail("KeyAgreement.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testDHKeyAgreement()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* Skip 512-bit DH params in FIPS mode. FIPS 186-4 only allows
         * 1024, 2048, and 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);

        AlgorithmParameters params;
        try {
            params = paramGen.generateParameters();
        }
        catch (RuntimeException e) {
            /* 512-bit DH parameter generation may not be supported due to
             * wolfSSL enforcing minimum parameter sizes. Skip test if
             * generation fails. */
            if (e.getMessage() != null && e.getMessage().contains(
                "Bad function argument")) {
                System.out.println("\t512-bit DH parameter generation " +
                    "not supported, skipping test");
                return;
            }
            throw e;
        }

        DHParameterSpec dhParams =
            params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, secureRandom);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA[] = aKeyAgree.generateSecret();
        byte secretB[] = bKeyAgree.generateSecret();

        assertArrayEquals(secretA, secretB);

        /* Try reusing the A object without calling init() again */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());

        aKeyAgree.doPhase(cPair.getPublic(), true);
        cKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA2[] = aKeyAgree.generateSecret();
        byte secretC[]  = cKeyAgree.generateSecret();

        assertArrayEquals(secretA2, secretC);
    }

    @Test
    public void testDHKeyAgreementWithUpdateArgument()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               ShortBufferException {

        /* Skip 512-bit DH params in FIPS mode. FIPS 186-4 only allows
         * 1024, 2048, and 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);

        AlgorithmParameters params;
        try {
            params = paramGen.generateParameters();
        }
        catch (RuntimeException e) {
            /* 512-bit DH parameter generation may not be supported due to
             * wolfSSL enforcing minimum parameter sizes. Skip test if
             * generation fails. */
            if (e.getMessage() != null && e.getMessage().contains(
                "Bad function argument")) {
                System.out.println("\t512-bit DH parameter generation " +
                    "not supported, skipping test");
                return;
            }
            throw e;
        }

        DHParameterSpec dhParams =
            params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, secureRandom);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA[] = new byte[256];
        byte secretB[] = new byte[256];
        int secretASz = aKeyAgree.generateSecret(secretA, 0);
        int secretBSz = bKeyAgree.generateSecret(secretB, 0);

        assertEquals(secretASz, secretBSz);
        assertArrayEquals(secretA, secretB);

        /* now, try reusing the A object without calling init() again */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());

        aKeyAgree.doPhase(cPair.getPublic(), true);
        cKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA2[] = new byte[256];
        byte secretC[]  = new byte[256];
        int secretA2Sz = aKeyAgree.generateSecret(secretA2, 0);
        int secretCSz  = cKeyAgree.generateSecret(secretC, 0);

        assertEquals(secretA2Sz, secretCSz);
        assertArrayEquals(secretA2, secretC);
    }

    @Test
    public void testDHKeyAgreementInterop()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* Skip 512-bit DH params in FIPS mode. FIPS 186-4 only allows
         * 1024, 2048, and 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);

        AlgorithmParameters params;
        try {
            params = paramGen.generateParameters();
        }
        catch (RuntimeException e) {
            /* 512-bit DH parameter generation may not be supported due to
             * wolfSSL enforcing minimum parameter sizes. Skip test if
             * generation fails. */
            if (e.getMessage() != null && e.getMessage().contains(
                "Bad function argument")) {
                System.out.println("\t512-bit DH parameter generation " +
                    "not supported, skipping test");
                return;
            }
            throw e;
        }

        DHParameterSpec dhParams =
            params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, secureRandom);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH");

        Provider prov = bKeyAgree.getProvider();

        /* only run test if we have another provider besides ourselves */
        if (!prov.equals("wolfJCE")) {
            KeyPair aPair = keyGen.generateKeyPair();
            KeyPair bPair = keyGen.generateKeyPair();

            aKeyAgree.init(aPair.getPrivate());
            bKeyAgree.init(bPair.getPrivate());

            aKeyAgree.doPhase(bPair.getPublic(), true);
            bKeyAgree.doPhase(aPair.getPublic(), true);

            byte secretA[] = aKeyAgree.generateSecret();
            byte secretB[] = bKeyAgree.generateSecret();

            /* Older versions of Java did not prepend a zero byte to shared
             * secrets that were smaller than the prime length. This was
             * changed in SunJCE as of JDK-7146728, but we may be running this
             * test on an older version that does not prepend the zero byte.
             * Since wolfJCE does prepend the zero byte, for the sake of this
             * interop test, we strip the zero byte from wolfJCE's secret
             * if lengths are different and try to compare that. */
            if (secretB.length == (secretA.length - 1)) {
                secretA = Arrays.copyOfRange(secretA, 1, secretA.length);
            }

            if (secretA.length != secretB.length) {
                int i = 0;
                System.out.println("secretA.length != secretB.length");

                System.out.println("secretA (wolfJCE, " +
                    secretA.length + " bytes):");
                for (i = 0; i < secretA.length; i++) {
                    System.out.printf("%02x", secretA[i]);
                } System.out.printf("\n");

                System.out.println("secretB (SunJCE, " +
                    secretB.length + " bytes):");
                for (i = 0; i < secretB.length; i++) {
                    System.out.printf("%02x", secretB[i]);
                } System.out.printf("\n");
            }
            assertArrayEquals(secretA, secretB);

            /* now, try reusing the A object without calling init() again */
            KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
            KeyPair cPair = keyGen.generateKeyPair();
            cKeyAgree.init(cPair.getPrivate());

            aKeyAgree.doPhase(cPair.getPublic(), true);
            cKeyAgree.doPhase(aPair.getPublic(), true);

            byte secretA2[] = aKeyAgree.generateSecret();
            byte secretC[]  = cKeyAgree.generateSecret();

            assertArrayEquals(secretA2, secretC);
        }
    }

    @Test
    public void testECDHCurveLoad()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "wolfJCE");
        ECGenParameterSpec ecsp = null;

        for (int i = 0; i < enabledCurves.size(); i++) {
            try {
                ecsp = new ECGenParameterSpec(enabledCurves.get(i));
                keyGen.initialize(ecsp);
            } catch (InvalidAlgorithmParameterException e) {
                System.out.println("ECDH: Skipping curve [" +
                        enabledCurves.get(i) +
                        "], not supported by " + keyGen.getProvider());
                continue;
            }

            KeyAgreement ka =
                KeyAgreement.getInstance("ECDH", "wolfJCE");

            assertNotNull(ka);
        }

        /* Trying to use a bad curve should throw an exception */
        try {
            ecsp = new ECGenParameterSpec("invalidcurve");
            keyGen.initialize(ecsp);
            KeyAgreement ka =
                KeyAgreement.getInstance("ECDH", "wolfJCE");
            assertNotNull(ka);

            fail("Initializing KeyAgreement with invalid curve spec " +
                 "should throw exception");
        } catch (InvalidAlgorithmParameterException e) { /* expected */ }

    }

    @Test
    public void testECDHKeyAgreement()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "wolfJCE");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecsp);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA[] = aKeyAgree.generateSecret();
        byte secretB[] = bKeyAgree.generateSecret();

        assertArrayEquals(secretA, secretB);

        /* now, try reusing the A object without calling init() again */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());

        aKeyAgree.doPhase(cPair.getPublic(), true);
        cKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA2[] = aKeyAgree.generateSecret();
        byte secretC[]  = cKeyAgree.generateSecret();

        assertArrayEquals(secretA2, secretC);
    }

    @Test
    public void testECDHKeyAgreementWithUpdateArgument()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               ShortBufferException {

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "wolfJCE");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecsp);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA[] = new byte[256];
        byte secretB[] = new byte[256];
        int secretASz = aKeyAgree.generateSecret(secretA, 0);
        int secretBSz = bKeyAgree.generateSecret(secretB, 0);

        assertEquals(secretASz, secretBSz);
        assertArrayEquals(secretA, secretB);

        /* now, try reusing the A object without calling init() again */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());

        aKeyAgree.doPhase(cPair.getPublic(), true);
        cKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA2[] = new byte[256];
        byte secretC[]  = new byte[256];
        int secretA2Sz = aKeyAgree.generateSecret(secretA2, 0);
        int secretCSz  = cKeyAgree.generateSecret(secretC, 0);

        assertEquals(secretA2Sz, secretCSz);
        assertArrayEquals(secretA2, secretC);
    }

    @Test
    public void testECDHKeyAgreementInterop()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "wolfJCE");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecsp);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH");

        Provider prov = bKeyAgree.getProvider();
        if (prov.equals("wolfJCE")) {
            /* return, no other provider installed to interop against */
            return;
        }

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA[] = aKeyAgree.generateSecret();
        byte secretB[] = bKeyAgree.generateSecret();

        assertArrayEquals(secretA, secretB);

        /* now, try reusing the A object without calling init() again */
        KeyAgreement cKeyAgree =
            KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());

        aKeyAgree.doPhase(cPair.getPublic(), true);
        cKeyAgree.doPhase(aPair.getPublic(), true);

        byte secretA2[] = aKeyAgree.generateSecret();
        byte secretC[]  = cKeyAgree.generateSecret();

        assertArrayEquals(secretA2, secretC);
    }

    private void threadRunnerKeyAgreeTest(String algo)
        throws InterruptedException, NoSuchAlgorithmException {

        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final String currentAlgo = algo;

        /* Used to detect timeout of CountDownLatch, don't run indefinitely
         * if threads are stalled out or deadlocked */
        boolean returnWithoutTimeout = true;

        /* Keep track of failure and success count */
        final AtomicIntegerArray failures = new AtomicIntegerArray(1);
        final AtomicIntegerArray success = new AtomicIntegerArray(1);
        failures.set(0, 0);
        success.set(0, 0);

        /* DH Tests - generate 512-bit params. Skip in FIPS mode since
         * FIPS 186-4 only allows 1024, 2048, and 3072-bit DH parameter
         * generation */
        final AlgorithmParameters params;
        if (algo.equals("DH")) {
            if (Fips.enabled) {
                return;
            }
            AlgorithmParameterGenerator paramGen =
                AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(512);

            try {
                params = paramGen.generateParameters();
            }
            catch (RuntimeException e) {
                /* 512-bit DH parameter generation may not be supported due to
                 * wolfSSL enforcing minimum parameter sizes. Skip test if
                 * generation fails. */
                if (e.getMessage() != null && e.getMessage().contains(
                    "Bad function argument")) {
                    System.out.println("\t512-bit DH parameter generation " +
                        "not supported, skipping test");
                    return;
                }
                throw e;
            }
        } else {
            params = null;
        }

        /* Do encrypt/decrypt and sign/verify in parallel across numThreads
         * threads, all operations should pass */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    KeyPairGenerator keyGen = null;
                    KeyAgreement aKeyAgree = null;
                    KeyAgreement bKeyAgree = null;
                    KeyAgreement cKeyAgree = null;
                    KeyPair aPair = null;
                    KeyPair bPair = null;
                    KeyPair cPair = null;

                    try {

                        /* Set up KeyPairGenerator */
                        if (currentAlgo.equals("DH")) {
                            DHParameterSpec dhParams =
                                params.getParameterSpec(DHParameterSpec.class);

                            keyGen = KeyPairGenerator.getInstance(
                                "DH", "wolfJCE");
                            keyGen.initialize(dhParams, secureRandom);
                        } else {
                            ECGenParameterSpec ecsp =
                                new ECGenParameterSpec("secp256r1");

                            keyGen = KeyPairGenerator.getInstance(
                                "EC", "wolfJCE");
                            keyGen.initialize(ecsp);
                        }

                        /* Get KeyAgreement objects */
                        aKeyAgree = KeyAgreement.getInstance(
                            currentAlgo, "wolfJCE");
                        bKeyAgree = KeyAgreement.getInstance(
                            currentAlgo, "wolfJCE");

                        /* Generate key pairs */
                        aPair = keyGen.generateKeyPair();
                        bPair = keyGen.generateKeyPair();

                        /* Initialize KeyAgreement objects with private keys */
                        aKeyAgree.init(aPair.getPrivate());
                        bKeyAgree.init(bPair.getPrivate());

                        aKeyAgree.doPhase(bPair.getPublic(), true);
                        bKeyAgree.doPhase(aPair.getPublic(), true);

                        /* Generate shared secrets */
                        byte secretA[] = aKeyAgree.generateSecret();
                        byte secretB[] = bKeyAgree.generateSecret();

                        if (!Arrays.equals(secretA, secretB)) {
                            throw new Exception(
                                "Secrets A and B to not match");
                        }

                        cKeyAgree = KeyAgreement.getInstance(
                            currentAlgo, "wolfJCE");
                        cPair = keyGen.generateKeyPair();
                        cKeyAgree.init(cPair.getPrivate());

                        aKeyAgree.doPhase(cPair.getPublic(), true);
                        cKeyAgree.doPhase(aPair.getPublic(), true);

                        byte secretA2[] = aKeyAgree.generateSecret();
                        byte secretC[]  = cKeyAgree.generateSecret();

                        if (!Arrays.equals(secretA2, secretC)) {
                            throw new Exception(
                                "Secrets A2 and C do not match");
                        }

                        /* Log success */
                        success.incrementAndGet(0);

                    } catch (Exception e) {
                        e.printStackTrace();

                        /* Log failure */
                        failures.incrementAndGet(0);

                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        returnWithoutTimeout = latch.await(10, TimeUnit.SECONDS);
        service.shutdown();

        /* Check failure count and success count against thread count */
        if ((failures.get(0) != 0) ||
            (success.get(0) != numThreads)) {
            if (returnWithoutTimeout == true) {
                fail("KeyAgreement test threading error: " +
                    failures.get(0) + " failures, " +
                    success.get(0) + " success, " +
                    numThreads + " num threads total");
            } else {
                fail("KeyAgreement test threading error, threads timed out");
            }
        }
    }

    @Test
    public void testDHGenerateSecretKeyForDES()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* Skip 512-bit DH params in FIPS mode. FIPS 186-4 only allows
         * 1024, 2048, and 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);

        AlgorithmParameters params;
        try {
            params = paramGen.generateParameters();
        }
        catch (RuntimeException e) {
            /* 512-bit DH parameter generation may not be supported due to
             * wolfSSL enforcing minimum parameter sizes. Skip test if
             * generation fails. */
            if (e.getMessage() != null && e.getMessage().contains(
                "Bad function argument")) {
                return;
            }
            throw e;
        }

        DHParameterSpec dhParams =
            params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen =
            KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, secureRandom);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        /* Test generateSecret("DES") returns SecretKey, not DESKeySpec */
        SecretKey desKeyA = null;
        SecretKey desKeyB = null;
        try {
            desKeyA = aKeyAgree.generateSecret("DES");
            assertNotNull(desKeyA);
            assertTrue(desKeyA instanceof SecretKey);
            assertEquals("DES", desKeyA.getAlgorithm());

            /* Verify key can be used with Cipher */
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, desKeyA);

        } catch (ClassCastException e) {
            fail("generateSecret(\"DES\") should return SecretKey, " +
                "not DESKeySpec: " + e.getMessage());

        } catch (Exception e) {
            fail("Unexpected exception during DES key generation: " +
                e.getMessage());
        }

        /* Test generateSecret("DESede") returns SecretKey */
        try {
            /* bKeyAgree already has doPhase() completed, just generate
             * secret with different algorithm */
            SecretKey desedeKey = bKeyAgree.generateSecret("DESede");
            assertNotNull(desedeKey);
            assertTrue(desedeKey instanceof SecretKey);
            assertEquals("DESede", desedeKey.getAlgorithm());

            /* Verify key can be used with Cipher */
            Cipher cipher =
                Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, desedeKey);

        } catch (ClassCastException e) {
            fail("generateSecret(\"DESede\") should return SecretKey, " +
                "not DESedeKeySpec: " + e.getMessage());

        } catch (Exception e) {
            fail("Unexpected exception during DESede key generation: " +
                e.getMessage());
        }

        /* Test generateSecret("AES") returns SecretKey with proper size */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());
        cKeyAgree.doPhase(aPair.getPublic(), true);

        try {
            SecretKey aesKey = cKeyAgree.generateSecret("AES");
            assertNotNull(aesKey);
            assertTrue(aesKey instanceof SecretKey);
            assertEquals("AES", aesKey.getAlgorithm());

            /* AES key should be 16, 24, or 32 bytes */
            byte[] encoded = aesKey.getEncoded();
            assertTrue("AES key length should be 16, 24, or 32 bytes",
                encoded.length == 16 || encoded.length == 24 ||
                encoded.length == 32);

            /* Verify key can be used with Cipher */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            /* Test encryption/decryption */
            byte[] plaintext = "Test AES encryption".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            cipher.init(Cipher.DECRYPT_MODE, aesKey,
                cipher.getParameters());
            byte[] decrypted = cipher.doFinal(ciphertext);
            assertArrayEquals(plaintext, decrypted);

        } catch (Exception e) {
            fail("Unexpected exception during AES key generation: " +
                e.getMessage());
        }
    }

    @Test
    public void testECDHGenerateSecretKeyForDES()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* initialize key pair generator */
        KeyPairGenerator keyGen =
            KeyPairGenerator.getInstance("EC", "wolfJCE");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecsp);

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");

        KeyPair aPair = keyGen.generateKeyPair();
        KeyPair bPair = keyGen.generateKeyPair();

        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        /* Test generateSecret("DES") returns SecretKey, not DESKeySpec */
        try {
            SecretKey desKey = aKeyAgree.generateSecret("DES");
            assertNotNull(desKey);
            assertTrue(desKey instanceof SecretKey);
            assertEquals("DES", desKey.getAlgorithm());

            /* Verify key can be used with Cipher */
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, desKey);

        } catch (ClassCastException e) {
            fail("generateSecret(\"DES\") should return SecretKey, " +
                "not DESKeySpec: " + e.getMessage());

        } catch (Exception e) {
            fail("Unexpected exception during DES key generation: " +
                e.getMessage());
        }

        /* Test generateSecret("DESede") returns SecretKey */
        try {
            /* bKeyAgree already has doPhase() completed, just generate
             * secret with different algorithm */
            SecretKey desedeKey = bKeyAgree.generateSecret("DESede");
            assertNotNull(desedeKey);
            assertTrue(desedeKey instanceof SecretKey);
            assertEquals("DESede", desedeKey.getAlgorithm());

            /* Verify key can be used with Cipher */
            Cipher cipher =
                Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, desedeKey);

        } catch (ClassCastException e) {
            fail("generateSecret(\"DESede\") should return SecretKey, " +
                "not DESedeKeySpec: " + e.getMessage());

        } catch (Exception e) {
            fail("Unexpected exception during DESede key generation: " +
                e.getMessage());
        }

        /* Test generateSecret("AES") returns SecretKey with proper size */
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("ECDH", "wolfJCE");
        KeyPair cPair = keyGen.generateKeyPair();
        cKeyAgree.init(cPair.getPrivate());
        cKeyAgree.doPhase(aPair.getPublic(), true);

        try {
            SecretKey aesKey = cKeyAgree.generateSecret("AES");
            assertNotNull(aesKey);
            assertTrue(aesKey instanceof SecretKey);
            assertEquals("AES", aesKey.getAlgorithm());

            /* AES key should be 16, 24, or 32 bytes */
            byte[] encoded = aesKey.getEncoded();
            assertTrue("AES key length should be 16, 24, or 32 bytes",
                encoded.length == 16 || encoded.length == 24 ||
                encoded.length == 32);

            /* Verify key can be used with Cipher */
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            /* Test encryption/decryption */
            byte[] plaintext = "Test AES encryption".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);
            cipher.init(Cipher.DECRYPT_MODE, aesKey,
                cipher.getParameters());
            byte[] decrypted = cipher.doFinal(ciphertext);
            assertArrayEquals(plaintext, decrypted);

        } catch (Exception e) {
            fail("Unexpected exception during AES key generation: " +
                e.getMessage());
        }
    }

    @Test
    public void testDHKeyAgreementPadding()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               ShortBufferException {

        /* This test verifies that DH shared secrets are properly padded to
         * the prime length when using generateSecret(byte[], int). This
         * matches the behavior of SunJCE after Java 8 (JDK-7146728) and
         * prevents regressions related to padding. Both generateSecret()
         * methods pad to primeLen. */

        /* Skip in FIPS mode. FIPS 186-4 only allows 1024, 2048, and
         * 3072-bit DH parameter generation */
        if (Fips.enabled) {
            return;
        }

        /* Generate 2048-bit DH parameters */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048);

        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParams =
            params.getParameterSpec(DHParameterSpec.class);

        /* Prime length should be 256 bytes for 2048-bit DH */
        int primeLen = dhParams.getP().toByteArray().length;
        if (dhParams.getP().toByteArray()[0] == 0x00) {
            primeLen--;
        }

        /* Initialize key pair generator */
        KeyPairGenerator keyGen =
            KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, secureRandom);

        KeyAgreement alice = KeyAgreement.getInstance("DH", "wolfJCE");
        KeyAgreement bob = KeyAgreement.getInstance("DH", "wolfJCE");

        /* Run multiple iterations to ensure consistent padding behavior */
        for (int i = 0; i < 100; i++) {
            byte[] aliceSecret = new byte[primeLen];
            byte[] bobSecret = new byte[primeLen];

            /* Fill buffers with different stale data to ensure padding
             * overwrites any existing data */
            Arrays.fill(aliceSecret, (byte)'a');
            Arrays.fill(bobSecret, (byte)'b');

            /* Generate new key pairs for this iteration */
            KeyPair aliceKeyPair = keyGen.generateKeyPair();
            KeyPair bobKeyPair = keyGen.generateKeyPair();

            /* Perform key agreement */
            alice.init(aliceKeyPair.getPrivate());
            alice.doPhase(bobKeyPair.getPublic(), true);
            int aliceLen = alice.generateSecret(aliceSecret, 0);

            bob.init(bobKeyPair.getPrivate());
            bob.doPhase(aliceKeyPair.getPublic(), true);
            int bobLen = bob.generateSecret(bobSecret, 0);

            /* Both secrets should be exactly primeLen bytes (always padded) */
            assertEquals("Alice's secret length should equal prime length",
                primeLen, aliceLen);
            assertEquals("Bob's secret length should equal prime length",
                primeLen, bobLen);

            /* Both secrets should be identical, including padding */
            assertArrayEquals("Alice and Bob should generate identical " +
                "secrets at iteration " + i, aliceSecret, bobSecret);
        }
    }

    @Test
    public void testThreadedKeyAgreement()
        throws InterruptedException, NoSuchAlgorithmException {

        threadRunnerKeyAgreeTest("DH");
        threadRunnerKeyAgreeTest("ECDH");
    }

    /**
     * Test DH key serialization and deserialization.
     */
    @Test
    public void testDHKeySerialization() throws Exception {
        /* Generate DH keypair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        /* Serialize and deserialize private key */
        PrivateKey deserializedPrivate =
            deserializeKey(serializeKey(kp.getPrivate()));
        assertNotNull("Deserialized private key should not be null",
            deserializedPrivate);
        assertTrue("Private key should be equal after serialization",
            kp.getPrivate().equals(deserializedPrivate));

        /* Serialize and deserialize public key */
        PublicKey deserializedPublic =
            deserializeKey(serializeKey(kp.getPublic()));
        assertNotNull("Deserialized public key should not be null",
            deserializedPublic);
        assertTrue("Public key should be equal after serialization",
            kp.getPublic().equals(deserializedPublic));

        /* Test KeyAgreement with deserialized keys */
        KeyAgreement ka = KeyAgreement.getInstance("DH", "wolfJCE");
        ka.init(deserializedPrivate);
        ka.doPhase(deserializedPublic, true);
        byte[] secret = ka.generateSecret();
        assertNotNull("KeyAgreement secret should not be null", secret);
    }

    /**
     * Test EC key serialization and deserialization.
     */
    @Test
    public void testECKeySerialization() throws Exception {
        /* Generate EC keypair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        /* Serialize and deserialize private key */
        PrivateKey deserializedPrivate =
            deserializeKey(serializeKey(kp.getPrivate()));
        assertNotNull("Deserialized private key should not be null",
            deserializedPrivate);
        assertTrue("Private key should be equal after serialization",
            kp.getPrivate().equals(deserializedPrivate));

        /* Serialize and deserialize public key */
        PublicKey deserializedPublic =
            deserializeKey(serializeKey(kp.getPublic()));
        assertNotNull("Deserialized public key should not be null",
            deserializedPublic);
        assertTrue("Public key should be equal after serialization",
            kp.getPublic().equals(deserializedPublic));

        /* Test KeyAgreement with deserialized keys */
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "wolfJCE");
        ka.init(deserializedPrivate);
        ka.doPhase(deserializedPublic, true);
        byte[] secret = ka.generateSecret();
        assertNotNull("KeyAgreement secret should not be null", secret);
    }

    /**
     * Serialize a key to byte array
     */
    private byte[] serializeKey(Key key) throws IOException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(key);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Deserialize a key from byte array
     */
    @SuppressWarnings("unchecked")
    private <T> T deserializeKey(byte[] bytes)
        throws IOException, ClassNotFoundException {

        ByteArrayInputStream bis =
            new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis);
        T key = (T) ois.readObject();
        ois.close();
        return key;
    }
}

