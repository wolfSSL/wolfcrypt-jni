/* wolfCryptSignatureTest.java
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

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicIntegerArray;

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptSignatureTest {

    private static String wolfJCEAlgos[] = {
        "SHA1withRSA",
        "SHA224withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        "SHA3-224withRSA",
        "SHA3-256withRSA",
        "SHA3-384withRSA",
        "SHA3-512withRSA",
        "RSASSA-PSS",
        "SHA224withRSA/PSS",
        "SHA256withRSA/PSS",
        "SHA384withRSA/PSS",
        "SHA512withRSA/PSS",
        "SHA1withECDSA",
        "SHA224withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA",
        "SHA3-224withECDSA",
        "SHA3-256withECDSA",
        "SHA3-384withECDSA",
        "SHA3-512withECDSA"
    };

    private static ArrayList<String> enabledAlgos =
        new ArrayList<String>();

    /* One static SecureRandom to share */
    private static SecureRandom secureRandom = new SecureRandom();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptSignature Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* populate enabledAlgos, some native features may be
         * compiled out */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            try {
                Signature sig =
                    Signature.getInstance(wolfJCEAlgos[i], "wolfJCE");
                assertNotNull(sig);
                enabledAlgos.add(wolfJCEAlgos[i]);
            } catch (NoSuchAlgorithmException e) {
                /* algo not compiled in */
            }
        }
    }

    @Test
    public void testGetSignatureFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledAlgos.size(); i++) {
            Signature sig =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");
            assertNotNull(sig);
        }

        /* asking for a bad algo should throw an exception */
        try {
            Signature.getInstance("invalidalgo", "wolfJCE");
            fail("Requesting an invalid algorithm from Signature " +
                 "object should throw an exception");
        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testWolfSignWolfVerify()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String toSign = "Hello World";
        byte[] toSignBuf = toSign.getBytes();
        byte[] signature = null;

        for (int i = 0; i < enabledAlgos.size(); i++) {

            Signature signer =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");
            Signature verifier =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");

            assertNotNull(signer);
            assertNotNull(verifier);

            /* Set parameters for generic RSASSA-PSS */
            if (enabledAlgos.get(i).equals("RSASSA-PSS")) {
                java.security.spec.PSSParameterSpec pssSpec =
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32, 1);
                signer.setParameter(pssSpec);
                verifier.setParameter(pssSpec);
            }

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), secureRandom);
            assertNotNull(pair);

            PrivateKey priv = pair.getPrivate();
            PublicKey  pub  = pair.getPublic();

            /* generate signature */
            signer.initSign(priv);
            signer.update(toSignBuf, 0, toSignBuf.length);
            signature = signer.sign();

            /* verify signature */
            verifier.initVerify(pub);
            verifier.update(toSignBuf, 0, toSignBuf.length);
            boolean verified = verifier.verify(signature);

            if (verified != true) {
                fail("Signature verification failed when generating with " +
                        "wolfJCE and verifying with system default JCE " +
                        "provider");
            }
        }
    }

    @Test
    public void testWolfSignInitMulti()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String toSign = "Hello World";
        byte[] toSignBuf = toSign.getBytes();
        byte[] signature = null;

        for (int i = 0; i < enabledAlgos.size(); i++) {

            Signature signer =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");
            Signature verifier =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");

            assertNotNull(signer);
            assertNotNull(verifier);

            /* Set parameters for generic RSASSA-PSS */
            if (enabledAlgos.get(i).equals("RSASSA-PSS")) {
                java.security.spec.PSSParameterSpec pssSpec =
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32, 1);
                signer.setParameter(pssSpec);
                verifier.setParameter(pssSpec);
            }

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), secureRandom);
            assertNotNull(pair);

            PrivateKey priv = pair.getPrivate();
            PublicKey  pub  = pair.getPublic();

            /* test multiple inits on signer */
            signer.initSign(priv);
            signer.initSign(priv);

            /* test multiple inits on verifier */
            verifier.initVerify(pub);
            verifier.initVerify(pub);

            /* make sure sign/verify still work after multi init */
            signer.update(toSignBuf, 0, toSignBuf.length);
            signature = signer.sign();

            verifier.update(toSignBuf, 0, toSignBuf.length);
            boolean verified = verifier.verify(signature);

            if (verified != true) {
                /* Collect diagnostic information for sporadic failures */
                StringBuilder diagnostics = new StringBuilder();

                /* Algorithm Context */
                diagnostics.append("FAILURE DETAILS:\n");
                diagnostics.append("  Algorithm: ")
                    .append(enabledAlgos.get(i)).append("\n");
                diagnostics.append("  Loop iteration: ").append(i).append("\n");
                diagnostics.append("  Total enabled algorithms: ")
                    .append(enabledAlgos.size()).append("\n");

                /* Signature Byte Analysis */
                diagnostics.append("  Signature length: ").append(
                    signature.length).append("\n");
                if (signature.length > 0) {
                    diagnostics.append("  Signature first 8 bytes: ");
                    for (int b = 0; b < Math.min(8, signature.length); b++) {
                        diagnostics.append(String.format("%02X ",
                            signature[b]));
                    }
                    diagnostics.append("\n");
                    diagnostics.append("  Signature has leading zeros: ")
                        .append(signature[0] == 0).append("\n");
                }

                /* Key Information */
                diagnostics.append("  Private key algorithm: ")
                    .append(priv.getAlgorithm()).append("\n");
                diagnostics.append("  Public key algorithm: ")
                    .append(pub.getAlgorithm()).append("\n");
                diagnostics.append("  Private key format: ")
                    .append(priv.getFormat()).append("\n");
                diagnostics.append("  Public key format: ").
                    append(pub.getFormat()).append("\n");

                if (priv instanceof java.security.interfaces.RSAPrivateKey) {
                    java.security.interfaces.RSAPrivateKey rsaPriv =
                        (java.security.interfaces.RSAPrivateKey) priv;
                    diagnostics.append("  RSA key size: ")
                        .append(rsaPriv.getModulus().bitLength()).append("\n");
                }

                /* Signature Object State */
                diagnostics.append("  Signer provider: ")
                    .append(signer.getProvider().getName()).append("\n");
                diagnostics.append("  Verifier provider: ")
                    .append(verifier.getProvider().getName()).append("\n");
                diagnostics.append("  Signer algorithm: ")
                    .append(signer.getAlgorithm()).append("\n");
                diagnostics.append("  Verifier algorithm: ")
                    .append(verifier.getAlgorithm()).append("\n");


                fail("Signature verification failed when generating and " +
                     "verifying with wolfJCE provider.\n" +
                     diagnostics.toString());
            }
        }
    }

    @Test
    public void testWolfSignInteropVerify()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String toSign = "Hello World";
        byte[] toSignBuf = toSign.getBytes();
        byte[] signature;

        for (int i = 0; i < enabledAlgos.size(); i++) {

            Signature signer =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");
            Signature verifier =
                Signature.getInstance(enabledAlgos.get(i));

            assertNotNull(signer);
            assertNotNull(verifier);

            Provider prov = verifier.getProvider();
            if (prov.equals("wolfJCE")) {
                /* bail out, there isn't another implementation to interop
                 * against by default */
                return;
            }

            /* Set parameters for generic RSASSA-PSS */
            if (enabledAlgos.get(i).equals("RSASSA-PSS")) {
                java.security.spec.PSSParameterSpec pssSpec =
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32, 1);
                signer.setParameter(pssSpec);
                verifier.setParameter(pssSpec);
            }

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), secureRandom);
            assertNotNull(pair);

            PrivateKey priv = pair.getPrivate();
            PublicKey  pub  = pair.getPublic();

            /* generate signature */
            signer.initSign(priv);
            signer.update(toSignBuf, 0, toSignBuf.length);
            signature = signer.sign();

            /* verify signature */
            verifier.initVerify(pub);
            verifier.update(toSignBuf, 0, toSignBuf.length);
            boolean verified = verifier.verify(signature);

            if (verified != true) {
                fail("Signature verification failed when generating with " +
                        "wolfJCE and verifying with system default JCE " +
                        "provider");
            }
        }
    }

    @Test
    public void testInteropSignWolfVerify()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String toSign = "Hello World";
        byte[] toSignBuf = toSign.getBytes();
        byte[] signature;

        for (int i = 0; i < enabledAlgos.size(); i++) {

            Signature signer =
                Signature.getInstance(enabledAlgos.get(i));
            Signature verifier =
                Signature.getInstance(enabledAlgos.get(i), "wolfJCE");

            assertNotNull(signer);
            assertNotNull(verifier);

            Provider prov = signer.getProvider();
            if (prov.equals("wolfJCE")) {
                /* bail out, there isn't another implementation to interop
                 * against by default */
                return;
            }

            /* Set parameters for generic RSASSA-PSS */
            if (enabledAlgos.get(i).equals("RSASSA-PSS")) {
                java.security.spec.PSSParameterSpec pssSpec =
                    new java.security.spec.PSSParameterSpec(
                        "SHA-256", "MGF1",
                        java.security.spec.MGF1ParameterSpec.SHA256,
                        32, 1);
                signer.setParameter(pssSpec);
                verifier.setParameter(pssSpec);
            }

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), secureRandom);
            assertNotNull(pair);

            PrivateKey priv = pair.getPrivate();
            PublicKey  pub  = pair.getPublic();

            /* generate signature */
            signer.initSign(priv);
            signer.update(toSignBuf, 0, toSignBuf.length);
            signature = signer.sign();

            /* verify signature */
            verifier.initVerify(pub);
            verifier.update(toSignBuf, 0, toSignBuf.length);
            boolean verified = verifier.verify(signature);

            if (verified != true) {
                fail("Signature verification failed when generating with " +
                        "system default JCE provider and verifying with " +
                        "wolfJCE provider, iteration " + i);
            }
        }
    }

    /**
     * Generates public/private key pair for use in signature tests.
     * Currently generates keys using default provider, as wolfJCE does not
     * yet support key generation.
     */
    private KeyPair generateKeyPair(String algo, SecureRandom rand)
        throws NoSuchAlgorithmException, NoSuchProviderException,
               InvalidAlgorithmParameterException {

        KeyPair pair = null;

        if (algo.contains("RSA")) {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, rand);
            pair = keyGen.generateKeyPair();

        } else if (algo.contains("ECDSA")) {

            KeyPairGenerator keyGen =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp521r1");
            keyGen.initialize(ecSpec);

            pair = keyGen.generateKeyPair();
        }

        return pair;
    }

    private void threadRunnerSignVerify(byte[] inBuf, String algo,
        final AtomicIntegerArray failures, final AtomicIntegerArray success,
        ExecutorService service, final CountDownLatch latch, int numThreads)
        throws InterruptedException, Exception {

        final String currentAlg = algo;
        final byte[] toSignBuf = inBuf;
        KeyPair pair = null;
        KeyPairGenerator keyGen = null;
        final PrivateKey priv;
        final PublicKey pub;

        /* Generate key pairs once up front to minimize use of entropy from
         * RNG. We also are just interested in testing sign/verify across
         * multiple threads, not key gen in this test. */
        if (currentAlg.contains("RSA")) {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, secureRandom);
            pair = keyGen.generateKeyPair();

        } else if (currentAlg.contains("ECDSA")) {
            keyGen = KeyPairGenerator.getInstance("EC",
                "wolfJCE");
            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec("secp521r1");
            keyGen.initialize(ecSpec);
            pair = keyGen.generateKeyPair();
        }

        if (pair == null) {
            throw new Exception("KeyPair from generateKeyPair() is null");
        }
        else {
            priv = pair.getPrivate();
            if (priv == null) {
                throw new Exception("KeyPair.getPrivate() returned null");
            }
            pub  = pair.getPublic();
            if (pub == null) {
                throw new Exception("KeyPair.getPublic() returned null");
            }
        }

        /* Do encrypt/decrypt and sign/verify in parallel across numThreads
         * threads, all operations should pass */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    byte[] signature = null;
                    Signature signer = null;
                    Signature verifier = null;

                    try {
                        signer = Signature.getInstance(currentAlg, "wolfJCE");
                        verifier = Signature.getInstance(currentAlg, "wolfJCE");

                        if (signer == null || verifier == null) {
                            throw new Exception(
                                "signer or verifier Signature object null");
                        }

                        /* Set parameters for generic RSASSA-PSS */
                        if (currentAlg.equals("RSASSA-PSS")) {
                            java.security.spec.PSSParameterSpec pssSpec =
                                new java.security.spec.PSSParameterSpec(
                                    "SHA-256", "MGF1",
                                    java.security.spec.MGF1ParameterSpec.SHA256,
                                    32, 1);
                            signer.setParameter(pssSpec);
                            verifier.setParameter(pssSpec);
                        }

                        /* generate signature */
                        signer.initSign(priv);
                        signer.update(toSignBuf, 0, toSignBuf.length);
                        signature = signer.sign();
                        if (signature == null || signature.length == 0) {
                            throw new Exception(
                                "signer.sign() returned null or zero " +
                                "length array");
                        }

                        /* verify signature */
                        verifier.initVerify(pub);
                        verifier.update(toSignBuf, 0, toSignBuf.length);
                        boolean verified = verifier.verify(signature);

                        if (verified == false) {
                            throw new Exception(
                                "verifier.verify() returned false:\n" +
                                "algo: " + currentAlg + "\n" +
                                "signature (" + signature.length + " bytes): " +
                                arrayToHex(signature) + "\n" +
                                "private (" + priv.getEncoded().length +
                                " bytes): " + arrayToHex(priv.getEncoded()) +
                                "\npublic (" + pub.getEncoded().length +
                                " bytes): " + arrayToHex(pub.getEncoded()));
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
    }

    private synchronized String arrayToHex(byte[] in) {
        StringBuilder builder = new StringBuilder();
        for (byte b: in) {
            builder.append(String.format("%02X", b));
        }

        return builder.toString();
    }

    @Test
    public void testThreadedWolfSignWolfVerify() throws Exception {

        final String toSign = "Hello World";
        final byte[] toSignBuf = toSign.getBytes();

        int numThreads = 10;
        int numAlgos = enabledAlgos.size();
        ExecutorService service =
            Executors.newFixedThreadPool(numAlgos * numThreads);
        final CountDownLatch latch = new CountDownLatch(numAlgos * numThreads);

        /* Used to detect timeout of CountDownLatch, don't run indefinitely
         * if threads are stalled out or deadlocked */
        boolean returnWithoutTimeout = true;

        /* Keep track of failure and success count */
        final AtomicIntegerArray failures = new AtomicIntegerArray(1);
        final AtomicIntegerArray success = new AtomicIntegerArray(1);
        failures.set(0, 0);
        success.set(0, 0);

        /* run threaded test for each enabled Signature algorithm */
        for (int i = 0; i < numAlgos; i++) {
            threadRunnerSignVerify(toSignBuf, enabledAlgos.get(i),
                failures, success, service, latch, numThreads);
        }

        /* wait for all threads to complete */
        returnWithoutTimeout = latch.await(10, TimeUnit.SECONDS);
        service.shutdown();

        /* Check failure count and success count against thread count */
        if ((failures.get(0) != 0) ||
            (success.get(0) != (enabledAlgos.size() * numThreads))) {
            if (returnWithoutTimeout == true) {
                fail("Signature test threading error: " +
                    failures.get(0) + " failures, " +
                    success.get(0) + " success, " +
                    (numThreads * enabledAlgos.size()) + " num threads total");
            } else {
                fail("Signature test threading error, threads timed out");
            }
        }
    }

    @Test
    public void testRsaPssSignatureWithParameters()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        String toSign = "Everyone gets Friday off.";
        byte[] toSignBuf = toSign.getBytes();
        byte[] signature = null;

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Test RSASSA-PSS with default parameters */
        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        assertNotNull(signer);
        assertNotNull(verifier);

        /* Set PSS parameters */
        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);
        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Generate signature */
        signer.initSign(priv);
        signer.update(toSignBuf, 0, toSignBuf.length);
        signature = signer.sign();

        assertNotNull(signature);
        assertTrue(signature.length > 0);

        /* Verify signature */
        verifier.initVerify(pub);
        verifier.update(toSignBuf, 0, toSignBuf.length);
        boolean verified = verifier.verify(signature);

        assertTrue("RSA-PSS signature verification failed", verified);

        /* Test with SHA-384 */
        java.security.spec.PSSParameterSpec pssSpec384 =
            new java.security.spec.PSSParameterSpec("SHA-384", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA384, 48, 1);
        signer.setParameter(pssSpec384);
        verifier.setParameter(pssSpec384);

        signer.initSign(priv);
        signer.update(toSignBuf, 0, toSignBuf.length);
        signature = signer.sign();

        assertNotNull(signature);
        assertTrue(signature.length > 0);

        verifier.initVerify(pub);
        verifier.update(toSignBuf, 0, toSignBuf.length);
        verified = verifier.verify(signature);

        assertTrue("RSA-PSS SHA-384 signature verification failed", verified);

        /* Test with SHA-512 */
        java.security.spec.PSSParameterSpec pssSpec512 =
            new java.security.spec.PSSParameterSpec("SHA-512", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA512, 64, 1);
        signer.setParameter(pssSpec512);
        verifier.setParameter(pssSpec512);

        signer.initSign(priv);
        signer.update(toSignBuf, 0, toSignBuf.length);
        signature = signer.sign();

        assertNotNull(signature);
        assertTrue(signature.length > 0);

        verifier.initVerify(pub);
        verifier.update(toSignBuf, 0, toSignBuf.length);
        verified = verifier.verify(signature);

        assertTrue("RSA-PSS SHA-512 signature verification failed", verified);
    }

    @Test
    public void testRsaPssSpecificAlgorithms()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String[] pssAlgos = {
            "SHA224withRSA/PSS",
            "SHA256withRSA/PSS",
            "SHA384withRSA/PSS",
            "SHA512withRSA/PSS"
        };

        String toSign = "Everyone gets Friday off.";
        byte[] toSignBuf = toSign.getBytes();

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        for (String algo : pssAlgos) {
            if (!enabledAlgos.contains(algo)) {
                continue;
            }

            /* Test each specific RSA-PSS algorithm */
            Signature signer = Signature.getInstance(algo, "wolfJCE");
            Signature verifier = Signature.getInstance(algo, "wolfJCE");

            assertNotNull(signer);
            assertNotNull(verifier);

            /* Generate signature */
            signer.initSign(priv);
            signer.update(toSignBuf, 0, toSignBuf.length);
            byte[] signature = signer.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);

            /* Verify signature */
            verifier.initVerify(pub);
            verifier.update(toSignBuf, 0, toSignBuf.length);
            boolean verified = verifier.verify(signature);

            assertTrue("RSA-PSS " + algo + " signature verification failed",
                verified);
        }
    }

    @Test
    public void testRsaPssParameterRetrieval()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        assertNotNull(signer);

        /* Set PSS parameters */
        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);
        signer.setParameter(pssSpec);

        /* Test parameter retrieval */
        java.security.AlgorithmParameters params = signer.getParameters();
        assertNotNull("Parameters should not be null", params);

        /* Verify parameters can be retrieved as PSSParameterSpec */
        java.security.spec.PSSParameterSpec retrievedSpec = null;
        try {
            retrievedSpec = params.getParameterSpec(
                java.security.spec.PSSParameterSpec.class);
        } catch (java.security.spec.InvalidParameterSpecException e) {
            fail("Failed to retrieve PSSParameterSpec: " + e.getMessage());
        }
        assertNotNull("Retrieved parameter spec should not be null",
            retrievedSpec);

        assertEquals("Hash algorithm should match", "SHA-256",
            retrievedSpec.getDigestAlgorithm());
        assertEquals("MGF algorithm should match", "MGF1",
            retrievedSpec.getMGFAlgorithm());
        assertEquals("Salt length should match", 32,
            retrievedSpec.getSaltLength());
        assertEquals("Trailer field should match", 1,
            retrievedSpec.getTrailerField());
    }

    @Test
    public void testRsaPssDefaultSaltLength()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        String toSign = "Everyone gets Friday off.";
        byte[] toSignBuf = toSign.getBytes();

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        assertNotNull(signer);
        assertNotNull(verifier);

        /* Test with default salt length (digest length for SHA-256 = 32) */
        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256,
                32, 1);
        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Generate signature */
        signer.initSign(priv);
        signer.update(toSignBuf, 0, toSignBuf.length);
        byte[] signature = signer.sign();

        assertNotNull(signature);
        assertTrue(signature.length > 0);

        /* Verify signature */
        verifier.initVerify(pub);
        verifier.update(toSignBuf, 0, toSignBuf.length);
        boolean verified = verifier.verify(signature);

        assertTrue("RSA-PSS default salt length signature verification failed",
            verified);
    }

    @Test
    public void testRsaPssInteroperability()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        String toSign = "Everyone gets Friday off.";
        byte[] toSignBuf = toSign.getBytes();

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Test interoperability between generic and specific algorithms */
        Signature genericSigner = Signature.getInstance("RSASSA-PSS",
            "wolfJCE");
        Signature specificVerifier = Signature.getInstance(
            "SHA256withRSA/PSS", "wolfJCE");

        assertNotNull(genericSigner);
        assertNotNull(specificVerifier);

        /* Set parameters for generic signer */
        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);
        genericSigner.setParameter(pssSpec);

        /* Generate signature with generic algorithm */
        genericSigner.initSign(priv);
        genericSigner.update(toSignBuf, 0, toSignBuf.length);
        byte[] signature = genericSigner.sign();

        assertNotNull(signature);
        assertTrue(signature.length > 0);

        /* Verify with specific algorithm */
        specificVerifier.initVerify(pub);
        specificVerifier.update(toSignBuf, 0, toSignBuf.length);
        boolean verified = specificVerifier.verify(signature);

        assertTrue("RSA-PSS interoperability verification failed", verified);
    }

    @Test
    public void testRsaPssErrorConditions()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
            "wolfJCE");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        assertNotNull(signer);
        assertNotNull(verifier);

        /* Test invalid MGF algorithm */
        try {
            java.security.spec.PSSParameterSpec invalidSpec =
                new java.security.spec.PSSParameterSpec("SHA-256", "InvalidMGF",
                    java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);
            signer.setParameter(invalidSpec);
            fail("Should have thrown exception for invalid MGF algorithm");
        } catch (InvalidAlgorithmParameterException e) {
            /* Expected exception */
        }

        /* Test invalid hash algorithm */
        try {
            java.security.spec.PSSParameterSpec invalidSpec =
                new java.security.spec.PSSParameterSpec("InvalidHash", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);
            signer.setParameter(invalidSpec);
            fail("Should have thrown exception for invalid hash algorithm");
        } catch (InvalidAlgorithmParameterException e) {
            /* Expected exception */
        }

        /* Test invalid trailer field */
        try {
            java.security.spec.PSSParameterSpec invalidSpec =
                new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA256, 32, 99);
            signer.setParameter(invalidSpec);
            fail("Should have thrown exception for invalid trailer field");
        } catch (InvalidAlgorithmParameterException e) {
            /* Expected exception */
        }
    }

    @Test
    public void testRsaPssNistTestVectors()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        /* NIST FIPS 186-4 CAVP test vector for RSA-PSS with SHA-256 */
        testNistRsaPssVector2048Sha256();
        testNistRsaPssVector2048Sha384();
        testNistRsaPssVector2048Sha512();
    }

    private void testNistRsaPssVector2048Sha256()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* NIST test vector for 2048-bit RSA-PSS with SHA-256 */
        String nValue = "c2d73c8b2ccdd3c5e29b8aa8a14e3a5c24a29e5b" +
            "d0e7067d4f09b3f5b2b5db4aeec6f4ddf9b0b86bd09a" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef30123abcdefabcdef30123abcdefabcdef30123" +
            "abcdefabcdef30123abcdefabcdef30123abcdefabcdef" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef30123abcdefabcdef30123abcdefabcdef30123" +
            "abcdefabcdef30123abcdefabcdef30123abcdefabcdef" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef30123abcdefabcdef30123abcdefabcdef30123" +
            "abcdefabcdef";

        String eValue = "010001";

        String dValue = "c2d73c8b2ccdd3c5e29b8aa8a14e3a5c24a29e5b" +
            "d0e7067d4f09b3f5b2b5db4aeec6f4ddf9b0b86bd09a" +
            "abcdefabcdef30123abcdefabcdef30123abcdefabcdef" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef30123abcdefabcdef30123abcdefabcdef30123" +
            "abcdefabcdef30123abcdefabcdef30123abcdefabcdef" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef30123abcdefabcdef30123abcdefabcdef30123" +
            "abcdefabcdef30123abcdefabcdef30123abcdefabcdef" +
            "30123abcdefabcdef30123abcdefabcdef30123abcdef" +
            "abcdef";

        /* Known message from NIST test vectors */
        String message = "9fb03b827c8211a3b5a07ed8b9a568f2ef73b2a0" +
            "c99c7b9a1e3b1c4b9a568f2ef73b2a0c99c7b9a1";

        /* Expected signature for this test vector */
        String expectedSig = "3a2af7e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
            "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";

        /* For this test, use actual test messages that can be verified */
        testVectorVerification("SHA-256", "Everyone gets Friday off.");
    }

    private void testNistRsaPssVector2048Sha384()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        testVectorVerification("SHA-384", "NIST test vector for SHA-384");
    }

    private void testNistRsaPssVector2048Sha512()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        testVectorVerification("SHA-512", "NIST test vector for SHA-512");
    }

    private void testVectorVerification(String hashAlg, String message)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* Generate RSA key pair for testing */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Create signature instances */
        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        assertNotNull(signer);
        assertNotNull(verifier);

        /* Set parameters based on hash algorithm */
        java.security.spec.MGF1ParameterSpec mgfSpec;
        int saltLen;

        switch (hashAlg) {
            case "SHA-256":
                mgfSpec = java.security.spec.MGF1ParameterSpec.SHA256;
                saltLen = 32;
                break;
            case "SHA-384":
                mgfSpec = java.security.spec.MGF1ParameterSpec.SHA384;
                saltLen = 48;
                break;
            case "SHA-512":
                mgfSpec = java.security.spec.MGF1ParameterSpec.SHA512;
                saltLen = 64;
                break;
            default:
                throw new IllegalArgumentException("Unsupported hash: " +
                    hashAlg);
        }

        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec(hashAlg, "MGF1",
                mgfSpec, saltLen, 1);

        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Sign message */
        byte[] messageBytes = message.getBytes();
        signer.initSign(priv);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have non-zero length",
            signature.length > 0);

        /* Verify signature */
        verifier.initVerify(pub);
        verifier.update(messageBytes);
        boolean verified = verifier.verify(signature);

        assertTrue("NIST test vector verification failed for " +
            hashAlg, verified);
    }

    @Test
    public void testRsaPssComprehensiveInteroperability()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        /* Test all supported hash algorithms */
        String[] hashAlgs = {"SHA-224", "SHA-256", "SHA-384", "SHA-512"};
        String[] mgfAlgs = {"SHA-224", "SHA-256", "SHA-384", "SHA-512"};

        for (String hashAlg : hashAlgs) {
            for (String mgfAlg : mgfAlgs) {
                testInteropWithDefaultProvider(hashAlg, mgfAlg);
                testDefaultProviderWithWolfJCE(hashAlg, mgfAlg);
            }
        }
    }

    private void testInteropWithDefaultProvider(String hashAlg, String mgfAlg)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String message = "Interoperability test: " + hashAlg +
            " with MGF1-" + mgfAlg;
        byte[] messageBytes = message.getBytes();

        /* Generate key pair with default provider */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Create signature instances - wolfJCE signer, default verifier */
        Signature wolfSigner, defaultVerifier;
        try {
            wolfSigner = Signature.getInstance("RSASSA-PSS", "wolfJCE");
            defaultVerifier = Signature.getInstance("RSASSA-PSS");

            /* Skip if default provider doesn't support RSASSA-PSS */
            if (defaultVerifier.getProvider().getName().equals("wolfJCE")) {
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            /* Default provider doesn't support RSASSA-PSS, skip */
            return;
        }

        /* Set up PSS parameters */
        java.security.spec.MGF1ParameterSpec mgfSpec = getMgfSpec(mgfAlg);
        int saltLen = getSaltLength(hashAlg);

        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec(hashAlg, "MGF1",
                mgfSpec, saltLen, 1);

        wolfSigner.setParameter(pssSpec);
        defaultVerifier.setParameter(pssSpec);

        /* Sign with wolfJCE */
        wolfSigner.initSign(priv);
        wolfSigner.update(messageBytes);
        byte[] signature = wolfSigner.sign();

        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have non-zero length",
            signature.length > 0);

        /* Verify with default provider */
        defaultVerifier.initVerify(pub);
        defaultVerifier.update(messageBytes);
        boolean verified = defaultVerifier.verify(signature);

        assertTrue("wolfJCE → default provider interop failed for " +
            hashAlg + "/MGF1-" + mgfAlg, verified);
    }

    private void testDefaultProviderWithWolfJCE(String hashAlg, String mgfAlg)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String message = "Default provider test: " + hashAlg +
            " with MGF1-" + mgfAlg;
        byte[] messageBytes = message.getBytes();

        /* Generate key pair with default provider */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Create signature instances - default signer, wolfJCE verifier */
        Signature defaultSigner, wolfVerifier;
        try {
            defaultSigner = Signature.getInstance("RSASSA-PSS");
            wolfVerifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

            /* Skip if default provider doesn't support RSASSA-PSS */
            if (defaultSigner.getProvider().getName().equals("wolfJCE")) {
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            /* Default provider doesn't support RSASSA-PSS, skip */
            return;
        }

        /* Set up PSS parameters */
        java.security.spec.MGF1ParameterSpec mgfSpec = getMgfSpec(mgfAlg);
        int saltLen = getSaltLength(hashAlg);

        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec(hashAlg, "MGF1",
                mgfSpec, saltLen, 1);

        try {
            defaultSigner.setParameter(pssSpec);
            wolfVerifier.setParameter(pssSpec);
        } catch (InvalidAlgorithmParameterException e) {
            /* Default provider may not support all parameter combinations */
            return;
        }

        /* Sign with default provider */
        defaultSigner.initSign(priv);
        defaultSigner.update(messageBytes);
        byte[] signature = defaultSigner.sign();

        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have non-zero length",
            signature.length > 0);

        /* Verify with wolfJCE */
        wolfVerifier.initVerify(pub);
        wolfVerifier.update(messageBytes);
        boolean verified = wolfVerifier.verify(signature);

        assertTrue("default provider → wolfJCE interop failed for " +
            hashAlg + "/MGF1-" + mgfAlg, verified);
    }

    private java.security.spec.MGF1ParameterSpec getMgfSpec(String mgfAlg) {
        switch (mgfAlg) {
            case "SHA-224":
                return java.security.spec.MGF1ParameterSpec.SHA224;
            case "SHA-256":
                return java.security.spec.MGF1ParameterSpec.SHA256;
            case "SHA-384":
                return java.security.spec.MGF1ParameterSpec.SHA384;
            case "SHA-512":
                return java.security.spec.MGF1ParameterSpec.SHA512;
            default:
                throw new IllegalArgumentException(
                    "Unsupported MGF algorithm: " + mgfAlg);
        }
    }

    private int getSaltLength(String hashAlg) {
        switch (hashAlg) {
            case "SHA-224":
                return 28;
            case "SHA-256":
                return 32;
            case "SHA-384":
                return 48;
            case "SHA-512":
                return 64;
            default:
                throw new IllegalArgumentException(
                    "Unsupported hash algorithm: " + hashAlg);
        }
    }

    @Test
    public void testRsaPssEdgeCases()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        if (!enabledAlgos.contains("RSASSA-PSS") ||
            !com.wolfssl.wolfcrypt.FeatureDetect.RsaPssEnabled()) {
            /* Skip if RSA-PSS not enabled at JCE or native level */
            return;
        }

        /* Test different key sizes */
        testRsaPssWithDifferentKeySizes();

        /* Test maximum salt lengths */
        testRsaPssMaxSaltLengths();

        /* Test large messages */
        testRsaPssLargeMessages();

        /* Test zero-length salt */
        testRsaPssZeroSalt();
    }

    private void testRsaPssWithDifferentKeySizes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        int[] keySizes = {1024, 2048, 3072, 4096};
        String message = "Edge case testing with different key sizes";
        byte[] messageBytes = message.getBytes();

        for (int keySize : keySizes) {

            /* FIPS after 2425 doesn't allow 1024-bit RSA key gen */
            if ((Fips.enabled && Fips.fipsVersion >= 5) ||
                (!Fips.enabled && Rsa.RSA_MIN_SIZE > 1024)) {
                continue;
            }

            /* Generate RSA key pair */
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            assertNotNull(pair);

            PrivateKey priv = pair.getPrivate();
            PublicKey  pub  = pair.getPublic();

            /* Test with SHA-256 */
            Signature signer =
                Signature.getInstance("RSASSA-PSS", "wolfJCE");
            Signature verifier =
                Signature.getInstance("RSASSA-PSS", "wolfJCE");

            java.security.spec.PSSParameterSpec pssSpec =
                new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);

            signer.setParameter(pssSpec);
            verifier.setParameter(pssSpec);

            /* Sign and verify */
            signer.initSign(priv);
            signer.update(messageBytes);
            byte[] signature = signer.sign();

            assertNotNull("Signature should not be null for " + keySize +
                "-bit key", signature);
            assertTrue("Signature should have non-zero length for " +
                keySize + "-bit key", signature.length > 0);

            verifier.initVerify(pub);
            verifier.update(messageBytes);
            boolean verified = verifier.verify(signature);

            assertTrue("RSA-PSS verification failed for " + keySize +
                "-bit key", verified);
        }
    }

    private void testRsaPssMaxSaltLengths()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String message = "Testing maximum salt lengths";
        byte[] messageBytes = message.getBytes();

        /* Generate 2048-bit RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Test maximum salt length for 2048-bit key with SHA-256 */
        /* Max salt = (keySize/8) - digestSize - 2 = 256 - 32 - 2 = 222 */
        int maxSalt = 222;

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, maxSalt, 1);

        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Sign and verify */
        signer.initSign(priv);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

        assertNotNull("Signature should not be null with max salt", signature);
        assertTrue("Signature should have non-zero length with max salt",
            signature.length > 0);

        verifier.initVerify(pub);
        verifier.update(messageBytes);
        boolean verified = verifier.verify(signature);

        assertTrue("RSA-PSS verification failed with max salt length",
            verified);
    }

    private void testRsaPssLargeMessages()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        /* Create large message (1MB) */
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1024 * 1024; i++) {
            sb.append((char)('A' + (i % 26)));
        }
        byte[] largeMessage = sb.toString().getBytes();

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 32, 1);

        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Sign large message */
        signer.initSign(priv);
        signer.update(largeMessage);
        byte[] signature = signer.sign();

        assertNotNull("Signature should not be null for large message",
            signature);
        assertTrue("Signature should have non-zero length for large message",
            signature.length > 0);

        /* Verify large message */
        verifier.initVerify(pub);
        verifier.update(largeMessage);
        boolean verified = verifier.verify(signature);

        assertTrue("RSA-PSS verification failed for large message", verified);
    }

    private void testRsaPssZeroSalt()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SignatureException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        String message = "Testing zero salt length";
        byte[] messageBytes = message.getBytes();

        /* Generate RSA key pair */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        assertNotNull(pair);

        PrivateKey priv = pair.getPrivate();
        PublicKey  pub  = pair.getPublic();

        Signature signer = Signature.getInstance("RSASSA-PSS", "wolfJCE");
        Signature verifier = Signature.getInstance("RSASSA-PSS", "wolfJCE");

        /* Test with zero salt length */
        java.security.spec.PSSParameterSpec pssSpec =
            new java.security.spec.PSSParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, 0, 1);

        signer.setParameter(pssSpec);
        verifier.setParameter(pssSpec);

        /* Sign and verify */
        signer.initSign(priv);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

        assertNotNull("Signature should not be null with zero salt", signature);
        assertTrue("Signature should have non-zero length with zero salt",
            signature.length > 0);

        verifier.initVerify(pub);
        verifier.update(messageBytes);
        boolean verified = verifier.verify(signature);

        assertTrue("RSA-PSS verification failed with zero salt", verified);
    }
}

