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
                fail("Signature verification failed when generating with " +
                        "wolfJCE and verifying with system default JCE " +
                        "provider");
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
}

