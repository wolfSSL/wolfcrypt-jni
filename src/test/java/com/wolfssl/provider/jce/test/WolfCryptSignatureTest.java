/* wolfCryptSignatureTest.java
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.BeforeClass;

import java.util.Arrays;
import java.util.ArrayList;

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
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        "SHA1withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA"
    };

    private static ArrayList<String> enabledAlgos =
        new ArrayList<String>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        Signature sig;

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* populate enabledAlgos, some native features may be
         * compiled out */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            try {
                sig = Signature.getInstance(wolfJCEAlgos[i], "wolfJCE");
                enabledAlgos.add(wolfJCEAlgos[i]);
            } catch (NoSuchAlgorithmException e) {
                /* algo not compiled in */
            }
        }
    }

    @Test
    public void testGetSignatureFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Signature sig;

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledAlgos.size(); i++) {
            sig = Signature.getInstance(enabledAlgos.get(i), "wolfJCE");
        }

        /* asking for a bad algo should throw an exception */
        try {
            sig = Signature.getInstance("invalidalgo", "wolfJCE");
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

            SecureRandom rand =
                SecureRandom.getInstance("HashDRBG", "wolfJCE");
            assertNotNull(rand);

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), rand);
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

            SecureRandom rand =
                SecureRandom.getInstance("HashDRBG", "wolfJCE");
            assertNotNull(rand);

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), rand);
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

            SecureRandom rand =
                SecureRandom.getInstance("HashDRBG", "wolfJCE");
            assertNotNull(rand);

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), rand);
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

            SecureRandom rand =
                SecureRandom.getInstance("HashDRBG", "wolfJCE");
            assertNotNull(rand);

            /* generate key pair */
            KeyPair pair = generateKeyPair(enabledAlgos.get(i), rand);
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
}

