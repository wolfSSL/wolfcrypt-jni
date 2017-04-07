/* wolfCryptKeyAgreementTest.java
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

import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;

import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.ECGenParameterSpec;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.provider.jce.WolfCryptProvider;

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

    private static void printDisabledCurves() {

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
    }

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        int disabledCount = 0;

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* build list of enabled curves and key sizes,
         * getCurveSizeFromName() will return 0 if curve not found */
        Ecc tmp = new Ecc();
        for (int i = 0; i < supportedCurves.length; i++) {

            int size = tmp.getCurveSizeFromName(
                        supportedCurves[i].toUpperCase());

            if (size > 0) {
                enabledCurves.add(supportedCurves[i]);
            } else {
                disabledCurves.add(supportedCurves[i]);
            }
        }

        /* uncomment this line to print disabled curves */
        /* printDisabledCurves(); */
    }

    @Test
    public void testGetKeyAgreementFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyAgreement ka;

        /* try to get all available options we expect to have */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            ka = KeyAgreement.getInstance(wolfJCEAlgos[i], "wolfJCE");
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            ka = KeyAgreement.getInstance("NotValid", "wolfJCE");

            fail("KeyAgreement.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testDHKeyAgreement()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);
        AlgorithmParameters params = paramGen.generateParameters();

        DHParameterSpec dhParams =
            (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, new SecureRandom());

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

    @Test
    public void testDHKeyAgreementWithUpdateArgument()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException,
               ShortBufferException {

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);
        AlgorithmParameters params = paramGen.generateParameters();

        DHParameterSpec dhParams =
            (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, new SecureRandom());

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

        assertArrayEquals(secretA2, secretC);
    }

    @Test
    public void testDHKeyAgreementInterop()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidParameterSpecException, InvalidKeyException,
               InvalidAlgorithmParameterException {

        /* create DH params */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(512);
        AlgorithmParameters params = paramGen.generateParameters();

        DHParameterSpec dhParams =
            (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        /* initialize key pair generator */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "wolfJCE");
        keyGen.initialize(dhParams, new SecureRandom());

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

            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "wolfJCE");
        }

        /* Trying to use a bad curve should throw an exception */
        try {
            ecsp = new ECGenParameterSpec("invalidcurve");
            keyGen.initialize(ecsp);
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "wolfJCE");

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

    final private static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private static String b2h(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];

        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }
}

