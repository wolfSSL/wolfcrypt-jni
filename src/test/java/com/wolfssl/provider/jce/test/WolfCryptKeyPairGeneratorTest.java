/* wolfCryptKeyPairGeneratorTest.java
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

import java.util.ArrayList;
import java.math.BigInteger;

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
import com.wolfssl.wolfcrypt.test.Util;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptKeyPairGeneratorTest {

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

    private static int supportedKeySizes[] = {
        112, 128, 160, 192, 224, 239, 256, 320, 384, 521
    };

    private static ArrayList<Integer> enabledKeySizes =
        new ArrayList<Integer>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

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

                if (!enabledKeySizes.contains(new Integer(size))) {
                    enabledKeySizes.add(new Integer(size));
                }
            }
        }
    }

    @Test
    public void testGetKeyPairGeneratorFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");

        /* getting a garbage algorithm should throw an exception */
        try {
            kpg = KeyPairGenerator.getInstance("NotValid", "wolfJCE");

            fail("KeyPairGenerator.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testKeyPairGeneratorEccInitializeWithParamSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all supported curves */
        for (int i = 0; i < enabledCurves.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(i));
            kpg.initialize(ecSpec);

            /* bad curve should fail */
            try {
                ecSpec = new ECGenParameterSpec("BADCURVE");
                kpg.initialize(ecSpec);
            } catch (InvalidAlgorithmParameterException e) {}
        }
    }

    @Test
    public void testKeyPairGeneratorEccInitializeWithKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all supported key sizes */
        for (int i = 0; i < enabledKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            kpg.initialize(enabledKeySizes.get(i));

            /* bad key size should fail */
            try {
                kpg.initialize(9999);
            } catch (WolfCryptException e) {}
        }
    }

    @Test
    public void testKeyPairGeneratorEccKeyGenAllCurves()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try generating keys for all supported curves */
        for (int i = 0; i < enabledCurves.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(i));
            kpg.initialize(ecSpec);

            KeyPair kp = kpg.generateKeyPair();
        }
    }

    @Test
    public void testKeyPairGeneratorEccMultipleInits()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (enabledCurves.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(0));

            kpg.initialize(ecSpec);
            kpg.initialize(ecSpec);
        }
    }

    @Test
    public void testKeyPairGeneratorEccMultipleKeyGen()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        if (enabledCurves.size() > 0) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");

            ECGenParameterSpec ecSpec =
                new ECGenParameterSpec(enabledCurves.get(0));
            kpg.initialize(ecSpec);

            KeyPair kp1 = kpg.generateKeyPair();
            KeyPair kp2 = kpg.generateKeyPair();
        }
    }

    @Test
    public void testKeyPairGeneratorDhInitializeWithKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidAlgorithmParameterException {

        /* try initializing KPG for all supported key sizes */
        //for (int i = 0; i < enabledKeySizes.size(); i++) {

            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");

            byte[] prime = Util.h2b(
                "B0A108069C0813BA59063CBC30D5F500C14F44A7D6EF4AC625271CE8D" +
                "296530A5C91DDA2C29484BF7DB2449F9BD2C18AC5BE725CA7E791E6D4" +
                "9F7307855B6648C770FAB4EE02C93D9A4ADA3DC1463E1969D1174607A" +
                "34D9F2B9617396D308D2AF394D375CFA075E6F2921F1A7005AA048357" +
                "30FBDA76933850E827FD63EE3CE5B7C809AE6F50358E84CE4A00E9127" +
                "E5A31D733FC211376CC1630DB0CFCC562A735B8EFB7B0ACC036F6D9C9" +
                "4648F94090002B1BAA6CE31AC30B039E1BC246E4484E22736FC35FD49" +
                "AD6300748D68C90ABD4F6F1E348D3584BA6B9CD29BF681F084B63862F" +
                "5C6BD6B60665F7A6DC00676BBBC3A94183FBC7FAC8E21E7EAF003F93"
            );

            byte[] base = new byte[] { 0x02 };

            /*byte[] prime = new byte[] {

                (byte)0xB0, (byte)0xA1, (byte)0x08, (byte)0x06,
                (byte)0x9C, (byte)0x08, (byte)0x13, (byte)0xBA,
                (byte)0x59, (byte)0x06, (byte)0x3C, (byte)0xBC,
                (byte)0x30, (byte)0xD5, (byte)0xF5, (byte)0x00,
                (byte)0xC1, (byte)0x4F, (byte)0x44, (byte)0xA7,
                (byte)0xD6, (byte)0xEF, (byte)0x4A, (byte)0xC6,
                (byte)0x25, (byte)0x27, (byte)0x1C, (byte)0xE8,
                (byte)0xD2, (byte)0x96, (byte)0x53, (byte)0x0A,
                (byte)0x5C, (byte)0x91, (byte)0xDD, (byte)0xA2,
                (byte)0xC2, (byte)0x94, (byte)0x84, (byte)0xBF,
                (byte)0x7D, (byte)0xB2, (byte)0x44, (byte)0x9F,
                (byte)0x9B, (byte)0xD2, (byte)0xC1, (byte)0x8A,
                (byte)0xC5, (byte)0xBE, (byte)0x72, (byte)0x5C,
                (byte)0xA7, (byte)0xE7, (byte)0x91, (byte)0xE6,
                (byte)0xD4, (byte)0x9F, (byte)0x73, (byte)0x07,
                (byte)0x85, (byte)0x5B, (byte)0x66, (byte)0x48,
                (byte)0xC7, (byte)0x70, (byte)0xFA, (byte)0xB4,
                (byte)0xEE, (byte)0x02, (byte)0xC9, (byte)0x3D,
                (byte)0x9A, (byte)0x4A, (byte)0xDA, (byte)0x3D,
                (byte)0xC1, (byte)0x46, (byte)0x3E, (byte)0x19,
                (byte)0x69, (byte)0xD1, (byte)0x17, (byte)0x46,
                (byte)0x07, (byte)0xA3, (byte)0x4D, (byte)0x9F,
                (byte)0x2B, (byte)0x96, (byte)0x17, (byte)0x39,
                (byte)0x6D, (byte)0x30, (byte)0x8D, (byte)0x2A,
                (byte)0xF3, (byte)0x94, (byte)0xD3, (byte)0x75,
                (byte)0xCF, (byte)0xA0, (byte)0x75, (byte)0xE6,
                (byte)0xF2, (byte)0x92, (byte)0x1F, (byte)0x1A,
                (byte)0x70, (byte)0x05, (byte)0xAA, (byte)0x04,
                (byte)0x83, (byte)0x57, (byte)0x30, (byte)0xFB,
                (byte)0xDA, (byte)0x76, (byte)0x93, (byte)0x38,
                (byte)0x50, (byte)0xE8, (byte)0x27, (byte)0xFD,
                (byte)0x63, (byte)0xEE, (byte)0x3C, (byte)0xE5,
                (byte)0xB7, (byte)0xC8, (byte)0x09, (byte)0xAE,
                (byte)0x6F, (byte)0x50, (byte)0x35, (byte)0x8E,
                (byte)0x84, (byte)0xCE, (byte)0x4A, (byte)0x00,
                (byte)0xE9, (byte)0x12, (byte)0x7E, (byte)0x5A,
                (byte)0x31, (byte)0xD7, (byte)0x33, (byte)0xFC,
                (byte)0x21, (byte)0x13, (byte)0x76, (byte)0xCC,
                (byte)0x16, (byte)0x30, (byte)0xDB, (byte)0x0C,
                (byte)0xFC, (byte)0xC5, (byte)0x62, (byte)0xA7,
                (byte)0x35, (byte)0xB8, (byte)0xEF, (byte)0xB7,
                (byte)0xB0, (byte)0xAC, (byte)0xC0, (byte)0x36,
                (byte)0xF6, (byte)0xD9, (byte)0xC9, (byte)0x46,
                (byte)0x48, (byte)0xF9, (byte)0x40, (byte)0x90,
                (byte)0x00, (byte)0x2B, (byte)0x1B, (byte)0xAA,
                (byte)0x6C, (byte)0xE3, (byte)0x1A, (byte)0xC3,
                (byte)0x0B, (byte)0x03, (byte)0x9E, (byte)0x1B,
                (byte)0xC2, (byte)0x46, (byte)0xE4, (byte)0x48, (byte)0x4E, (byte)0x22, (byte)0x73, (byte)0x6F, (byte)0xC3, (byte)0x5F, (byte)0xD4, (byte)0x9A, (byte)0xD6, (byte)0x30, (byte)0x07, (byte)0x48, (byte)0xD6, (byte)0x8C, (byte)0x90, (byte)0xAB, (byte)0xD4, (byte)0xF6, (byte)0xF1, (byte)0xE3, (byte)0x48, (byte)0xD3, (byte)0x58, (byte)0x4B, (byte)0xA6, (byte)0xB9, (byte)0xCD, (byte)0x29, (byte)0xBF, (byte)0x68, (byte)0x1F, (byte)0x08, (byte)0x4B, (byte)0x63, (byte)0x86, (byte)0x2F, (byte)0x5C, (byte)0x6B, (byte)0xD6, (byte)0xB6, (byte)0x06, (byte)0x65, (byte)0xF7, (byte)0xA6, (byte)0xDC, (byte)0x00, (byte)0x67, (byte)0x6B, (byte)0xBB, (byte)0xC3, (byte)0xA9, (byte)0x41, (byte)0x83, (byte)0xFB, (byte)0xC7, (byte)0xFA, (byte)0xC8, (byte)0xE2, (byte)0x1E, (byte)0x7E, (byte)0xAF, (byte)0x00, (byte)0x3F, (byte)0x93
            };*/

            //kpg.initialize(512);
            DHParameterSpec spec = new DHParameterSpec(
                    new BigInteger(prime),
                    new BigInteger(base),
                    512);
            kpg.initialize(spec);
            
            KeyPair kp1 = kpg.generateKeyPair();

            /* bad key size should fail */
            //try {
            //    kpg.initialize(9999);
            //} catch (WolfCryptException e) {}
        //}
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

