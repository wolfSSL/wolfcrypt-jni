/* WolfCryptMlDsaKeyFactoryTest.java
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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.util.Arrays;

import com.wolfssl.provider.jce.WolfCryptMlDsaPrivateKey;
import com.wolfssl.provider.jce.WolfCryptMlDsaPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for ML-DSA KeyFactory service.
 */
public class WolfCryptMlDsaKeyFactoryTest {

    private static final String[] LEVEL_NAMES = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    };

    private static boolean mlDsaEnabled = false;
    private static KeyPair[] kps = new KeyPair[3];

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("JCE WolfCryptMlDsaKeyFactoryTest Class");

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

        for (int i = 0; i < 3; i++) {
            kps[i] = KeyPairGenerator.getInstance(LEVEL_NAMES[i], "wolfJCE")
                .generateKeyPair();
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-DSA not compiled in", mlDsaEnabled);
    }

    @Test
    public void getInstanceForAllAliases() throws Exception {

        assumeEnabled();

        KeyFactory.getInstance("ML-DSA", "wolfJCE");
        KeyFactory.getInstance("ML-DSA-44", "wolfJCE");
        KeyFactory.getInstance("ML-DSA-65", "wolfJCE");
        KeyFactory.getInstance("ML-DSA-87", "wolfJCE");
        KeyFactory.getInstance("2.16.840.1.101.3.4.3.17", "wolfJCE");
        KeyFactory.getInstance("2.16.840.1.101.3.4.3.18", "wolfJCE");
        KeyFactory.getInstance("2.16.840.1.101.3.4.3.19", "wolfJCE");
    }

    @Test
    public void pkcs8RoundTripAllLevels() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        for (int i = 0; i < 3; i++) {
            byte[] der = kps[i].getPrivate().getEncoded();
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(der));
            assertEquals(LEVEL_NAMES[i], "ML-DSA", priv.getAlgorithm());
            assertEquals("PKCS#8", priv.getFormat());
            assertTrue(Arrays.equals(der, priv.getEncoded()));
        }
    }

    @Test
    public void x509RoundTripAllLevels() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        for (int i = 0; i < 3; i++) {
            byte[] der = kps[i].getPublic().getEncoded();
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(der));
            assertEquals(LEVEL_NAMES[i], "ML-DSA", pub.getAlgorithm());
            assertEquals("X.509", pub.getFormat());
            assertTrue(Arrays.equals(der, pub.getEncoded()));
        }
    }

    @Test
    public void getKeySpecPkcs8() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        PKCS8EncodedKeySpec spec = kf.getKeySpec(kps[1].getPrivate(),
            PKCS8EncodedKeySpec.class);
        assertNotNull(spec);
        assertTrue(Arrays.equals(kps[1].getPrivate().getEncoded(),
            spec.getEncoded()));
    }

    @Test
    public void getKeySpecX509() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        X509EncodedKeySpec spec = kf.getKeySpec(kps[1].getPublic(),
            X509EncodedKeySpec.class);
        assertNotNull(spec);
        assertTrue(Arrays.equals(kps[1].getPublic().getEncoded(),
            spec.getEncoded()));
    }

    @Test
    public void translateKeyWolfReturnsSameRef() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        Key t1 = kf.translateKey(kps[1].getPublic());
        Key t2 = kf.translateKey(kps[1].getPrivate());
        assertSame(kps[1].getPublic(), t1);
        assertSame(kps[1].getPrivate(), t2);
    }

    @Test
    public void translateKeyForeignWraps() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        final byte[] spki = kps[2].getPublic().getEncoded();
        PublicKey foreign = new PublicKey() {
            public String getAlgorithm() { return "ML-DSA"; }
            public String getFormat()    { return "X.509"; }
            public byte[] getEncoded()   { return spki.clone(); }
        };

        Key t = kf.translateKey(foreign);
        assertTrue(t instanceof WolfCryptMlDsaPublicKey);
        assertEquals(MlDsa.ML_DSA_87,
            ((WolfCryptMlDsaPublicKey) t).getLevel());

        /* Translated key produces a working signature verifier. */
        byte[] msg = "interop".getBytes();
        Signature s = Signature.getInstance("ML-DSA-87", "wolfJCE");
        s.initSign(kps[2].getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        Signature v = Signature.getInstance("ML-DSA-87", "wolfJCE");
        v.initVerify((PublicKey) t);
        v.update(msg);
        assertTrue(v.verify(sig));
    }

    @Test
    public void signedByGeneratedKeyVerifiesViaSignature() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        byte[] msg = "kf->sig".getBytes();
        for (int i = 0; i < 3; i++) {
            PrivateKey priv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(kps[i].getPrivate().getEncoded()));
            PublicKey pub = kf.generatePublic(
                new X509EncodedKeySpec(kps[i].getPublic().getEncoded()));

            Signature s = Signature.getInstance(LEVEL_NAMES[i], "wolfJCE");
            s.initSign(priv);
            s.update(msg);
            byte[] sig = s.sign();

            Signature v = Signature.getInstance(LEVEL_NAMES[i], "wolfJCE");
            v.initVerify(pub);
            v.update(msg);
            assertTrue(LEVEL_NAMES[i], v.verify(sig));
        }
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateRejectsX509Spec() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
        kf.generatePrivate(
            new X509EncodedKeySpec(kps[1].getPublic().getEncoded()));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicRejectsPkcs8Spec() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
        kf.generatePublic(
            new PKCS8EncodedKeySpec(kps[1].getPrivate().getEncoded()));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateRejectsMalformedDer() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
        kf.generatePrivate(new PKCS8EncodedKeySpec(new byte[128]));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicRejectsMalformedDer() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
        kf.generatePublic(new X509EncodedKeySpec(new byte[128]));
    }

    @Test(expected = InvalidKeyException.class)
    public void translateKeyRejectsForeignNonMlDsa() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        /* Foreign RSA-like key with an X.509 format claim but obviously
         * non-ML-DSA encoded contents. */
        PublicKey foreign = KeyFactory.getInstance("RSA", "wolfJCE")
            .generatePublic(new RSAPublicKeySpec(
                new BigInteger("C0FFEE0123456789ABCDEF0123456789ABCDEF" +
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" +
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" +
                    "0123456789ABCDEF0123456789ABCDEF", 16),
                BigInteger.valueOf(65537)));

        kf.translateKey(foreign);
    }

    @Test(expected = InvalidKeyException.class)
    public void translateKeyRejectsForeignWrongFormat() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        PublicKey foreign = new PublicKey() {
            public String getAlgorithm() { return "ML-DSA"; }
            public String getFormat()    { return "FOO"; }
            public byte[] getEncoded()   { return new byte[]{0,1,2,3}; }
        };
        kf.translateKey(foreign);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecOnDestroyedKeyFails() throws Exception {

        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");

        WolfCryptMlDsaPublicKey pub = new WolfCryptMlDsaPublicKey(
            kps[0].getPublic().getEncoded());
        pub.destroy();
        kf.getKeySpec(pub, X509EncodedKeySpec.class);
    }
}
