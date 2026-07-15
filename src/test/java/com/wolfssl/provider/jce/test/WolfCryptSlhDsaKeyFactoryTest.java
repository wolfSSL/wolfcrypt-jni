/* WolfCryptSlhDsaKeyFactoryTest.java
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
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for the SLH-DSA KeyFactory service.
 */
public class WolfCryptSlhDsaKeyFactoryTest {

    private static final String GEN_NAME = "SLH-DSA-SHA2-128f";

    private static boolean slhDsaEnabled = false;
    private static boolean genAvailable = false;
    private static KeyPair kp = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("JCE WolfCryptSlhDsaKeyFactoryTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        slhDsaEnabled = FeatureDetect.SlhDsaEnabled();
        if (!slhDsaEnabled) {
            System.out.println("SLH-DSA test skipped: NOT_COMPILED_IN");
            return;
        }

        try {
            kp = KeyPairGenerator.getInstance(GEN_NAME, "wolfJCE")
                .generateKeyPair();
            genAvailable = true;
        } catch (Exception e) {
            /* SHA2-128f not compiled into this build */
        }
    }

    private void assumeReady() {
        Assume.assumeTrue("SLH-DSA not compiled in", slhDsaEnabled);
        Assume.assumeTrue(GEN_NAME + " not available", genAvailable);
    }

    @Test
    public void publicKeyX509RoundTrip() throws Exception {
        assumeReady();

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        byte[] spki = kp.getPublic().getEncoded();

        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki));
        assertEquals("SLH-DSA", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());
        assertArrayEquals(spki, pub.getEncoded());

        X509EncodedKeySpec spec =
            kf.getKeySpec(pub, X509EncodedKeySpec.class);
        assertArrayEquals(spki, spec.getEncoded());
    }

    @Test
    public void privateKeyPkcs8RoundTrip() throws Exception {
        assumeReady();

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        assertEquals("SLH-DSA", priv.getAlgorithm());
        assertEquals("PKCS#8", priv.getFormat());
        assertArrayEquals(pkcs8, priv.getEncoded());

        PKCS8EncodedKeySpec spec =
            kf.getKeySpec(priv, PKCS8EncodedKeySpec.class);
        assertArrayEquals(pkcs8, spec.getEncoded());
    }

    @Test
    public void generatePublicRejectsPkcs8() throws Exception {
        assumeReady();

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        try {
            kf.generatePublic(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            fail("expected InvalidKeySpecException");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void generatePrivateRejectsX509() throws Exception {
        assumeReady();

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        try {
            kf.generatePrivate(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            fail("expected InvalidKeySpecException");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void translateKey() throws Exception {
        assumeReady();

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        PublicKey pub = (PublicKey) kf.translateKey(kp.getPublic());
        assertEquals("SLH-DSA", pub.getAlgorithm());
        assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded());
    }

    @Test
    public void getInstanceForAllNames() throws Exception {
        Assume.assumeTrue("SLH-DSA not compiled in", slhDsaEnabled);

        KeyFactory.getInstance("SLH-DSA", "wolfJCE");

        /* Per-set services and OID aliases (.20 - .31) are registered
         * only for parameter sets compiled into native wolfSSL */
        for (int i = 0; i < PARAM_NAMES.length; i++) {
            String oid = "2.16.840.1.101.3.4.3." + (20 + i);

            if (FeatureDetect.SlhDsaParamEnabled(PARAM_IDS[i])) {
                KeyFactory.getInstance(PARAM_NAMES[i], "wolfJCE");
                KeyFactory.getInstance(oid, "wolfJCE");
            }
            else {
                for (String alg : new String[] { PARAM_NAMES[i], oid }) {
                    try {
                        KeyFactory.getInstance(alg, "wolfJCE");
                        fail(alg + " not compiled into native wolfSSL, " +
                            "should not be registered");
                    } catch (NoSuchAlgorithmException e) {
                        /* expected */
                    }
                }
            }
        }
    }

    @Test
    public void perSetFactoryRejectsMismatchedKey() throws Exception {
        assumeReady();

        /* Needs a parameter set different from kp (SLH-DSA-SHA2-128f)
         * that is compiled into native wolfSSL, its KeyFactory service
         * is not registered otherwise */
        Assume.assumeTrue("SLH-DSA-SHAKE-128s not compiled in",
            FeatureDetect.SlhDsaParamEnabled(SlhDsa.SLH_DSA_SHAKE_128S));

        /* A parameter-set-locked KeyFactory must reject keys of a
         * different set. kp is SLH-DSA-SHA2-128f. */
        KeyFactory kf =
            KeyFactory.getInstance("SLH-DSA-SHAKE-128s", "wolfJCE");

        try {
            kf.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            fail("expected InvalidKeySpecException for set mismatch");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }

        try {
            kf.generatePrivate(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            fail("expected InvalidKeySpecException for set mismatch");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void nullAlgorithmIdParametersAccepted() throws Exception {
        assumeReady();

        /* RFC 9909 omits the AlgorithmIdentifier parameters for SLH-DSA,
         * but the JDK X.509 stack can re-encode a certificate
         * SubjectPublicKeyInfo with an explicit NULL parameters field when
         * it hands the public key to this KeyFactory by OID. That form
         * must decode to the same key as the canonical no-parameters form. */
        byte[] spki = kp.getPublic().getEncoded();

        /* Recover the raw public key bytes via the JNI layer. */
        com.wolfssl.wolfcrypt.SlhDsa k = new com.wolfssl.wolfcrypt.SlhDsa();
        byte[] rawPub;
        try {
            k.importPublicKeyDer(spki);
            rawPub = k.exportPublicKey();
        }
        finally {
            k.releaseNativeStruct();
        }

        /* Rebuild the SPKI with AlgorithmIdentifier parameters = NULL. */
        byte[] algIdNull = tlv(0x30, concat(SHA2_128F_OID,
            new byte[] { (byte) 0x05, (byte) 0x00 }));
        byte[] bitString = tlv(0x03,
            concat(new byte[] { 0x00 }, rawPub));
        byte[] spkiNull = tlv(0x30, concat(algIdNull, bitString));

        KeyFactory kf = KeyFactory.getInstance("SLH-DSA", "wolfJCE");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spkiNull));
        assertEquals("SLH-DSA", pub.getAlgorithm());

        /* The NULL-parameters form normalizes to the same canonical RFC 9909
         * (absent-parameters) encoding. */
        assertArrayEquals(spki, pub.getEncoded());

        /* getKeySpec() of a foreign key holding the NULL-parameters form
         * also returns the canonical encoding: keys are normalized through
         * translateKey(), not passed through byte-for-byte. */
        final byte[] foreignEncoded = spkiNull;
        PublicKey foreign = new PublicKey() {
            public String getAlgorithm() {
                return "SLH-DSA";
            }
            public String getFormat() {
                return "X.509";
            }
            public byte[] getEncoded() {
                return foreignEncoded.clone();
            }
        };

        X509EncodedKeySpec normalized =
            kf.getKeySpec(foreign, X509EncodedKeySpec.class);

        assertArrayEquals(spki, normalized.getEncoded());
    }

    /* OID TLV for 2.16.840.1.101.3.4.3.21 (id-slh-dsa-sha2-128f). */
    private static final byte[] SHA2_128F_OID = {
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
        (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x03,
        (byte) 0x15
    };

    /* All 12 per-set KeyFactory service names. */
    private static final String[] PARAM_NAMES = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };

    /* Parameter set IDs, same order as PARAM_NAMES */
    private static final int[] PARAM_IDS = {
        SlhDsa.SLH_DSA_SHA2_128S,  SlhDsa.SLH_DSA_SHA2_128F,
        SlhDsa.SLH_DSA_SHA2_192S,  SlhDsa.SLH_DSA_SHA2_192F,
        SlhDsa.SLH_DSA_SHA2_256S,  SlhDsa.SLH_DSA_SHA2_256F,
        SlhDsa.SLH_DSA_SHAKE_128S, SlhDsa.SLH_DSA_SHAKE_128F,
        SlhDsa.SLH_DSA_SHAKE_192S, SlhDsa.SLH_DSA_SHAKE_192F,
        SlhDsa.SLH_DSA_SHAKE_256S, SlhDsa.SLH_DSA_SHAKE_256F
    };

    /* DER TLV with a definite length (content up to 0xFFFF bytes). */
    private static byte[] tlv(int tag, byte[] content) {
        int n = content.length;
        byte[] len;
        if (n < 0x80) {
            len = new byte[] { (byte) n };
        } else if (n < 0x100) {
            len = new byte[] { (byte) 0x81, (byte) n };
        } else {
            len = new byte[] { (byte) 0x82, (byte) (n >> 8), (byte) n };
        }
        byte[] out = new byte[1 + len.length + n];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, n);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
