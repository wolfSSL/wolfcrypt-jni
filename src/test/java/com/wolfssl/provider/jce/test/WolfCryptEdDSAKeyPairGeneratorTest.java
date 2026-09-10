/* WolfCryptEdDSAKeyPairGeneratorTest.java
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.wolfssl.provider.jce.WolfCryptEdDSAPrivateKey;
import com.wolfssl.provider.jce.WolfCryptEdDSAPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Tests for wolfJCE EdDSA KeyPairGenerator services.
 */
public class WolfCryptEdDSAKeyPairGeneratorTest {

    private static boolean ed25519Enabled = false;
    private static boolean ed448Enabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {

        System.out.println("JCE WolfCryptEdDSAKeyPairGeneratorTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        assertNotNull(Security.getProvider("wolfJCE"));

        ed25519Enabled = FeatureDetect.Ed25519KeyGenEnabled();
        ed448Enabled = FeatureDetect.Ed448KeyGenEnabled();
    }

    private void assumeAnyEnabled() {
        Assume.assumeTrue("No EdDSA curve compiled in",
            ed25519Enabled || ed448Enabled);
    }

    private static String curveOf(KeyPair kp) {

        assertTrue(kp.getPublic() instanceof WolfCryptEdDSAPublicKey);
        assertTrue(kp.getPrivate() instanceof WolfCryptEdDSAPrivateKey);
        String c = ((WolfCryptEdDSAPublicKey) kp.getPublic()).getCurveName();
        assertEquals(c,
            ((WolfCryptEdDSAPrivateKey) kp.getPrivate()).getCurveName());

        return c;
    }

    /* JDK 11+ NamedParameterSpec by reflection, null when absent */
    private static AlgorithmParameterSpec namedSpec(String name)
        throws Exception {

        try {
            Class<?> cls = Class.forName(
                "java.security.spec.NamedParameterSpec");
            return (AlgorithmParameterSpec) cls.getConstructor(String.class)
                .newInstance(name);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private static void assertPairWorks(KeyPair kp, String curve)
        throws Exception {

        byte[] msg = "kpg".getBytes();
        Signature s = Signature.getInstance(curve, "wolfJCE");
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        s.initVerify(kp.getPublic());
        s.update(msg);
        assertTrue(s.verify(sig));
    }

    @Test
    public void getInstanceForAllAliases() throws Exception {

        assumeAnyEnabled();

        /* the umbrella generator is registered with either curve */
        for (String n : new String[] { "EdDSA", "EDDSA" }) {
            assertEquals("wolfJCE", KeyPairGenerator.getInstance(n,
                "wolfJCE").getProvider().getName());
        }
        if (ed25519Enabled) {
            for (String n : new String[] { "Ed25519", "ED25519",
                    "1.3.101.112", "OID.1.3.101.112" }) {
                assertEquals("wolfJCE", KeyPairGenerator.getInstance(n,
                    "wolfJCE").getProvider().getName());
            }
        }
        if (ed448Enabled) {
            for (String n : new String[] { "Ed448", "ED448", "1.3.101.113",
                    "OID.1.3.101.113" }) {
                assertEquals("wolfJCE", KeyPairGenerator.getInstance(n,
                    "wolfJCE").getProvider().getName());
            }
        }
        else {
            try {
                KeyPairGenerator.getInstance("Ed448", "wolfJCE");
                fail("Ed448 KPG should not be registered");
            } catch (NoSuchAlgorithmException e) {
                /* expected */
            }
        }
    }

    @Test
    public void defaultsWithoutInitialize() throws Exception {

        assumeAnyEnabled();

        if (ed25519Enabled) {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519", "wolfJCE")
                .generateKeyPair();
            assertEquals("Ed25519", curveOf(kp));
            assertPairWorks(kp, "Ed25519");

            /* Umbrella defaults to Ed25519 like SunEC */
            KeyPair u = KeyPairGenerator.getInstance("EdDSA", "wolfJCE")
                .generateKeyPair();
            assertEquals("Ed25519", curveOf(u));
            assertPairWorks(u, "EdDSA");
        }
        else {
            /* without Ed25519 the umbrella falls back to Ed448 */
            KeyPair u = KeyPairGenerator.getInstance("EdDSA", "wolfJCE")
                .generateKeyPair();
            assertEquals("Ed448", curveOf(u));
            assertPairWorks(u, "EdDSA");
        }
        if (ed448Enabled) {
            KeyPair kp = KeyPairGenerator.getInstance("Ed448", "wolfJCE")
                .generateKeyPair();
            assertEquals("Ed448", curveOf(kp));
            assertPairWorks(kp, "Ed448");
        }
    }

    @Test
    public void initializeWithKeySize() throws Exception {

        /* key sizes no EdDSA curve accepts */
        int[] badKeySizes = new int[] {
            0, 1, 224, 254, 257, 384, 447, 449, 512, 2048, -1
        };

        assumeAnyEnabled();

        KeyPairGenerator g = KeyPairGenerator.getInstance("EdDSA", "wolfJCE");

        if (ed25519Enabled) {
            g.initialize(255);
            assertEquals("Ed25519", curveOf(g.generateKeyPair()));
            g.initialize(256, new SecureRandom());
            assertEquals("Ed25519", curveOf(g.generateKeyPair()));
        }
        else {
            try {
                g.initialize(255);
                fail("Ed25519 size accepted without Ed25519");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }

        if (ed448Enabled) {
            g.initialize(448);
            assertEquals("Ed448", curveOf(g.generateKeyPair()));
            if (ed25519Enabled) {
                /* and back */
                g.initialize(255);
                assertEquals("Ed25519", curveOf(g.generateKeyPair()));
            }

            KeyPairGenerator g448 = KeyPairGenerator.getInstance("Ed448",
                "wolfJCE");
            g448.initialize(448);
            assertEquals("Ed448", curveOf(g448.generateKeyPair()));
            try {
                g448.initialize(255);
                fail("Ed448 generator accepted 255");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }
        else {
            try {
                g.initialize(448);
                fail("Ed448 size accepted without Ed448");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }

        for (int bad : badKeySizes) {
            try {
                g.initialize(bad);
                fail("key size " + bad + " accepted");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }

        if (ed25519Enabled) {
            KeyPairGenerator g25519 = KeyPairGenerator.getInstance(
                "Ed25519", "wolfJCE");
            g25519.initialize(255);
            g25519.initialize(256);
            try {
                g25519.initialize(448);
                fail("Ed25519 generator accepted 448");
            } catch (InvalidParameterException e) {
                /* expected */
            }
            /* still usable after a rejected initialize */
            assertEquals("Ed25519", curveOf(g25519.generateKeyPair()));
        }
    }

    @Test
    public void initializeWithSpec() throws Exception {

        assumeAnyEnabled();

        KeyPairGenerator g = KeyPairGenerator.getInstance("EdDSA", "wolfJCE");

        /* ECGenParameterSpec works on every JDK, names are case
         * insensitive and OID strings are accepted */
        if (ed25519Enabled) {
            g.initialize(new ECGenParameterSpec("ed25519"));
            assertEquals("Ed25519", curveOf(g.generateKeyPair()));
            g.initialize(new ECGenParameterSpec("1.3.101.112"));
            assertEquals("Ed25519", curveOf(g.generateKeyPair()));
        }
        else {
            try {
                g.initialize(new ECGenParameterSpec("Ed25519"));
                fail("Ed25519 spec accepted without Ed25519");
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }

        if (ed448Enabled) {
            g.initialize(new ECGenParameterSpec("Ed448"), new SecureRandom());
            assertEquals("Ed448", curveOf(g.generateKeyPair()));
            g.initialize(new ECGenParameterSpec("OID.1.3.101.113"));
            assertEquals("Ed448", curveOf(g.generateKeyPair()));
        }
        else {
            try {
                g.initialize(new ECGenParameterSpec("Ed448"));
                fail("Ed448 spec accepted without Ed448");
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }
        if (ed25519Enabled && ed448Enabled) {
            KeyPairGenerator g25519 = KeyPairGenerator.getInstance(
                "Ed25519", "wolfJCE");
            try {
                g25519.initialize(new ECGenParameterSpec("Ed448"));
                fail("Ed25519 generator accepted an Ed448 spec");
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }

        /* JDK 11+ NamedParameterSpec */
        AlgorithmParameterSpec nps = namedSpec("Ed25519");
        if (nps != null) {
            if (ed25519Enabled) {
                g.initialize(nps);
                assertEquals("Ed25519", curveOf(g.generateKeyPair()));
            }
            if (ed448Enabled) {
                g.initialize(namedSpec("Ed448"));
                assertEquals("Ed448", curveOf(g.generateKeyPair()));
            }
            try {
                g.initialize(namedSpec("X25519"));
                fail("X25519 spec accepted");
            } catch (InvalidAlgorithmParameterException e) {
                /* expected */
            }
        }

        try {
            g.initialize(new ECGenParameterSpec("secp256r1"));
            fail("secp256r1 accepted");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
        try {
            g.initialize(new RSAKeyGenParameterSpec(2048,
                RSAKeyGenParameterSpec.F4));
            fail("RSA spec accepted");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
        try {
            g.initialize((AlgorithmParameterSpec) null);
            fail("null spec accepted");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
    }

    @Test
    public void generatedKeysAreDistinctAndConsistent() throws Exception {

        assumeAnyEnabled();

        for (String curve : new String[] { "Ed25519", "Ed448" }) {
            if ((curve.equals("Ed25519") && !ed25519Enabled) ||
                (curve.equals("Ed448") && !ed448Enabled)) {
                continue;
            }
            KeyPairGenerator g = KeyPairGenerator.getInstance(curve,
                "wolfJCE");
            Set<String> seen = new HashSet<String>();
            for (int i = 0; i < 20; i++) {
                KeyPair kp = g.generateKeyPair();
                assertEquals(curve, curveOf(kp));
                WolfCryptEdDSAPrivateKey priv =
                    (WolfCryptEdDSAPrivateKey) kp.getPrivate();
                WolfCryptEdDSAPublicKey pub =
                    (WolfCryptEdDSAPublicKey) kp.getPublic();
                /* private key carries the matching public key */
                assertArrayEquals(pub.getRawPublicKey(),
                    priv.getRawPublicKey());
                assertTrue(seen.add(Arrays.toString(pub.getRawPublicKey())));
                assertPairWorks(kp, curve);
            }
        }
    }
}
