/* WolfCryptSlhDsaKeyTest.java
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.security.auth.Destroyable;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for the SLH-DSA PublicKey and PrivateKey classes.
 */
public class WolfCryptSlhDsaKeyTest {

    private static final String GEN_NAME = "SLH-DSA-SHA2-128f";

    private static boolean slhDsaEnabled = false;
    private static boolean genAvailable = false;
    private static KeyPair kp = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("JCE WolfCryptSlhDsaKeyTest Class");

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
            /* not available */
        }
    }

    private void assumeReady() {
        Assume.assumeTrue("SLH-DSA not compiled in", slhDsaEnabled);
        Assume.assumeTrue(GEN_NAME + " not available", genAvailable);
    }

    @Test
    public void publicKeyProperties() {
        assumeReady();

        PublicKey pub = kp.getPublic();
        assertEquals("SLH-DSA", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());
        assertNotNull(pub.getEncoded());
        assertTrue(pub.getEncoded().length > 0);
    }

    @Test
    public void privateKeyProperties() {
        assumeReady();

        PrivateKey priv = kp.getPrivate();
        assertEquals("SLH-DSA", priv.getAlgorithm());
        assertEquals("PKCS#8", priv.getFormat());
        assertNotNull(priv.getEncoded());
        assertTrue(priv.getEncoded().length > 0);
    }

    @Test
    public void getEncodedReturnsCopy() {
        assumeReady();

        PublicKey pub = kp.getPublic();
        byte[] a = pub.getEncoded();
        byte[] b = pub.getEncoded();
        assertNotSame(a, b);
        assertArrayEquals(a, b);

        /* Mutating the returned array must not affect the key. */
        a[0] ^= (byte)0xFF;
        assertFalse(java.util.Arrays.equals(a, pub.getEncoded()));
    }

    @Test
    public void equalsAndHashCode() {
        assumeReady();

        PublicKey pub = kp.getPublic();
        assertEquals(pub, pub);
        assertEquals(pub.hashCode(), pub.hashCode());
        assertNotEquals(pub, null);
        assertNotEquals(pub, "not a key");
    }

    @Test
    public void privateKeyDestroyable() throws Exception {
        assumeReady();

        /* Generate a throwaway key to destroy. */
        KeyPair tmp = KeyPairGenerator.getInstance(GEN_NAME, "wolfJCE")
            .generateKeyPair();
        PrivateKey priv = tmp.getPrivate();
        assertTrue(priv instanceof Destroyable);

        Destroyable d = (Destroyable) priv;
        assertFalse(d.isDestroyed());
        d.destroy();
        assertTrue(d.isDestroyed());
    }
}
