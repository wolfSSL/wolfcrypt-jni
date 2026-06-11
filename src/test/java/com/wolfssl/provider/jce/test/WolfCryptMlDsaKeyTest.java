/* WolfCryptMlDsaKeyTest.java
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

import com.wolfssl.provider.jce.WolfCryptMlDsaPrivateKey;
import com.wolfssl.provider.jce.WolfCryptMlDsaPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfPQCParameterSpec;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Direct tests for {@link WolfPQCParameterSpec},
 * {@link WolfCryptMlDsaPublicKey}, and {@link WolfCryptMlDsaPrivateKey}.
 */
public class WolfCryptMlDsaKeyTest {

    private static boolean mlDsaEnabled = false;

    /* Cached generated keys, one per level to save time vs. re-keygen. */
    private static KeyPair kp44;
    private static KeyPair kp65;
    private static KeyPair kp87;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("JCE WolfCryptMlDsaKeyTest Class");

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

        kp44 = KeyPairGenerator.getInstance("ML-DSA-44", "wolfJCE")
            .generateKeyPair();
        kp65 = KeyPairGenerator.getInstance("ML-DSA-65", "wolfJCE")
            .generateKeyPair();
        kp87 = KeyPairGenerator.getInstance("ML-DSA-87", "wolfJCE")
            .generateKeyPair();
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-DSA not compiled in", mlDsaEnabled);
    }

    @Test
    public void wolfPqcSpecConstructorRoundTrip() {
        WolfPQCParameterSpec s = new WolfPQCParameterSpec("ML-DSA-65");
        assertEquals("ML-DSA-65", s.getName());
    }

    @Test(expected = NullPointerException.class)
    public void wolfPqcSpecNullNameThrows() {
        new WolfPQCParameterSpec(null);
    }

    @Test
    public void wolfPqcSpecPredefinedConstantsHaveExpectedNames() {
        assertEquals("ML-DSA-44", WolfPQCParameterSpec.ML_DSA_44.getName());
        assertEquals("ML-DSA-65", WolfPQCParameterSpec.ML_DSA_65.getName());
        assertEquals("ML-DSA-87", WolfPQCParameterSpec.ML_DSA_87.getName());
        assertEquals("ML-KEM-512", WolfPQCParameterSpec.ML_KEM_512.getName());
        assertEquals("ML-KEM-768", WolfPQCParameterSpec.ML_KEM_768.getName());
        assertEquals("ML-KEM-1024", WolfPQCParameterSpec.ML_KEM_1024.getName());
    }

    @Test
    public void wolfPqcSpecToStringIncludesName() {
        String s = WolfPQCParameterSpec.ML_DSA_87.toString();
        assertTrue(s.contains("ML-DSA-87"));
    }

    @Test
    public void wolfPqcSpecAcceptsArbitraryName() {
        /* Constructor stores any name. KeyPairGenerator.initialize() is what
         * enforces "must be a known ML-DSA name". */
        WolfPQCParameterSpec s = new WolfPQCParameterSpec("Anything");
        assertEquals("Anything", s.getName());
    }

    @Test
    public void publicKeyAccessors() {

        assumeEnabled();

        WolfCryptMlDsaPublicKey pub = (WolfCryptMlDsaPublicKey)kp65.getPublic();

        assertEquals("ML-DSA", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());
        assertEquals(MlDsa.ML_DSA_65, pub.getLevel());

        byte[] enc = pub.getEncoded();
        assertNotNull(enc);
        assertTrue(enc.length > 0);
        assertNotNull(pub.toString());
    }

    @Test
    public void publicKeyEncodedReturnsClone() {

        assumeEnabled();

        WolfCryptMlDsaPublicKey pub = (WolfCryptMlDsaPublicKey)kp65.getPublic();

        byte[] enc1 = pub.getEncoded();
        enc1[0] ^= (byte) 0xFF;
        byte[] enc2 = pub.getEncoded();
        assertEquals("getEncoded() must return a clone, not internal state",
            (byte) (enc1[0] ^ (byte) 0xFF), enc2[0]);
    }

    @Test
    public void publicKeySingleArgCtorAutoDetectsLevel() {

        assumeEnabled();

        for (KeyPair kp : new KeyPair[] { kp44, kp65, kp87 }) {
            byte[] der = kp.getPublic().getEncoded();
            WolfCryptMlDsaPublicKey k = new WolfCryptMlDsaPublicKey(der);
            assertEquals(((WolfCryptMlDsaPublicKey) kp.getPublic())
                .getLevel(), k.getLevel());
        }
    }

    @Test
    public void publicKeyTwoArgCtorAcceptsMatchingLevel() {

        assumeEnabled();

        byte[] der = kp65.getPublic().getEncoded();
        WolfCryptMlDsaPublicKey k =
            new WolfCryptMlDsaPublicKey(der, MlDsa.ML_DSA_65);
        assertEquals(MlDsa.ML_DSA_65, k.getLevel());
    }

    @Test(expected = IllegalArgumentException.class)
    public void publicKeyTwoArgCtorRejectsMismatchingLevel() {

        assumeEnabled();

        /* Level-65 SPKI passed in with level=ML_DSA_44, native rejects. */
        byte[] der = kp65.getPublic().getEncoded();
        new WolfCryptMlDsaPublicKey(der, MlDsa.ML_DSA_44);
    }

    @Test(expected = IllegalArgumentException.class)
    public void publicKeyCtorRejectsEmptyBytes() {

        assumeEnabled();

        new WolfCryptMlDsaPublicKey(new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void publicKeyCtorRejectsNullBytes() {

        assumeEnabled();

        new WolfCryptMlDsaPublicKey((byte[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void publicKeyCtorRejectsMalformedDer() {

        assumeEnabled();

        byte[] junk = new byte[128];
        for (int i = 0; i < junk.length; i++) {
            junk[i] = (byte) i;
        }

        new WolfCryptMlDsaPublicKey(junk);
    }

    @Test
    public void publicKeyEqualsAndHashCode() {

        assumeEnabled();

        WolfCryptMlDsaPublicKey a =
            new WolfCryptMlDsaPublicKey(kp65.getPublic().getEncoded());
        WolfCryptMlDsaPublicKey b =
            new WolfCryptMlDsaPublicKey(kp65.getPublic().getEncoded());
        WolfCryptMlDsaPublicKey c =
            new WolfCryptMlDsaPublicKey(kp44.getPublic().getEncoded());

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotEquals(null, a);
        assertNotEquals("ML-DSA", a);
    }

    @Test
    public void publicKeyDestroyZeroesAndReturnsNull() {

        assumeEnabled();

        WolfCryptMlDsaPublicKey k =
            new WolfCryptMlDsaPublicKey(kp65.getPublic().getEncoded());
        assertFalse(k.isDestroyed());
        assertNotNull(k.getEncoded());

        k.destroy();
        assertTrue(k.isDestroyed());
        assertNull(k.getEncoded());
        /* Idempotent. */
        k.destroy();
        assertTrue(k.isDestroyed());
    }

    @Test
    public void privateKeyAccessors() {

        assumeEnabled();

        WolfCryptMlDsaPrivateKey priv =
            (WolfCryptMlDsaPrivateKey) kp87.getPrivate();

        assertEquals("ML-DSA", priv.getAlgorithm());
        assertEquals("PKCS#8", priv.getFormat());
        assertEquals(MlDsa.ML_DSA_87, priv.getLevel());
        assertNotNull(priv.getEncoded());
        assertNotNull(priv.toString());
    }

    @Test
    public void privateKeyEncodedReturnsClone() {

        assumeEnabled();

        WolfCryptMlDsaPrivateKey priv =
            (WolfCryptMlDsaPrivateKey) kp65.getPrivate();

        byte[] enc1 = priv.getEncoded();
        enc1[0] ^= (byte) 0xFF;
        byte[] enc2 = priv.getEncoded();
        assertEquals("getEncoded() must return a clone, not internal state",
            (byte) (enc1[0] ^ (byte) 0xFF), enc2[0]);
    }

    @Test
    public void privateKeySingleArgCtorAutoDetectsLevel() {

        assumeEnabled();

        for (KeyPair kp : new KeyPair[] { kp44, kp65, kp87 }) {
            byte[] der = kp.getPrivate().getEncoded();
            WolfCryptMlDsaPrivateKey k = new WolfCryptMlDsaPrivateKey(der);
            assertEquals(((WolfCryptMlDsaPrivateKey) kp.getPrivate())
                .getLevel(), k.getLevel());
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void privateKeyTwoArgCtorRejectsMismatchingLevel() {

        assumeEnabled();

        byte[] der = kp65.getPrivate().getEncoded();
        new WolfCryptMlDsaPrivateKey(der, MlDsa.ML_DSA_87);
    }

    @Test(expected = IllegalArgumentException.class)
    public void privateKeyCtorRejectsEmptyBytes() {

        assumeEnabled();

        new WolfCryptMlDsaPrivateKey(new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void privateKeyCtorRejectsNullBytes() {

        assumeEnabled();

        new WolfCryptMlDsaPrivateKey((byte[]) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void privateKeyCtorRejectsMalformedDer() {

        assumeEnabled();

        new WolfCryptMlDsaPrivateKey(new byte[128]);
    }

    @Test
    public void privateKeyEqualsAndHashCode() {

        assumeEnabled();

        WolfCryptMlDsaPrivateKey a =
            new WolfCryptMlDsaPrivateKey(kp65.getPrivate().getEncoded());
        WolfCryptMlDsaPrivateKey b =
            new WolfCryptMlDsaPrivateKey(kp65.getPrivate().getEncoded());

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(null, a);
    }

    @Test
    public void privateKeyDestroyZeroesAndReturnsNull() {

        assumeEnabled();

        WolfCryptMlDsaPrivateKey k =
            new WolfCryptMlDsaPrivateKey(kp44.getPrivate().getEncoded());
        assertFalse(k.isDestroyed());
        assertNotNull(k.getEncoded());

        k.destroy();
        assertTrue(k.isDestroyed());
        assertNull(k.getEncoded());
    }
}
