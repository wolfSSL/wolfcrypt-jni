/* Curve25519Test.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.Curve25519;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class Curve25519Test {

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean curve25519Enabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUpRng() {
        synchronized (rngLock) {
            rng.init();
        }
    }

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Curve25519();
            curve25519Enabled = true;
            System.out.println("JNI Curve25519 Class");

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Curve25519 test skipped: " + e.getError());
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("Curve25519 not compiled in", curve25519Enabled);
    }

    /**
     * Skip test if WolfCryptException is NOT_COMPILED_IN, otherwise rethrow.
     */
    private static void skipIfNotCompiledIn(WolfCryptException e) {

        if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
            Assume.assumeNoException(e);
        }
        throw e;
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {

        assumeEnabled();
        assertEquals(NativeStruct.NULL, new Curve25519().getNativeStruct());
    }

    @Test
    public void sharedSecretShouldMatch() {

        assumeEnabled();

        Curve25519 alice = new Curve25519();
        Curve25519 bob = new Curve25519();

        synchronized (rngLock) {
            alice.makeKey(rng, Curve25519.CURVE25519_KEY_SIZE);
            bob.makeKey(rng, Curve25519.CURVE25519_KEY_SIZE);
        }

        byte[] secretA;
        byte[] secretB;
        try {
            secretA = alice.makeSharedSecret(bob);
            secretB = bob.makeSharedSecret(alice);
        } catch (WolfCryptException e) {
            alice.releaseNativeStruct();
            bob.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }

        assertNotNull(secretA);
        assertNotNull(secretB);
        assertTrue(secretA.length > 0);
        assertArrayEquals(secretA, secretB);

        alice.releaseNativeStruct();
        bob.releaseNativeStruct();
    }

    @Test
    public void exportImportPublicAndSharedSecret() {

        assumeEnabled();

        Curve25519 alice = new Curve25519();
        Curve25519 bob = new Curve25519();

        synchronized (rngLock) {
            alice.makeKey(rng, Curve25519.CURVE25519_KEY_SIZE);
            bob.makeKey(rng, Curve25519.CURVE25519_KEY_SIZE);
        }

        /* Export and reimport Alice's public key */
        byte[] alicePub;
        try {
            alicePub = alice.exportPublic();
        } catch (WolfCryptException e) {
            alice.releaseNativeStruct();
            bob.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }
        assertNotNull(alicePub);
        assertTrue(alicePub.length > 0);

        Curve25519 alicePubOnly = new Curve25519();
        alicePubOnly.importPublic(alicePub);

        /* Bob's shared secret with original and reimported should match */
        byte[] secret1;
        byte[] secret2;
        try {
            secret1 = bob.makeSharedSecret(alice);
            secret2 = bob.makeSharedSecret(alicePubOnly);
        } catch (WolfCryptException e) {
            alice.releaseNativeStruct();
            bob.releaseNativeStruct();
            alicePubOnly.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }
        assertArrayEquals(secret1, secret2);

        alice.releaseNativeStruct();
        bob.releaseNativeStruct();
        alicePubOnly.releaseNativeStruct();
    }

    @Test
    public void exportImportPrivateKey() {

        assumeEnabled();

        Curve25519 origKey = new Curve25519();

        synchronized (rngLock) {
            origKey.makeKey(rng, Curve25519.CURVE25519_KEY_SIZE);
        }

        byte[] privKey;
        byte[] pubKey;
        try {
            privKey = origKey.exportPrivate();
            pubKey = origKey.exportPublic();
        } catch (WolfCryptException e) {
            origKey.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }
        assertNotNull(privKey);
        assertNotNull(pubKey);
        assertTrue(privKey.length > 0);
        assertTrue(pubKey.length > 0);

        /* Import private + public into new key object */
        Curve25519 importedKey = new Curve25519();
        importedKey.importPrivate(privKey, pubKey);

        /* Verify exported keys match original */
        byte[] reExportedPriv = importedKey.exportPrivate();
        byte[] reExportedPub = importedKey.exportPublic();
        assertArrayEquals(privKey, reExportedPriv);
        assertArrayEquals(pubKey, reExportedPub);

        origKey.releaseNativeStruct();
        importedKey.releaseNativeStruct();
    }
}

