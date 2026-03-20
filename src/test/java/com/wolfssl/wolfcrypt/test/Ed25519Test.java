/* Ed25519Test.java
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

import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class Ed25519Test {

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean ed25519Enabled = false;

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
            new Ed25519();
            ed25519Enabled = true;
            System.out.println("JNI Ed25519 Class");

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Ed25519 test skipped: " + e.getError());
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("Ed25519 not compiled in", ed25519Enabled);
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

        assertEquals(NativeStruct.NULL, new Ed25519().getNativeStruct());
    }

    @Test
    public void signAndVerifyShouldWork() {

        assumeEnabled();

        Ed25519 key = new Ed25519();

        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig;
        try {
            sig = key.sign_msg(msg);
        } catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }

        assertNotNull(sig);
        assertTrue(sig.length > 0);
        assertTrue(key.verify_msg(msg, sig));

        key.releaseNativeStruct();
    }

    @Test
    public void verifyWithDifferentMsgShouldFail() {

        assumeEnabled();

        Ed25519 key = new Ed25519();

        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig;
        try {
            sig = key.sign_msg(msg);
        } catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }

        byte[] badMsg = "Not the original message.".getBytes();
        boolean result = false;

        try {
            result = key.verify_msg(badMsg, sig);

        } catch (WolfCryptException e) {
            /* Native verify may throw on bad msg */
            result = false;
        }
        assertFalse(result);

        key.releaseNativeStruct();
    }

    @Test
    public void verifyWithCorruptSigShouldFail() {

        assumeEnabled();

        Ed25519 key = new Ed25519();

        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig;
        try {
            sig = key.sign_msg(msg);
        } catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }
        boolean result = false;

        /* Corrupt one byte of the signature */
        sig[0] = (byte)(sig[0] ^ 0xFF);

        try {
            result = key.verify_msg(msg, sig);

        } catch (WolfCryptException e) {
            /* Some corruptions may cause verify to throw */
            result = false;
        }
        assertFalse(result);

        key.releaseNativeStruct();
    }

    @Test
    public void exportImportPublicKeyAndVerify() {

        assumeEnabled();

        Ed25519 signKey = new Ed25519();

        synchronized (rngLock) {
            signKey.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig;
        byte[] pubKey;
        try {
            sig = signKey.sign_msg(msg);
            pubKey = signKey.exportPublic();
        } catch (WolfCryptException e) {
            signKey.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }

        /* Export public key and import into new object */
        assertNotNull(pubKey);
        assertTrue(pubKey.length > 0);

        Ed25519 verifyKey = new Ed25519();
        verifyKey.importPublic(pubKey);

        assertTrue(verifyKey.verify_msg(msg, sig));

        signKey.releaseNativeStruct();
        verifyKey.releaseNativeStruct();
    }

    @Test
    public void exportImportPrivateKeyAndSign() {

        assumeEnabled();

        Ed25519 origKey = new Ed25519();

        synchronized (rngLock) {
            origKey.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
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

        Ed25519 importedKey = new Ed25519();
        importedKey.importPrivate(privKey, pubKey);

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = importedKey.sign_msg(msg);

        assertTrue(origKey.verify_msg(msg, sig));

        origKey.releaseNativeStruct();
        importedKey.releaseNativeStruct();
    }

    @Test
    public void checkKeyShouldPass() {

        assumeEnabled();

        Ed25519 key = new Ed25519();

        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        /* Should not throw */
        try {
            key.checkKey();
        } catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }

        key.releaseNativeStruct();
    }

    @Test
    public void signVerifyWithDifferentSigAndMsgLengths() {

        assumeEnabled();

        Ed25519 key = new Ed25519();

        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }

        /*
         * Use message much longer than signature (64 bytes) to catch bugs
         * where sig length and msg length are swapped.
         */
        byte[] longMsg = new byte[256];
        for (int i = 0; i < longMsg.length; i++) {
            longMsg[i] = (byte)(i & 0xFF);
        }

        byte[] sig;
        try {
            sig = key.sign_msg(longMsg);
        } catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
            return;
        }
        assertNotNull(sig);
        assertTrue(key.verify_msg(longMsg, sig));

        /* Use very short message */
        byte[] shortMsg = new byte[1];
        shortMsg[0] = 0x42;

        byte[] sig2 = key.sign_msg(shortMsg);
        assertNotNull(sig2);
        assertTrue(key.verify_msg(shortMsg, sig2));

        key.releaseNativeStruct();
    }
}

