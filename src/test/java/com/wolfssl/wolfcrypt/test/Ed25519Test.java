/* Ed25519Test.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JNI-level tests for Ed25519: RFC 8032 known-answer vectors
 * (ported from native wolfcrypt/test/test.c), pure / ctx / ph variants,
 * raw and DER import/export, streaming verify, and negative cases.
 */
public class Ed25519Test {

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean ed25519Enabled = false;

    /* RFC 8410 fixed DER prefixes, must match native output */
    private static final byte[] SPKI_PREFIX = {
        (byte)0x30, (byte)0x2a, (byte)0x30, (byte)0x05, (byte)0x06,
        (byte)0x03, (byte)0x2b, (byte)0x65, (byte)0x70, (byte)0x03,
        (byte)0x21, (byte)0x00
    };

    private static final byte[] PKCS8_PREFIX = {
        (byte)0x30, (byte)0x2e, (byte)0x02, (byte)0x01, (byte)0x00,
        (byte)0x30, (byte)0x05, (byte)0x06, (byte)0x03, (byte)0x2b,
        (byte)0x65, (byte)0x70, (byte)0x04, (byte)0x22, (byte)0x04,
        (byte)0x20
    };

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

    /* Key gen, signing, and private key import all need native make_public */
    private void assumeKeyGenEnabled() {
        assumeEnabled();
        Assume.assumeTrue("Ed25519 key generation not compiled in",
            FeatureDetect.Ed25519KeyGenEnabled());
    }

    private static Ed25519 newKey() {
        Ed25519 key = new Ed25519();
        synchronized (rngLock) {
            key.makeKey(rng, Ed25519.ED25519_KEY_SIZE);
        }
        return key;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {

        assumeEnabled();

        assertEquals(NativeStruct.NULL, new Ed25519().getNativeStruct());
    }

    @Test
    public void notCompiledInThrowsFromConstructor() {

        Assume.assumeFalse("Ed25519 compiled in", ed25519Enabled);

        try {
            new Ed25519();
            fail("constructor should throw NOT_COMPILED_IN");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        assertFalse(FeatureDetect.Ed25519Enabled());
    }

    @Test
    public void signAndVerifyShouldWork() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = key.sign(msg);

        assertNotNull(sig);
        assertEquals(Ed25519.ED25519_SIG_SIZE, sig.length);
        assertTrue(key.verify(sig, msg));
        assertTrue(key.hasPrivateKey());
        assertTrue(key.hasPublicKey());

        key.releaseNativeStruct();
    }

    @Test
    public void makeKeyDefaultSizeAndDevId() {

        assumeKeyGenEnabled();

        /* no crypto callback device in CI, only INVALID_DEVID is used */
        Ed25519 key = new Ed25519(Ed25519.INVALID_DEVID);
        synchronized (rngLock) {
            key.makeKey(rng);
        }
        byte[] msg = "devId".getBytes();
        byte[] sig = key.sign(msg);
        assertTrue(key.verify(sig, msg));
        key.releaseNativeStruct();
    }

    @Test
    public void verifyWithDifferentMsgShouldFail() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = key.sign(msg);

        byte[] badMsg = "Not the original message.".getBytes();
        assertFalse(key.verify(sig, badMsg));

        key.releaseNativeStruct();
    }

    @Test
    public void verifyWithCorruptSigShouldFail() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = key.sign(msg);

        /* Corrupt one byte of R and, separately, one byte of S */
        byte[] badR = sig.clone();
        badR[0] ^= (byte)0xFF;
        assertFalse(key.verify(badR, msg));

        byte[] badS = sig.clone();
        badS[sig.length - 1] ^= (byte)0x01;
        assertFalse(key.verify(badS, msg));

        key.releaseNativeStruct();
    }

    @Test
    public void wrongSignatureLengthIsFalseNotException() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[] msg = "len".getBytes();

        assertFalse(key.verify(new byte[Ed25519.ED25519_SIG_SIZE - 1], msg));
        assertFalse(key.verify(new byte[Ed25519.ED25519_SIG_SIZE + 1], msg));
        /* an Ed448-sized signature */
        assertFalse(key.verify(new byte[114], msg));
        assertFalse(key.verify(new byte[0], msg));

        key.releaseNativeStruct();
    }

    @Test
    public void makeKeyRejectsWrongSize() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        try {
            synchronized (rngLock) {
                key.makeKey(rng, Ed25519.ED25519_KEY_SIZE - 1);
            }
            fail("wrong key size should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        assertFalse(key.hasPrivateKey());

        key.releaseNativeStruct();
    }

    private static void assertNoPrivateKey(Runnable op, String what) {
        try {
            op.run();
            fail(what + " without a private key should throw");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.ECC_PRIV_KEY_E, e.getError());
        }
    }

    @Test
    public void privateExportWithoutPrivateKeyThrows() {

        assumeEnabled();

        final Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);

        /* native copies key->k without checking privKeySet, the Java guard
         * must refuse instead of exporting zeros */
        assertNoPrivateKey(() -> key.makePublic(), "makePublic()");
        assertNoPrivateKey(() -> key.exportPrivate(), "exportPrivate()");
        assertNoPrivateKey(() -> key.exportPrivateOnly(),
            "exportPrivateOnly()");
        assertNoPrivateKey(() -> key.exportKey(), "exportKey()");
        assertNoPrivateKey(() -> key.exportPrivateKeyDer(),
            "exportPrivateKeyDer()");
        assertNoPrivateKey(() -> key.exportPrivateKeyDer(true),
            "exportPrivateKeyDer(true)");
        assertTrue(key.hasPublicKey());

        key.releaseNativeStruct();
    }

    @Test
    public void exportImportPublicKeyAndVerify() {

        assumeKeyGenEnabled();

        Ed25519 signKey = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig;
        byte[] pubKey;
        sig = signKey.sign(msg);
        pubKey = signKey.exportPublic();

        assertNotNull(pubKey);
        assertEquals(Ed25519.ED25519_PUB_KEY_SIZE, pubKey.length);

        Ed25519 verifyKey = new Ed25519();
        verifyKey.importPublic(pubKey);
        assertTrue(verifyKey.hasPublicKey());
        assertFalse(verifyKey.hasPrivateKey());

        assertTrue(verifyKey.verify(sig, msg));

        /* public-only key cannot sign */
        try {
            verifyKey.sign(msg);
            fail("sign with public-only key should fail");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.ECC_PRIV_KEY_E, e.getError());
        }

        signKey.releaseNativeStruct();
        verifyKey.releaseNativeStruct();
    }

    @Test
    public void exportImportPrivateKeyAndSign() {

        assumeKeyGenEnabled();

        Ed25519 origKey = newKey();

        byte[] privKey;
        byte[] pubKey;
        privKey = origKey.exportPrivate();
        pubKey = origKey.exportPublic();
        assertEquals(Ed25519.ED25519_PRV_KEY_SIZE, privKey.length);
        assertEquals(Ed25519.ED25519_PUB_KEY_SIZE, pubKey.length);

        /* private||public form with a separate public key */
        Ed25519 importedKey = new Ed25519();
        importedKey.importPrivate(privKey, pubKey);

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = importedKey.sign(msg);
        assertTrue(origKey.verify(sig, msg));

        /* private||public form alone (pub == null) */
        Ed25519 importedKey2 = new Ed25519();
        importedKey2.importPrivate(privKey, null);
        assertTrue(importedKey2.hasPublicKey());
        assertArrayEquals(sig, importedKey2.sign(msg));

        /* exportPrivateOnly + separate pub */
        Ed25519 importedKey3 = new Ed25519();
        importedKey3.importPrivate(origKey.exportPrivateOnly(), pubKey);
        assertArrayEquals(sig, importedKey3.sign(msg));

        origKey.releaseNativeStruct();
        importedKey.releaseNativeStruct();
        importedKey2.releaseNativeStruct();
        importedKey3.releaseNativeStruct();
    }

    @Test
    public void exportKeyReturnsPrivateAndPublic() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[][] pair = key.exportKey();

        assertEquals(2, pair.length);
        /* native exports the private||public form as the private part */
        assertArrayEquals(key.exportPrivate(), pair[0]);
        assertEquals(Ed25519.ED25519_PRV_KEY_SIZE, pair[0].length);
        assertArrayEquals(key.exportPublic(), pair[1]);
        assertArrayEquals(concat(key.exportPrivateOnly(), pair[1]),
            pair[0]);

        key.releaseNativeStruct();
    }

    @Test
    public void sizesMatchNativeConstants() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        assertEquals(Ed25519.ED25519_KEY_SIZE, key.size());
        assertEquals(Ed25519.ED25519_PRV_KEY_SIZE, key.privSize());
        assertEquals(Ed25519.ED25519_PUB_KEY_SIZE, key.pubSize());
        assertEquals(Ed25519.ED25519_SIG_SIZE, key.sigSize());
        key.releaseNativeStruct();
    }

    @Test
    public void checkKeyShouldPass() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        key.checkKey();

        key.releaseNativeStruct();
    }

    @Test
    public void mismatchedPairIsRejectedUnlessTrusted() {

        assumeKeyGenEnabled();

        /* untrusted import validates the pair */
        Ed25519 key = new Ed25519();
        try {
            key.importPrivate(Ed25519TestVectors.SKEY1,
                Ed25519TestVectors.PKEY2);
            fail("mismatched pair should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        key = new Ed25519();
        try {
            key.importPrivateEx(Ed25519TestVectors.SKEY1,
                Ed25519TestVectors.PKEY2, false);
            fail("mismatched pair should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        /* trusted import skips validation, checkKey then catches it */
        key = new Ed25519();
        key.importPrivateEx(Ed25519TestVectors.SKEY1,
            Ed25519TestVectors.PKEY2, true);
        try {
            key.checkKey();
            fail("checkKey should fail for mismatched pair");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        /* matching pair passes both ways */
        key = new Ed25519();
        key.importPrivateEx(Ed25519TestVectors.SKEY1,
            Ed25519TestVectors.PKEY1, false);
        key.checkKey();
        key.releaseNativeStruct();
    }

    @Test
    public void importPublicExValidatesPoint() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPublicEx(Ed25519TestVectors.PKEY1, false);
        assertArrayEquals(Ed25519TestVectors.PKEY1, key.exportPublic());
        key.releaseNativeStruct();

        /* trusted import of the same point works too */
        key = new Ed25519();
        key.importPublicEx(Ed25519TestVectors.PKEY1, true);
        assertTrue(key.verify(Ed25519TestVectors.SIG1,
            Ed25519TestVectors.MSG1));
        key.releaseNativeStruct();

        /* y = 2 is not on the curve: rejected untrusted, taken trusted */
        byte[] offCurve = new byte[Ed25519.ED25519_PUB_KEY_SIZE];
        offCurve[0] = 0x02;
        key = new Ed25519();
        try {
            key.importPublicEx(offCurve, false);
            fail("off-curve public key should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();
        key = new Ed25519();
        key.importPublicEx(offCurve, true);
        assertTrue(key.hasPublicKey());
        key.releaseNativeStruct();

        /* wrong length is rejected either way */
        for (boolean trusted : new boolean[] { false, true }) {
            key = new Ed25519();
            try {
                key.importPublicEx(new byte[31], trusted);
                fail("31 byte public key should be rejected");
            } catch (WolfCryptException e) {
                /* expected */
            }
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signVerifyWithDifferentSigAndMsgLengths() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        /*
         * Use message much longer than signature (64 bytes) to catch bugs
         * where sig length and msg length are swapped.
         */
        byte[] longMsg = new byte[256];
        for (int i = 0; i < longMsg.length; i++) {
            longMsg[i] = (byte)(i & 0xFF);
        }

        byte[] sig = key.sign(longMsg);
        assertNotNull(sig);
        assertTrue(key.verify(sig, longMsg));

        /* Use very short message */
        byte[] shortMsg = new byte[1];
        shortMsg[0] = 0x42;

        byte[] sig2 = key.sign(shortMsg);
        assertNotNull(sig2);
        assertTrue(key.verify(sig2, shortMsg));

        /* Empty message (RFC 8032 TEST 1 shape) */
        byte[] sig3 = key.sign(new byte[0]);
        assertTrue(key.verify(sig3, new byte[0]));
        assertFalse(key.verify(sig3, shortMsg));

        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section71Verify() {

        assumeEnabled();

        for (int i = 0; i < Ed25519TestVectors.PKEY.length; i++) {
            byte[] sig = Ed25519TestVectors.SIG[i];
            byte[] msg = Ed25519TestVectors.MSG[i];

            /* pKey may be the 65 byte uncompressed or 33 byte prefixed form
             * for indexes 3 and 4 */
            Ed25519 pubOnly = new Ed25519();
            pubOnly.importPublic(Ed25519TestVectors.PKEY[i]);
            assertTrue("KAT " + i + " pub-only verify",
                pubOnly.verify(sig, msg));
            if (msg.length > 0) {
                byte[] bad = msg.clone();
                bad[0] ^= 1;
                assertFalse(pubOnly.verify(sig, bad));
            }
            pubOnly.releaseNativeStruct();
        }
    }

    @Test
    public void katRfc8032Section71() {

        assumeKeyGenEnabled();

        for (int i = 0; i < Ed25519TestVectors.SKEY.length; i++) {

            byte[] sKey = Ed25519TestVectors.SKEY[i];
            byte[] pKey = Ed25519TestVectors.PKEY[i];
            byte[] sig = Ed25519TestVectors.SIG[i];
            byte[] msg = Ed25519TestVectors.MSG[i];

            /* sign with private + public (pKey may be the 65 byte
             * uncompressed or 33 byte prefixed form for indexes 3 and 4) */
            Ed25519 key = new Ed25519();
            key.importPrivate(sKey, pKey);
            assertArrayEquals("KAT " + i + " signature", sig, key.sign(msg));
            assertTrue("KAT " + i + " verify", key.verify(sig, msg));

            /* canonical 32 byte public key always comes back */
            byte[] pub = key.exportPublic();
            assertEquals(Ed25519.ED25519_PUB_KEY_SIZE, pub.length);
            /* entries 3 and 4 are alternate encodings of the TEST 1 key */
            assertArrayEquals(
                Ed25519TestVectors.PKEY[(i == 3 || i == 4) ? 0 : i], pub);
            key.releaseNativeStruct();

            /* signEx / verifyEx with the pure type */
            Ed25519 ex = new Ed25519();
            ex.importPrivate(sKey, pKey);
            assertArrayEquals(sig, ex.signEx(msg, Ed25519.ED25519_TYPE_PURE,
                null));
            assertTrue(ex.verifyEx(sig, msg, Ed25519.ED25519_TYPE_PURE, null));
            ex.releaseNativeStruct();
        }
    }

    @Test
    public void katPrivateOnlyImportDerivesPublic() {

        assumeKeyGenEnabled();

        Ed25519 key = new Ed25519();
        key.importPrivateOnly(Ed25519TestVectors.SKEY1);
        assertTrue(key.hasPrivateKey());
        assertFalse(key.hasPublicKey());

        /* native cannot sign or export the public half yet */
        try {
            key.sign(Ed25519TestVectors.MSG1);
            fail("sign without public key should fail");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.PUBLIC_KEY_E, e.getError());
        }
        try {
            key.exportPrivate();
            fail("private||public export without public key should fail");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.PUBLIC_KEY_E, e.getError());
        }
        try {
            key.exportPublic();
            fail("exportPublic without public key should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            key.verify(Ed25519TestVectors.SIG1, Ed25519TestVectors.MSG1);
            fail("verify without public key should fail");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.PUBLIC_KEY_E, e.getError());
        }

        /* derivation also loads the public key (native behaviour) */
        assertArrayEquals(Ed25519TestVectors.PKEY1, key.makePublic());
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed25519TestVectors.PKEY1, key.exportPublic());
        assertArrayEquals(concat(Ed25519TestVectors.SKEY1,
            Ed25519TestVectors.PKEY1), key.exportPrivate());
        assertArrayEquals(Ed25519TestVectors.SIG1,
            key.sign(Ed25519TestVectors.MSG1));
        key.releaseNativeStruct();

        /* the v2 export derives and keeps the public half too */
        key = new Ed25519();
        key.importPrivateOnly(Ed25519TestVectors.SKEY1);
        byte[] v2 = key.exportPrivateKeyDer(true);
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed25519TestVectors.PKEY1, Arrays.copyOfRange(v2,
            v2.length - Ed25519.ED25519_PUB_KEY_SIZE, v2.length));
        key.releaseNativeStruct();

        /* ensurePublicKey() does the same in one call, and is a no-op
         * once the public key is present */
        key = new Ed25519();
        key.importPrivateOnly(Ed25519TestVectors.SKEY1);
        assertFalse(key.hasPublicKey());
        key.ensurePublicKey();
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed25519TestVectors.PKEY1, key.exportPublic());

        /* the derived public key must also appear in the private||public
         * export, which is what a raw round trip re-imports */
        byte[] prv = key.exportPrivate();
        assertArrayEquals(concat(Ed25519TestVectors.SKEY1,
            Ed25519TestVectors.PKEY1), prv);
        assertArrayEquals(prv, key.exportKey()[0]);
        Ed25519 again = new Ed25519();
        again.importPrivate(prv, null);
        assertArrayEquals(Ed25519TestVectors.SIG1,
            again.sign(Ed25519TestVectors.MSG1));
        again.releaseNativeStruct();
        key.ensurePublicKey();
        assertArrayEquals(Ed25519TestVectors.PKEY1, key.exportPublic());
        assertArrayEquals(Ed25519TestVectors.SIG1,
            key.sign(Ed25519TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section72Ed25519ctxVerify() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.CTX_PKEY);
        assertTrue(key.verifyCtx(Ed25519TestVectors.CTX_SIG_FOO,
            Ed25519TestVectors.CTX_MSG, Ed25519TestVectors.CTX_CONTEXT));
        assertFalse(key.verifyCtx(Ed25519TestVectors.CTX_SIG_FOO,
            Ed25519TestVectors.CTX_MSG, null));
        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section73Ed25519phVerify() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PH_PKEY);
        assertTrue(key.verifyPh(Ed25519TestVectors.PH_SIG,
            Ed25519TestVectors.PH_MSG, null));
        assertTrue(key.verifyPhHash(Ed25519TestVectors.PH_SIG,
            Ed25519TestVectors.PH_HASH, null));
        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section72Ed25519ctx() {

        assumeKeyGenEnabled();

        byte[] msg = Ed25519TestVectors.CTX_MSG;
        byte[] ctx = Ed25519TestVectors.CTX_CONTEXT;

        Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.CTX_SKEY,
            Ed25519TestVectors.CTX_PKEY);

        /* RFC 8032 7.2 vector, context "foo" */
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_FOO, key.signCtx(msg,
            ctx));
        assertTrue(key.verifyCtx(Ed25519TestVectors.CTX_SIG_FOO, msg, ctx));
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_FOO,
            key.signEx(msg, Ed25519.ED25519_TYPE_CTX, ctx));
        assertTrue(key.verifyEx(Ed25519TestVectors.CTX_SIG_FOO, msg,
            Ed25519.ED25519_TYPE_CTX, ctx));

        /* wrong or missing context does not verify */
        assertFalse(key.verifyCtx(Ed25519TestVectors.CTX_SIG_FOO, msg,
            "bar".getBytes()));
        assertFalse(key.verifyCtx(Ed25519TestVectors.CTX_SIG_FOO, msg, null));
        assertFalse(key.verify(Ed25519TestVectors.CTX_SIG_FOO, msg));

        /* Ed25519ctx with an empty context (dom2 applied) is a different
         * signature from pure Ed25519 */
        byte[] sigEmpty = key.signCtx(msg, null);
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_EMPTY, sigEmpty);
        assertArrayEquals(sigEmpty, key.signCtx(msg, new byte[0]));
        assertTrue(key.verifyCtx(sigEmpty, msg, null));
        assertTrue(key.verifyCtx(sigEmpty, msg, new byte[0]));
        assertFalse(Arrays.equals(sigEmpty, key.sign(msg)));
        assertFalse(key.verify(sigEmpty, msg));

        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section73Ed25519ph() {

        assumeKeyGenEnabled();

        byte[] msg = Ed25519TestVectors.PH_MSG;
        byte[] hash = Ed25519TestVectors.PH_HASH;
        byte[] ctx = Ed25519TestVectors.PH_CONTEXT;

        Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.PH_SKEY,
            Ed25519TestVectors.PH_PKEY);

        /* RFC 8032 7.3 vector, no context: over the message and over the
         * caller supplied SHA-512 hash */
        assertArrayEquals(Ed25519TestVectors.PH_SIG, key.signPh(msg, null));
        assertArrayEquals(Ed25519TestVectors.PH_SIG,
            key.signPhHash(hash, null));
        assertArrayEquals(Ed25519TestVectors.PH_SIG,
            key.signEx(hash, Ed25519.ED25519_TYPE_PH, null));
        assertTrue(key.verifyPh(Ed25519TestVectors.PH_SIG, msg, null));
        assertTrue(key.verifyPhHash(Ed25519TestVectors.PH_SIG, hash, null));
        assertTrue(key.verifyEx(Ed25519TestVectors.PH_SIG, hash,
            Ed25519.ED25519_TYPE_PH, null));

        /* the ph type of the *Ex methods takes the pre-hash, not the msg */
        try {
            key.signEx(msg, Ed25519.ED25519_TYPE_PH, null);
            fail("signEx(ph) with a raw message should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyEx(Ed25519TestVectors.PH_SIG, msg,
                Ed25519.ED25519_TYPE_PH, null);
            fail("verifyEx(ph) with a raw message should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* with context "foo" */
        assertArrayEquals(Ed25519TestVectors.PH_SIG_FOO, key.signPh(msg, ctx));
        assertArrayEquals(Ed25519TestVectors.PH_SIG_FOO,
            key.signPhHash(hash, ctx));
        assertTrue(key.verifyPh(Ed25519TestVectors.PH_SIG_FOO, msg, ctx));
        assertTrue(key.verifyPhHash(Ed25519TestVectors.PH_SIG_FOO, hash, ctx));

        /* variants do not cross-verify */
        assertFalse(key.verifyPh(Ed25519TestVectors.PH_SIG, msg, ctx));
        assertFalse(key.verify(Ed25519TestVectors.PH_SIG, msg));
        assertFalse(key.verifyCtx(Ed25519TestVectors.PH_SIG, msg, null));

        key.releaseNativeStruct();
    }

    @Test
    public void rareMalformedSignaturesAreFalse() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.RARE_PKEY);

        for (int i = 0; i < Ed25519TestVectors.RARE_SIGS.length; i++) {
            assertFalse("rare signature " + i,
                key.verify(Ed25519TestVectors.RARE_SIGS[i],
                    Ed25519TestVectors.RARE_MSG));
        }

        key.releaseNativeStruct();
    }

    @Test
    public void derExportMatchesRfc8410Templates() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.SKEY1, Ed25519TestVectors.PKEY1);

        byte[] spki = key.exportPublicKeyDer(true);
        assertArrayEquals(concat(SPKI_PREFIX, Ed25519TestVectors.PKEY1), spki);

        byte[] pkcs8 = key.exportPrivateKeyDer();
        assertArrayEquals(concat(PKCS8_PREFIX, Ed25519TestVectors.SKEY1),
            pkcs8);
        assertArrayEquals(pkcs8, key.exportPrivateKeyDer(false));

        /* v2 with public key is longer and carries the public key */
        byte[] pkcs8v2 = key.exportPrivateKeyDer(true);
        assertTrue(pkcs8v2.length > pkcs8.length);
        /* the v2 form ends with publicKey [1] */
        assertEquals((byte)Util.TAG_PUBLIC_KEY,
            pkcs8v2[pkcs8v2.length - Ed25519.ED25519_PUB_KEY_SIZE - 2]);

        /* without the AlgorithmIdentifier native returns the raw key */
        byte[] pubNoAlg = key.exportPublicKeyDer(false);
        assertArrayEquals(Ed25519TestVectors.PKEY1, pubNoAlg);

        key.releaseNativeStruct();
    }

    @Test
    public void derImportRoundTrips() {

        assumeKeyGenEnabled();

        Ed25519 orig = newKey();
        byte[] spki = orig.exportPublicKeyDer(true);
        byte[] pkcs8 = orig.exportPrivateKeyDer();
        byte[] pkcs8v2 = orig.exportPrivateKeyDer(true);
        byte[] msg = "der".getBytes();
        byte[] sig = orig.sign(msg);

        Ed25519 pub = new Ed25519();
        pub.importPublicKeyDer(spki);
        assertTrue(pub.hasPublicKey());
        assertFalse(pub.hasPrivateKey());
        assertArrayEquals(orig.exportPublic(), pub.exportPublic());
        assertTrue(pub.verify(sig, msg));
        assertArrayEquals(spki, pub.exportPublicKeyDer(true));
        pub.releaseNativeStruct();

        /* v1: public key derived on import, immediately signable */
        Ed25519 priv = new Ed25519();
        priv.importPrivateKeyDer(pkcs8);
        assertTrue(priv.hasPrivateKey());
        assertTrue(priv.hasPublicKey());
        assertArrayEquals(orig.exportPrivateOnly(), priv.exportPrivateOnly());
        assertArrayEquals(orig.exportPrivate(), priv.exportPrivate());
        assertArrayEquals(orig.exportPublic(), priv.exportPublic());
        assertArrayEquals(sig, priv.sign(msg));
        assertArrayEquals(pkcs8, priv.exportPrivateKeyDer());
        priv.releaseNativeStruct();

        /* v2 with public key */
        Ed25519 priv2 = new Ed25519();
        priv2.importPrivateKeyDer(pkcs8v2);
        assertTrue(priv2.hasPublicKey());
        assertArrayEquals(orig.exportPublic(), priv2.exportPublic());
        assertArrayEquals(sig, priv2.sign(msg));
        assertArrayEquals(pkcs8v2, priv2.exportPrivateKeyDer(true));
        priv2.releaseNativeStruct();

        orig.releaseNativeStruct();
    }

    @Test
    public void derMalformedIsRejected() {

        assumeEnabled();

        byte[][] badPub = {
            new byte[0],
            new byte[] { Util.TAG_SEQUENCE },
            Arrays.copyOf(concat(SPKI_PREFIX, Ed25519TestVectors.PKEY1), 40),
            "not der at all, just some bytes......".getBytes(),
            /* Ed448 OID with an Ed25519 sized key */
            concat(new byte[] {
                (byte)0x30, (byte)0x2a, (byte)0x30, (byte)0x05, (byte)0x06,
                (byte)0x03, (byte)0x2b, (byte)0x65, (byte)0x71, (byte)0x03,
                (byte)0x21, (byte)0x00 }, Ed25519TestVectors.PKEY1)
        };
        for (byte[] der : badPub) {
            Ed25519 key = new Ed25519();
            try {
                key.importPublicKeyDer(der);
                fail("malformed SPKI accepted, len " + der.length);
            } catch (WolfCryptException e) {
                /* expected */
            }
            key.releaseNativeStruct();
        }

        byte[][] badPriv = {
            new byte[0],
            Arrays.copyOf(concat(PKCS8_PREFIX, Ed25519TestVectors.SKEY1), 30),
            concat(SPKI_PREFIX, Ed25519TestVectors.PKEY1)
        };
        for (byte[] der : badPriv) {
            Ed25519 key = new Ed25519();
            try {
                key.importPrivateKeyDer(der);
                fail("malformed PKCS#8 accepted, len " + der.length);
            } catch (WolfCryptException e) {
                /* expected */
            }
            key.releaseNativeStruct();
        }
    }

    @Test
    public void streamingVerify() {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        /* pure, 1023 byte message fed in uneven chunks */
        byte[] msg = Ed25519TestVectors.MSG[5];
        byte[] sig = Ed25519TestVectors.SIG[5];

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY[5]);

        key.verifyInit(sig, Ed25519.ED25519_TYPE_PURE, null);
        key.verifyUpdate(new byte[0]);
        key.verifyUpdate(msg, 0, 1);
        key.verifyUpdate(msg, 1, 100);
        key.verifyUpdate(msg, 101, msg.length - 101);
        assertTrue(key.verifyFinal(sig));

        /* corrupted message */
        byte[] bad = msg.clone();
        bad[500] ^= 1;
        key.verifyInit(sig, Ed25519.ED25519_TYPE_PURE, null);
        key.verifyUpdate(bad);
        assertFalse(key.verifyFinal(sig));

        /* one-shot still works afterwards */
        assertTrue(key.verify(sig, msg));
        key.releaseNativeStruct();

        /* ctx variant */
        Ed25519 ctxKey = new Ed25519();
        ctxKey.importPublic(Ed25519TestVectors.CTX_PKEY);
        ctxKey.verifyInit(Ed25519TestVectors.CTX_SIG_FOO,
            Ed25519.ED25519_TYPE_CTX, Ed25519TestVectors.CTX_CONTEXT);
        ctxKey.verifyUpdate(Ed25519TestVectors.CTX_MSG);
        assertTrue(ctxKey.verifyFinal(Ed25519TestVectors.CTX_SIG_FOO));
        ctxKey.releaseNativeStruct();

        /* ph variant */
        Ed25519 phKey = new Ed25519();
        phKey.importPublic(Ed25519TestVectors.PH_PKEY);
        phKey.verifyInit(Ed25519TestVectors.PH_SIG, Ed25519.ED25519_TYPE_PH,
            null);
        /* streaming ph verify is fed the pre-hash, not the message */
        phKey.verifyUpdate(Ed25519TestVectors.PH_HASH);
        assertTrue(phKey.verifyFinal(Ed25519TestVectors.PH_SIG));
        phKey.releaseNativeStruct();
    }

    @Test
    public void streamingVerifyStateErrors() {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);

        try {
            key.verifyUpdate(new byte[1]);
            fail("update before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verifyFinal(Ed25519TestVectors.SIG1);
            fail("final before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.verifyInit(new byte[Ed25519.ED25519_SIG_SIZE - 1],
                Ed25519.ED25519_TYPE_PURE, null);
            fail("wrong-length signature should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.verifyInit(Ed25519TestVectors.SIG1, Ed25519.ED25519_TYPE_PURE,
            null);
        try {
            key.verifyUpdate(new byte[4], 2, 3);
            fail("out of bounds update should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        byte[][] segs = { null, new byte[4], new byte[4], new byte[4] };
        int[][] bounds = { { 0, 0 }, { -1, 1 }, { 0, -1 }, { 5, 0 } };
        for (int i = 0; i < segs.length; i++) {
            try {
                key.verifyUpdate(segs[i], bounds[i][0], bounds[i][1]);
                fail("bad segment " + i + " should throw");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        try {
            key.verifyUpdate((byte[]) null);
            fail("null segment should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        assertTrue(key.verifyFinal(Ed25519TestVectors.SIG1));

        /* state is cleared by final */
        try {
            key.verifyFinal(Ed25519TestVectors.SIG1);
            fail("second final should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void streamingVerifyNotCompiledIn() {

        assumeEnabled();
        Assume.assumeFalse("streaming verify compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);
        try {
            key.verifyInit(Ed25519TestVectors.SIG1,
                Ed25519.ED25519_TYPE_PURE, null);
            fail("verifyInit should throw NOT_COMPILED_IN");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        key.releaseNativeStruct();
    }

    @Test
    public void contextTooLongIsRejected() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[] msg = "ctx".getBytes();
        byte[] max = new byte[Ed25519.ED25519_MAX_CONTEXT_LEN];
        byte[] tooLong = new byte[Ed25519.ED25519_MAX_CONTEXT_LEN + 1];

        /* 255 is fine */
        byte[] sig = key.signCtx(msg, max);
        assertTrue(key.verifyCtx(sig, msg, max));
        assertTrue(key.verifyPh(key.signPh(msg, max), msg, max));

        try {
            key.signCtx(msg, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyCtx(sig, msg, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.signPh(msg, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.signEx(msg, Ed25519.ED25519_TYPE_CTX, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void prehashLengthIsChecked() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();

        try {
            key.signPhHash(new byte[Ed25519.ED25519_PREHASH_SIZE - 1], null);
            fail("63 byte hash should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.signPhHash(null, null);
            fail("null hash should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyPhHash(new byte[Ed25519.ED25519_SIG_SIZE],
                new byte[Ed25519.ED25519_PREHASH_SIZE + 1], null);
            fail("65 byte hash should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void invalidTypeIsRejected() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[] msg = "type".getBytes();
        try {
            key.signEx(msg, 7, null);
            fail("invalid type should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyEx(new byte[Ed25519.ED25519_SIG_SIZE], msg, -3, null);
            fail("invalid type should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        key.releaseNativeStruct();
    }

    @Test
    public void nullArgumentsAreRejected() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[] msg = "null".getBytes();
        byte[] sig = key.sign(msg);
        try {
            key.sign(null);
            fail("null message should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verify(sig, null);
            fail("null message should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verify(null, msg);
            fail("null signature should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        key.releaseNativeStruct();
    }

    @Test
    public void operationsWithoutKeyThrow() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        byte[] msg = "nokey".getBytes();

        try {
            key.sign(msg);
            fail("sign without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verify(new byte[Ed25519.ED25519_SIG_SIZE], msg);
            fail("verify without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.exportPublic();
            fail("export without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.makePublic();
            fail("makePublic without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        assertFalse(key.hasPrivateKey());
        assertFalse(key.hasPublicKey());

        key.releaseNativeStruct();
    }

    @Test
    public void secondImportThrows() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        try {
            key.importPublic(Ed25519TestVectors.PKEY1);
            fail("second import should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.importPrivateKeyDer(concat(PKCS8_PREFIX,
                Ed25519TestVectors.SKEY1));
            fail("second import should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        key.releaseNativeStruct();
    }

    @Test
    public void useAfterReleaseThrows() {

        assumeKeyGenEnabled();

        Ed25519 key = newKey();
        byte[] msg = "released".getBytes();
        byte[] sig = key.sign(msg);
        key.releaseNativeStruct();

        try {
            key.sign(msg);
            fail("sign after release should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verify(sig, msg);
            fail("verify after release should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        assertFalse(key.hasPrivateKey());

        /* double release is harmless */
        key.releaseNativeStruct();
    }

    @SuppressWarnings("deprecation")
    @Test
    public void deprecatedDelegatesMatchNewApi() {

        assumeKeyGenEnabled();

        Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.SKEY2, Ed25519TestVectors.PKEY2);
        byte[] msg = Ed25519TestVectors.MSG2;

        assertArrayEquals(key.sign(msg), key.sign_msg(msg));
        assertArrayEquals(Ed25519TestVectors.SIG2, key.sign_msg(msg));
        assertTrue(key.verify_msg(msg, Ed25519TestVectors.SIG2));
        assertFalse(key.verify_msg(Ed25519TestVectors.MSG3,
            Ed25519TestVectors.SIG2));

        key.releaseNativeStruct();
    }

    @Test
    public void repeatedCreateReleaseStress() {

        assumeKeyGenEnabled();

        /* stress only, leak detection is the sanitizer job's */

        byte[] msg = "leak loop".getBytes();
        for (int i = 0; i < 2000; i++) {
            Ed25519 key = newKey();
            Ed25519 again = new Ed25519();
            try {
                byte[] sig = key.sign(msg);
                assertTrue(key.verify(sig, msg));
                byte[] der = key.exportPrivateKeyDer();
                again.importPrivateKeyDer(der);
                assertArrayEquals(sig, again.sign(msg));
            } finally {
                key.releaseNativeStruct();
                again.releaseNativeStruct();
            }
        }
    }

    @Test
    public void oneShotSignVerifyRejectedDuringStreamingVerify() {

        assumeKeyGenEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.SKEY1,
            Ed25519TestVectors.PKEY1);
        key.verifyInit(Ed25519TestVectors.SIG1, Ed25519.ED25519_TYPE_PURE,
            null);

        /* one-shot calls would clobber the streaming digest */
        try {
            key.sign(Ed25519TestVectors.MSG1);
            fail("sign during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verify(Ed25519TestVectors.SIG1, Ed25519TestVectors.MSG1);
            fail("verify during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.makePublic();
            fail("makePublic during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.ensurePublicKey();
            fail("ensurePublicKey during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.checkKey();
            fail("checkKey during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.exportPrivateKeyDer(true);
            fail("exportPrivateKeyDer(true) during streaming verify " +
                "should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* the streaming verify is untouched and completes */
        key.verifyUpdate(Ed25519TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed25519TestVectors.SIG1));
        assertArrayEquals(Ed25519TestVectors.SIG1,
            key.sign(Ed25519TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void streamingVerifyIsBoundToStartingThread() throws Exception {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        final Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);
        key.verifyInit(Ed25519TestVectors.SIG1, Ed25519.ED25519_TYPE_PURE,
            null);

        /* another thread may neither feed, finish nor restart the stream */
        final AtomicInteger rejected = new AtomicInteger(0);
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    key.verifyUpdate(Ed25519TestVectors.MSG1);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
                try {
                    key.verifyFinal(Ed25519TestVectors.SIG1);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
                try {
                    key.verifyInit(Ed25519TestVectors.SIG1,
                        Ed25519.ED25519_TYPE_PURE, null);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
            }
        });
        t.start();
        t.join();
        assertEquals(3, rejected.get());

        /* the starting thread finishes normally */
        key.verifyUpdate(Ed25519TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed25519TestVectors.SIG1));

        key.releaseNativeStruct();
    }

    @Test
    public void verifyAbortWithoutStreamIsHarmless() {

        assumeEnabled();

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);
        key.verifyAbort();
        key.verifyAbort();
        assertTrue(key.verify(Ed25519TestVectors.SIG1,
            Ed25519TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void verifyAbortDropsAnAbandonedStream() throws Exception {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        final Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);
        key.verifyInit(Ed25519TestVectors.SIG1, Ed25519.ED25519_TYPE_PURE,
            null);

        /* any thread may drop the stream */
        Thread t = new Thread(new Runnable() {
            public void run() {
                key.verifyAbort();
            }
        });
        t.start();
        t.join();

        assertTrue(key.verify(Ed25519TestVectors.SIG1,
            Ed25519TestVectors.MSG1));
        try {
            key.verifyFinal(Ed25519TestVectors.SIG1);
            fail("aborted stream should not finish");
        } catch (IllegalStateException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void malformedSignatureStreamingVerifyIsFalse() {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed25519StreamingVerifyEnabled());

        Ed25519 key = new Ed25519();
        key.importPublic(Ed25519TestVectors.PKEY1);

        /* S with its top bits set, native rejects it before verifying */
        byte[] bad = Ed25519TestVectors.SIG1.clone();
        bad[bad.length - 1] |= (byte)0x80;
        assertFalse(key.verify(bad, Ed25519TestVectors.MSG1));

        key.verifyInit(bad, Ed25519.ED25519_TYPE_PURE, null);
        key.verifyUpdate(Ed25519TestVectors.MSG1);
        assertFalse(key.verifyFinal(bad));

        /* the object is usable again afterwards */
        key.verifyInit(Ed25519TestVectors.SIG1, Ed25519.ED25519_TYPE_PURE,
            null);
        key.verifyUpdate(Ed25519TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed25519TestVectors.SIG1));

        key.releaseNativeStruct();
    }

    @Test
    public void threadedSignVerifyOnSharedKey() throws Exception {

        assumeKeyGenEnabled();

        final Ed25519 key = new Ed25519();
        key.importPrivate(Ed25519TestVectors.SKEY1, Ed25519TestVectors.PKEY1);
        final boolean streaming = FeatureDetect.Ed25519StreamingVerifyEnabled();
        final int numThreads = 8;
        final int iterations = 40;
        final ExecutorService service =
            Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final AtomicInteger failures = new AtomicInteger(0);
        final AtomicReference<Throwable> firstError =
            new AtomicReference<Throwable>();

        for (int t = 0; t < numThreads; t++) {
            final int id = t;
            service.execute(new Runnable() {
                public void run() {
                    /* one-shot calls share the key, a streaming verify
                     * is per object so each thread uses its own */
                    Ed25519 own = new Ed25519();
                    try {
                        own.importPublic(Ed25519TestVectors.PKEY1);
                        for (int i = 0; i < iterations; i++) {
                            byte[] msg =
                                ("thread " + id + " " + i).getBytes();
                            byte[] sig = key.sign(msg);
                            if (!key.verify(sig, msg)) {
                                failures.incrementAndGet();
                            }
                            byte[] bad = msg.clone();
                            bad[0] ^= 1;
                            if (key.verify(sig, bad)) {
                                failures.incrementAndGet();
                            }
                            if (streaming) {
                                own.verifyInit(Ed25519TestVectors.SIG1,
                                    Ed25519.ED25519_TYPE_PURE, null);
                                own.verifyUpdate(Ed25519TestVectors.MSG1);
                                if (!own.verifyFinal(Ed25519TestVectors.SIG1)) {
                                    failures.incrementAndGet();
                                }
                            }
                        }
                    } catch (Throwable e) {
                        firstError.compareAndSet(null, e);
                        failures.incrementAndGet();
                    } finally {
                        own.releaseNativeStruct();
                        latch.countDown();
                    }
                }
            });
        }

        try {
            assertTrue("threads timed out", latch.await(60, TimeUnit.SECONDS));
            assertEquals("first error: " + firstError.get(), 0, failures.get());
        }
        finally {
            service.shutdownNow();
            key.releaseNativeStruct();
        }
    }
}
