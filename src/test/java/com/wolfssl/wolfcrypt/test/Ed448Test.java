/* Ed448Test.java
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

import com.wolfssl.wolfcrypt.Ed448;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JNI-level tests for {@link Ed448}: RFC 8032 known-answer vectors from
 * native test.c, pure and ph variants with and without context, raw and
 * DER import/export, streaming verify, and negative cases.
 */
public class Ed448Test {

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean ed448Enabled = false;

    /* RFC 8410 DER prefixes, expected native output */
    private static final byte[] SPKI_PREFIX = {
        (byte)0x30, (byte)0x43, (byte)0x30, (byte)0x05, (byte)0x06,
        (byte)0x03, (byte)0x2b, (byte)0x65, (byte)0x71, (byte)0x03,
        (byte)0x3a, (byte)0x00
    };

    private static final byte[] PKCS8_PREFIX = {
        (byte)0x30, (byte)0x47, (byte)0x02, (byte)0x01, (byte)0x00,
        (byte)0x30, (byte)0x05, (byte)0x06, (byte)0x03, (byte)0x2b,
        (byte)0x65, (byte)0x71, (byte)0x04, (byte)0x3b, (byte)0x04,
        (byte)0x39
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
            new Ed448();
            ed448Enabled = true;
            System.out.println("JNI Ed448 Class");

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Ed448 test skipped: " + e.getError());
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("Ed448 not compiled in", ed448Enabled);
    }

    private static Ed448 newKey() {
        Ed448 key = new Ed448();
        synchronized (rngLock) {
            key.makeKey(rng, Ed448.ED448_KEY_SIZE);
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

        assertEquals(NativeStruct.NULL, new Ed448().getNativeStruct());
    }

    @Test
    public void notCompiledInThrowsFromConstructor() {

        Assume.assumeFalse("Ed448 compiled in", ed448Enabled);

        try {
            new Ed448();
            fail("constructor should throw NOT_COMPILED_IN");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        assertFalse(FeatureDetect.Ed448Enabled());
    }

    @Test
    public void signAndVerifyShouldWork() {

        assumeEnabled();

        Ed448 key = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = key.sign(msg);

        assertNotNull(sig);
        assertEquals(Ed448.ED448_SIG_SIZE, sig.length);
        assertTrue(key.verify(sig, msg));
        assertTrue(key.verify(sig, msg, null));
        assertTrue(key.verify(sig, msg, new byte[0]));
        assertTrue(key.hasPrivateKey());
        assertTrue(key.hasPublicKey());

        /* Ed448 always applies dom4, so null/empty contexts sign identically */
        assertArrayEquals(sig, key.sign(msg, null));
        assertArrayEquals(sig, key.sign(msg, new byte[0]));

        key.releaseNativeStruct();
    }

    @Test
    public void makeKeyDefaultSizeAndDevId() {

        assumeEnabled();

        /* no crypto callback device in CI, only INVALID_DEVID is used */
        Ed448 key = new Ed448(Ed448.INVALID_DEVID);
        synchronized (rngLock) {
            key.makeKey(rng);
        }
        byte[] msg = "devId".getBytes();
        byte[] sig = key.sign(msg);
        assertTrue(key.verify(sig, msg));
        key.releaseNativeStruct();
    }

    @Test
    public void verifyWithDifferentMsgOrCorruptSigShouldFail() {

        assumeEnabled();

        Ed448 key = newKey();

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = key.sign(msg);

        assertFalse(key.verify(sig, "Not the original message.".getBytes()));

        byte[] badR = sig.clone();
        badR[0] ^= (byte)0xFF;
        assertFalse(key.verify(badR, msg));

        byte[] badS = sig.clone();
        badS[sig.length - 2] ^= (byte)0x01;
        assertFalse(key.verify(badS, msg));

        /* wrong context */
        assertFalse(key.verify(sig, msg, "x".getBytes()));

        key.releaseNativeStruct();
    }

    @Test
    public void wrongSignatureLengthIsFalseNotException() {

        assumeEnabled();

        Ed448 key = newKey();
        byte[] msg = "len".getBytes();

        assertFalse(key.verify(new byte[Ed448.ED448_SIG_SIZE - 1], msg));
        assertFalse(key.verify(new byte[Ed448.ED448_SIG_SIZE + 1], msg));
        assertFalse(key.verify(new byte[64], msg));
        assertFalse(key.verify(new byte[0], msg));

        key.releaseNativeStruct();
    }

    @Test
    public void makeKeyRejectsWrongSize() {

        assumeEnabled();

        Ed448 key = new Ed448();
        try {
            synchronized (rngLock) {
                key.makeKey(rng, Ed448.ED448_KEY_SIZE - 1);
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

        final Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);

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

        assumeEnabled();

        Ed448 signKey = newKey();
        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = signKey.sign(msg);
        byte[] pubKey = signKey.exportPublic();

        assertEquals(Ed448.ED448_PUB_KEY_SIZE, pubKey.length);

        Ed448 verifyKey = new Ed448();
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

        assumeEnabled();

        Ed448 origKey = newKey();
        byte[] privKey = origKey.exportPrivate();
        byte[] pubKey = origKey.exportPublic();

        assertEquals(Ed448.ED448_PRV_KEY_SIZE, privKey.length);
        assertEquals(Ed448.ED448_PUB_KEY_SIZE, pubKey.length);

        byte[] msg = "Everyone gets Friday off.".getBytes();
        byte[] sig = origKey.sign(msg);

        Ed448 importedKey = new Ed448();
        importedKey.importPrivate(privKey, pubKey);
        assertArrayEquals(sig, importedKey.sign(msg));

        Ed448 importedKey2 = new Ed448();
        importedKey2.importPrivate(privKey, null);
        assertTrue(importedKey2.hasPublicKey());
        assertArrayEquals(sig, importedKey2.sign(msg));

        Ed448 importedKey3 = new Ed448();
        importedKey3.importPrivate(origKey.exportPrivateOnly(), pubKey);
        assertArrayEquals(sig, importedKey3.sign(msg));

        origKey.releaseNativeStruct();
        importedKey.releaseNativeStruct();
        importedKey2.releaseNativeStruct();
        importedKey3.releaseNativeStruct();
    }

    @Test
    public void exportKeyReturnsPrivateAndPublic() {

        assumeEnabled();

        Ed448 key = newKey();
        byte[][] pair = key.exportKey();

        assertEquals(2, pair.length);
        /* native exports the private||public form as the private part */
        assertArrayEquals(key.exportPrivate(), pair[0]);
        assertEquals(Ed448.ED448_PRV_KEY_SIZE, pair[0].length);
        assertArrayEquals(key.exportPublic(), pair[1]);
        assertArrayEquals(concat(key.exportPrivateOnly(), pair[1]),
            pair[0]);

        key.releaseNativeStruct();
    }

    @Test
    public void sizesMatchNativeConstants() {

        assumeEnabled();

        Ed448 key = new Ed448();
        assertEquals(Ed448.ED448_KEY_SIZE, key.size());
        assertEquals(Ed448.ED448_PRV_KEY_SIZE, key.privSize());
        assertEquals(Ed448.ED448_PUB_KEY_SIZE, key.pubSize());
        assertEquals(Ed448.ED448_SIG_SIZE, key.sigSize());
        key.releaseNativeStruct();
    }

    @Test
    public void checkKeyShouldPass() {

        assumeEnabled();

        Ed448 key = newKey();
        key.checkKey();
        key.releaseNativeStruct();
    }

    @Test
    public void mismatchedPairIsRejectedUnlessTrusted() {

        assumeEnabled();

        Ed448 key = new Ed448();
        try {
            key.importPrivate(Ed448TestVectors.SKEY1, Ed448TestVectors.PKEY2);
            fail("mismatched pair should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        key = new Ed448();
        try {
            key.importPrivateEx(Ed448TestVectors.SKEY1,
                Ed448TestVectors.PKEY2, false);
            fail("mismatched pair should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        key = new Ed448();
        key.importPrivateEx(Ed448TestVectors.SKEY1, Ed448TestVectors.PKEY2,
            true);
        try {
            key.checkKey();
            fail("checkKey should fail for mismatched pair");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();

        key = new Ed448();
        key.importPrivateEx(Ed448TestVectors.SKEY1, Ed448TestVectors.PKEY1,
            false);
        key.checkKey();
        key.releaseNativeStruct();
    }

    @Test
    public void importPublicExValidatesPoint() {

        assumeEnabled();

        Ed448 key = new Ed448();
        key.importPublicEx(Ed448TestVectors.PKEY1, false);
        assertArrayEquals(Ed448TestVectors.PKEY1, key.exportPublic());
        key.releaseNativeStruct();

        key = new Ed448();
        key.importPublicEx(Ed448TestVectors.PKEY1, true);
        assertTrue(key.verify(Ed448TestVectors.SIG1, Ed448TestVectors.MSG1));
        key.releaseNativeStruct();

        /* y = 2 is not on the curve: rejected untrusted, taken trusted */
        byte[] offCurve = new byte[Ed448.ED448_PUB_KEY_SIZE];
        offCurve[0] = 0x02;
        key = new Ed448();
        try {
            key.importPublicEx(offCurve, false);
            fail("off-curve public key should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }
        key.releaseNativeStruct();
        key = new Ed448();
        key.importPublicEx(offCurve, true);
        assertTrue(key.hasPublicKey());
        key.releaseNativeStruct();

        /* wrong length is rejected either way */
        for (boolean trusted : new boolean[] { false, true }) {
            key = new Ed448();
            try {
                key.importPublicEx(new byte[56], trusted);
                fail("56 byte public key should be rejected");
            } catch (WolfCryptException e) {
                /* expected */
            }
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signVerifyWithDifferentSigAndMsgLengths() {

        assumeEnabled();

        Ed448 key = newKey();

        byte[] longMsg = new byte[512];
        for (int i = 0; i < longMsg.length; i++) {
            longMsg[i] = (byte)(i & 0xFF);
        }
        byte[] sig = key.sign(longMsg);
        assertTrue(key.verify(sig, longMsg));

        byte[] shortMsg = new byte[] { 0x42 };
        byte[] sig2 = key.sign(shortMsg);
        assertTrue(key.verify(sig2, shortMsg));

        byte[] sig3 = key.sign(new byte[0]);
        assertTrue(key.verify(sig3, new byte[0]));
        assertFalse(key.verify(sig3, shortMsg));

        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section74() {

        assumeEnabled();

        /* entry 3 repeats entry 0 and is kept for native index parity */
        for (int i = 0; i < Ed448TestVectors.SKEY.length; i++) {

            byte[] sKey = Ed448TestVectors.SKEY[i];
            byte[] pKey = Ed448TestVectors.PKEY[i];
            byte[] sig = Ed448TestVectors.SIG[i];
            byte[] msg = Ed448TestVectors.MSG[i];

            Ed448 key = new Ed448();
            key.importPrivate(sKey, pKey);
            assertArrayEquals("KAT " + i + " signature", sig, key.sign(msg));
            assertArrayEquals("KAT " + i + " signature (null ctx)", sig,
                key.sign(msg, null));
            assertTrue("KAT " + i + " verify", key.verify(sig, msg));
            /* entry 4 is the 0x40-prefixed form of the "Blank" key */
            assertArrayEquals(Ed448TestVectors.PKEY[i == 4 ? 0 : i],
                key.exportPublic());
            key.releaseNativeStruct();

            Ed448 pubOnly = new Ed448();
            pubOnly.importPublic(pKey);
            assertTrue("KAT " + i + " pub-only verify",
                pubOnly.verify(sig, msg));
            if (msg.length > 0) {
                byte[] bad = msg.clone();
                bad[0] ^= 1;
                assertFalse(pubOnly.verify(sig, bad));
            }
            pubOnly.releaseNativeStruct();

            Ed448 ex = new Ed448();
            ex.importPrivate(sKey, pKey);
            assertArrayEquals(sig, ex.signEx(msg, Ed448.ED448_TYPE_PURE, null));
            assertTrue(ex.verifyEx(sig, msg, Ed448.ED448_TYPE_PURE, null));
            ex.releaseNativeStruct();
        }
    }

    @Test
    public void katPrivateOnlyImportDerivesPublic() {

        assumeEnabled();

        Ed448 key = new Ed448();
        key.importPrivateOnly(Ed448TestVectors.SKEY1);
        assertTrue(key.hasPrivateKey());
        assertFalse(key.hasPublicKey());

        /* no public key yet, so it can neither sign nor export it */
        try {
            key.sign(Ed448TestVectors.MSG1);
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
            key.verify(Ed448TestVectors.SIG1, Ed448TestVectors.MSG1);
            fail("verify without public key should fail");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.PUBLIC_KEY_E, e.getError());
        }

        /* makePublic() also loads the derived key */
        assertArrayEquals(Ed448TestVectors.PKEY1, key.makePublic());
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed448TestVectors.PKEY1, key.exportPublic());
        assertArrayEquals(concat(Ed448TestVectors.SKEY1,
            Ed448TestVectors.PKEY1), key.exportPrivate());
        assertArrayEquals(Ed448TestVectors.SIG1,
            key.sign(Ed448TestVectors.MSG1));
        key.releaseNativeStruct();

        /* the v2 export derives and keeps the public half too */
        key = new Ed448();
        key.importPrivateOnly(Ed448TestVectors.SKEY1);
        byte[] v2 = key.exportPrivateKeyDer(true);
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed448TestVectors.PKEY1, Arrays.copyOfRange(v2,
            v2.length - Ed448.ED448_PUB_KEY_SIZE, v2.length));
        key.releaseNativeStruct();

        /* ensurePublicKey() does the same, and is a no-op afterwards */
        key = new Ed448();
        key.importPrivateOnly(Ed448TestVectors.SKEY1);
        assertFalse(key.hasPublicKey());
        key.ensurePublicKey();
        assertTrue(key.hasPublicKey());
        assertArrayEquals(Ed448TestVectors.PKEY1, key.exportPublic());

        /* the derived public key must also appear in the private||public
         * export, which is what a raw round trip re-imports */
        byte[] prv = key.exportPrivate();
        assertArrayEquals(concat(Ed448TestVectors.SKEY1,
            Ed448TestVectors.PKEY1), prv);
        assertArrayEquals(prv, key.exportKey()[0]);
        Ed448 again = new Ed448();
        again.importPrivate(prv, null);
        assertArrayEquals(Ed448TestVectors.SIG1,
            again.sign(Ed448TestVectors.MSG1));
        again.releaseNativeStruct();
        key.ensurePublicKey();
        assertArrayEquals(Ed448TestVectors.PKEY1, key.exportPublic());
        assertArrayEquals(Ed448TestVectors.SIG1,
            key.sign(Ed448TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section74WithContext() {

        assumeEnabled();

        byte[] msg = Ed448TestVectors.CTX_MSG;
        byte[] ctx = Ed448TestVectors.CTX_CONTEXT;

        Ed448 key = new Ed448();
        key.importPrivate(Ed448TestVectors.CTX_SKEY, Ed448TestVectors.CTX_PKEY);

        assertArrayEquals(Ed448TestVectors.CTX_SIG_FOO, key.sign(msg, ctx));
        assertArrayEquals(Ed448TestVectors.CTX_SIG_FOO,
            key.signEx(msg, Ed448.ED448_TYPE_PURE, ctx));
        assertTrue(key.verify(Ed448TestVectors.CTX_SIG_FOO, msg, ctx));
        assertTrue(key.verifyEx(Ed448TestVectors.CTX_SIG_FOO, msg,
            Ed448.ED448_TYPE_PURE, ctx));

        /* wrong or missing context does not verify */
        assertFalse(key.verify(Ed448TestVectors.CTX_SIG_FOO, msg,
            "bar".getBytes()));
        assertFalse(key.verify(Ed448TestVectors.CTX_SIG_FOO, msg, null));
        assertFalse(key.verify(Ed448TestVectors.CTX_SIG_FOO, msg));

        /* the same key with no context is the RFC "1 octet" vector */
        assertArrayEquals(Ed448TestVectors.SIG2, key.sign(msg));
        assertFalse(Arrays.equals(key.sign(msg),
            key.sign(msg, "foo".getBytes())));

        key.releaseNativeStruct();
    }

    @Test
    public void katRfc8032Section75Ed448ph() {

        assumeEnabled();

        byte[] msg = Ed448TestVectors.PH_MSG;
        byte[] hash = Ed448TestVectors.PH_HASH;
        byte[] ctx = Ed448TestVectors.PH_CONTEXT;

        Ed448 key = new Ed448();
        key.importPrivate(Ed448TestVectors.PH_SKEY, Ed448TestVectors.PH_PKEY);

        /* no context, over the message and over the caller's 64-byte
         * SHAKE256 pre-hash */
        assertArrayEquals(Ed448TestVectors.PH_SIG, key.signPh(msg, null));
        assertArrayEquals(Ed448TestVectors.PH_SIG, key.signPhHash(hash, null));
        assertArrayEquals(Ed448TestVectors.PH_SIG,
            key.signEx(hash, Ed448.ED448_TYPE_PH, null));
        assertTrue(key.verifyPh(Ed448TestVectors.PH_SIG, msg, null));
        assertTrue(key.verifyPhHash(Ed448TestVectors.PH_SIG, hash, null));
        assertTrue(key.verifyEx(Ed448TestVectors.PH_SIG, hash,
            Ed448.ED448_TYPE_PH, null));

        /* *Ex with the ph type takes the pre-hash, not the message */
        try {
            key.signEx(msg, Ed448.ED448_TYPE_PH, null);
            fail("signEx(ph) with a raw message should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyEx(Ed448TestVectors.PH_SIG, msg,
                Ed448.ED448_TYPE_PH, null);
            fail("verifyEx(ph) with a raw message should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* with context "foo" */
        assertArrayEquals(Ed448TestVectors.PH_SIG_FOO, key.signPh(msg, ctx));
        assertArrayEquals(Ed448TestVectors.PH_SIG_FOO,
            key.signPhHash(hash, ctx));
        assertTrue(key.verifyPh(Ed448TestVectors.PH_SIG_FOO, msg, ctx));
        assertTrue(key.verifyPhHash(Ed448TestVectors.PH_SIG_FOO, hash, ctx));

        /* variants do not cross-verify */
        assertFalse(key.verifyPh(Ed448TestVectors.PH_SIG, msg, ctx));
        assertFalse(key.verify(Ed448TestVectors.PH_SIG, msg));
        assertFalse(key.verify(Ed448TestVectors.PH_SIG, msg, ctx));

        key.releaseNativeStruct();
    }

    @Test
    public void rareMalformedSignaturesAreFalse() {

        assumeEnabled();

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);

        for (int i = 0; i < Ed448TestVectors.RARE_SIGS.length; i++) {
            assertFalse("rare signature " + i,
                key.verify(Ed448TestVectors.RARE_SIGS[i],
                    Ed448TestVectors.MSG1));
        }

        key.releaseNativeStruct();
    }

    @Test
    public void derExportMatchesRfc8410Templates() {

        assumeEnabled();

        Ed448 key = new Ed448();
        key.importPrivate(Ed448TestVectors.SKEY1, Ed448TestVectors.PKEY1);

        byte[] spki = key.exportPublicKeyDer(true);
        assertArrayEquals(concat(SPKI_PREFIX, Ed448TestVectors.PKEY1), spki);

        byte[] pkcs8 = key.exportPrivateKeyDer();
        assertArrayEquals(concat(PKCS8_PREFIX, Ed448TestVectors.SKEY1), pkcs8);
        assertArrayEquals(pkcs8, key.exportPrivateKeyDer(false));

        byte[] pkcs8v2 = key.exportPrivateKeyDer(true);
        assertTrue(pkcs8v2.length > pkcs8.length);
        /* the v2 form ends with publicKey [1] */
        assertEquals((byte)Util.TAG_PUBLIC_KEY,
            pkcs8v2[pkcs8v2.length - Ed448.ED448_PUB_KEY_SIZE - 2]);

        /* without the AlgorithmIdentifier native returns the raw key */
        byte[] pubNoAlg = key.exportPublicKeyDer(false);
        assertArrayEquals(Ed448TestVectors.PKEY1, pubNoAlg);

        key.releaseNativeStruct();
    }

    @Test
    public void derImportRoundTrips() {

        assumeEnabled();

        Ed448 orig = newKey();
        byte[] spki = orig.exportPublicKeyDer(true);
        byte[] pkcs8 = orig.exportPrivateKeyDer();
        byte[] pkcs8v2 = orig.exportPrivateKeyDer(true);
        byte[] msg = "der".getBytes();
        byte[] sig = orig.sign(msg);

        Ed448 pub = new Ed448();
        pub.importPublicKeyDer(spki);
        assertTrue(pub.hasPublicKey());
        assertFalse(pub.hasPrivateKey());
        assertArrayEquals(orig.exportPublic(), pub.exportPublic());
        assertTrue(pub.verify(sig, msg));
        assertArrayEquals(spki, pub.exportPublicKeyDer(true));
        pub.releaseNativeStruct();

        Ed448 priv = new Ed448();
        priv.importPrivateKeyDer(pkcs8);
        assertTrue(priv.hasPrivateKey());
        assertTrue(priv.hasPublicKey());
        assertArrayEquals(orig.exportPrivateOnly(), priv.exportPrivateOnly());
        assertArrayEquals(orig.exportPrivate(), priv.exportPrivate());
        assertArrayEquals(orig.exportPublic(), priv.exportPublic());
        assertArrayEquals(sig, priv.sign(msg));
        assertArrayEquals(pkcs8, priv.exportPrivateKeyDer());
        priv.releaseNativeStruct();

        Ed448 priv2 = new Ed448();
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
            Arrays.copyOf(concat(SPKI_PREFIX, Ed448TestVectors.PKEY1), 60),
            "not der at all, just some bytes......".getBytes(),
            /* Ed25519 OID with an Ed448 sized key */
            concat(new byte[] {
                (byte)0x30, (byte)0x43, (byte)0x30, (byte)0x05, (byte)0x06,
                (byte)0x03, (byte)0x2b, (byte)0x65, (byte)0x70, (byte)0x03,
                (byte)0x3a, (byte)0x00 }, Ed448TestVectors.PKEY1)
        };
        for (byte[] der : badPub) {
            Ed448 key = new Ed448();
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
            Arrays.copyOf(concat(PKCS8_PREFIX, Ed448TestVectors.SKEY1), 40),
            concat(SPKI_PREFIX, Ed448TestVectors.PKEY1)
        };
        for (byte[] der : badPriv) {
            Ed448 key = new Ed448();
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
            FeatureDetect.Ed448StreamingVerifyEnabled());

        byte[] msg = Ed448TestVectors.MSG[5];
        byte[] sig = Ed448TestVectors.SIG[5];

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY[5]);

        key.verifyInit(sig, Ed448.ED448_TYPE_PURE, null);
        key.verifyUpdate(new byte[0]);
        key.verifyUpdate(msg, 0, 1);
        key.verifyUpdate(msg, 1, 100);
        key.verifyUpdate(msg, 101, msg.length - 101);
        assertTrue(key.verifyFinal(sig));

        byte[] bad = msg.clone();
        bad[500] ^= 1;
        key.verifyInit(sig, Ed448.ED448_TYPE_PURE, null);
        key.verifyUpdate(bad);
        assertFalse(key.verifyFinal(sig));

        assertTrue(key.verify(sig, msg));
        key.releaseNativeStruct();

        /* with context */
        Ed448 ctxKey = new Ed448();
        ctxKey.importPublic(Ed448TestVectors.CTX_PKEY);
        ctxKey.verifyInit(Ed448TestVectors.CTX_SIG_FOO,
            Ed448.ED448_TYPE_PURE, Ed448TestVectors.CTX_CONTEXT);
        ctxKey.verifyUpdate(Ed448TestVectors.CTX_MSG);
        assertTrue(ctxKey.verifyFinal(Ed448TestVectors.CTX_SIG_FOO));
        ctxKey.releaseNativeStruct();

        /* ph variant */
        Ed448 phKey = new Ed448();
        phKey.importPublic(Ed448TestVectors.PH_PKEY);
        phKey.verifyInit(Ed448TestVectors.PH_SIG, Ed448.ED448_TYPE_PH, null);
        /* streaming ph verify is fed the pre-hash, not the message */
        phKey.verifyUpdate(Ed448TestVectors.PH_HASH);
        assertTrue(phKey.verifyFinal(Ed448TestVectors.PH_SIG));
        phKey.releaseNativeStruct();
    }

    @Test
    public void streamingVerifyStateErrors() {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed448StreamingVerifyEnabled());

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);

        try {
            key.verifyUpdate(new byte[1]);
            fail("update before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verifyFinal(Ed448TestVectors.SIG1);
            fail("final before init should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            key.verifyInit(new byte[Ed448.ED448_SIG_SIZE - 1],
                Ed448.ED448_TYPE_PURE, null);
            fail("wrong-length signature should throw");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE, null);
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
        assertTrue(key.verifyFinal(Ed448TestVectors.SIG1));

        try {
            key.verifyFinal(Ed448TestVectors.SIG1);
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
            FeatureDetect.Ed448StreamingVerifyEnabled());

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);
        try {
            key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE,
                null);
            fail("verifyInit should throw NOT_COMPILED_IN");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        key.releaseNativeStruct();
    }

    @Test
    public void contextTooLongIsRejected() {

        assumeEnabled();

        Ed448 key = newKey();
        byte[] msg = "ctx".getBytes();
        byte[] max = new byte[Ed448.ED448_MAX_CONTEXT_LEN];
        byte[] tooLong = new byte[Ed448.ED448_MAX_CONTEXT_LEN + 1];

        byte[] sig = key.sign(msg, max);
        assertTrue(key.verify(sig, msg, max));
        assertTrue(key.verifyPh(key.signPh(msg, max), msg, max));

        try {
            key.sign(msg, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verify(sig, msg, tooLong);
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
            key.signEx(msg, Ed448.ED448_TYPE_PURE, tooLong);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void prehashLengthIsChecked() {

        assumeEnabled();

        Ed448 key = newKey();

        try {
            key.signPhHash(new byte[Ed448.ED448_PREHASH_SIZE - 1], null);
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
            key.verifyPhHash(new byte[Ed448.ED448_SIG_SIZE],
                new byte[Ed448.ED448_PREHASH_SIZE + 1], null);
            fail("65 byte hash should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        key.releaseNativeStruct();
    }

    @Test
    public void invalidTypeIsRejected() {

        assumeEnabled();

        Ed448 key = newKey();
        byte[] msg = "type".getBytes();
        try {
            key.signEx(msg, 7, null);
            fail("invalid type should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            key.verifyEx(new byte[Ed448.ED448_SIG_SIZE], msg, -1, null);
            fail("invalid type should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        key.releaseNativeStruct();
    }

    @Test
    public void nullArgumentsAreRejected() {

        assumeEnabled();

        Ed448 key = newKey();
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

        Ed448 key = new Ed448();
        byte[] msg = "nokey".getBytes();

        try {
            key.sign(msg);
            fail("sign without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verify(new byte[Ed448.ED448_SIG_SIZE], msg);
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

        assumeEnabled();

        Ed448 key = newKey();
        try {
            key.importPublic(Ed448TestVectors.PKEY1);
            fail("second import should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.importPrivateKeyDer(key.exportPrivateKeyDer());
            fail("second DER import should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        key.releaseNativeStruct();
    }

    @Test
    public void useAfterReleaseThrows() {

        assumeEnabled();

        Ed448 key = newKey();
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

    @Test
    public void repeatedCreateReleaseStress() {

        assumeEnabled();

        /* stress only, leak detection is the sanitizer job's */

        byte[] msg = "leak loop".getBytes();
        for (int i = 0; i < 1000; i++) {
            Ed448 key = newKey();
            Ed448 again = new Ed448();
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

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed448StreamingVerifyEnabled());

        Ed448 key = new Ed448();
        key.importPrivate(Ed448TestVectors.SKEY1,
            Ed448TestVectors.PKEY1);
        key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE, null);

        /* one-shot calls would clobber the streaming digest */
        try {
            key.sign(Ed448TestVectors.MSG1);
            fail("sign during streaming verify should fail");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            key.verify(Ed448TestVectors.SIG1, Ed448TestVectors.MSG1);
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
        key.verifyUpdate(Ed448TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed448TestVectors.SIG1));
        assertArrayEquals(Ed448TestVectors.SIG1,
            key.sign(Ed448TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void streamingVerifyIsBoundToStartingThread() throws Exception {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed448StreamingVerifyEnabled());

        final Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);
        key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE, null);

        /* another thread may neither feed, finish nor restart the stream */
        final AtomicInteger rejected = new AtomicInteger(0);
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    key.verifyUpdate(Ed448TestVectors.MSG1);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
                try {
                    key.verifyFinal(Ed448TestVectors.SIG1);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
                try {
                    key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE,
                        null);
                } catch (IllegalStateException e) {
                    rejected.incrementAndGet();
                }
            }
        });
        t.start();
        t.join();
        assertEquals(3, rejected.get());

        /* the starting thread finishes normally */
        key.verifyUpdate(Ed448TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed448TestVectors.SIG1));

        key.releaseNativeStruct();
    }

    @Test
    public void verifyAbortWithoutStreamIsHarmless() {

        assumeEnabled();

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);
        key.verifyAbort();
        key.verifyAbort();
        assertTrue(key.verify(Ed448TestVectors.SIG1, Ed448TestVectors.MSG1));
        key.releaseNativeStruct();
    }

    @Test
    public void verifyAbortDropsAnAbandonedStream() throws Exception {

        assumeEnabled();
        Assume.assumeTrue("streaming verify not compiled in",
            FeatureDetect.Ed448StreamingVerifyEnabled());

        final Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);
        key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE, null);

        /* any thread may drop the stream */
        Thread t = new Thread(new Runnable() {
            public void run() {
                key.verifyAbort();
            }
        });
        t.start();
        t.join();

        assertTrue(key.verify(Ed448TestVectors.SIG1, Ed448TestVectors.MSG1));
        try {
            key.verifyFinal(Ed448TestVectors.SIG1);
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
            FeatureDetect.Ed448StreamingVerifyEnabled());

        Ed448 key = new Ed448();
        key.importPublic(Ed448TestVectors.PKEY1);

        /* S with its top bits set, native rejects it before verifying */
        byte[] bad = Ed448TestVectors.SIG1.clone();
        bad[bad.length - 1] |= (byte)0x80;
        assertFalse(key.verify(bad, Ed448TestVectors.MSG1));

        key.verifyInit(bad, Ed448.ED448_TYPE_PURE, null);
        key.verifyUpdate(Ed448TestVectors.MSG1);
        assertFalse(key.verifyFinal(bad));

        /* the object is usable again afterwards */
        key.verifyInit(Ed448TestVectors.SIG1, Ed448.ED448_TYPE_PURE, null);
        key.verifyUpdate(Ed448TestVectors.MSG1);
        assertTrue(key.verifyFinal(Ed448TestVectors.SIG1));

        key.releaseNativeStruct();
    }

    @Test
    public void threadedSignVerifyOnSharedKey() throws Exception {

        assumeEnabled();

        final Ed448 key = new Ed448();
        key.importPrivate(Ed448TestVectors.SKEY1, Ed448TestVectors.PKEY1);
        final boolean streaming = FeatureDetect.Ed448StreamingVerifyEnabled();
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
                    Ed448 own = new Ed448();
                    try {
                        own.importPublic(Ed448TestVectors.PKEY1);
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
                                own.verifyInit(Ed448TestVectors.SIG1,
                                    Ed448.ED448_TYPE_PURE, null);
                                own.verifyUpdate(Ed448TestVectors.MSG1);
                                if (!own.verifyFinal(Ed448TestVectors.SIG1)) {
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
