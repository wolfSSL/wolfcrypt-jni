/* WolfCryptLmsKeyFactoryTest.java
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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * wolfJCE tests for the LMS/HSS KeyFactory service (verify-only), via JCE API.
 *
 * <p>wolfJCE LMS is verify-only (matching the JDK SUN provider), so the public
 * key is built from the RFC 8554 Test Case 1 raw HSS public key wrapped in an
 * X.509 SubjectPublicKeyInfo rather than generated.</p>
 */
public class WolfCryptLmsKeyFactoryTest {

    private static boolean lmsEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptLmsKeyFactoryTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        lmsEnabled = FeatureDetect.LmsEnabled();
    }

    private void assumeEnabled() {
        Assume.assumeTrue("LMS not compiled in", lmsEnabled);
    }

    /* Short local alias of Util.h2b() to keep the vector readable. */
    private static byte[] hex(String s) {
        return Util.h2b(s);
    }

    /* RFC 8554 Appendix F Test Case 1 raw HSS public key (HSS L2, SHA256
     * H5/W8), 60 bytes. */
    private static final byte[] RFC8554_TC1_PK = hex(
        "00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b" +
        "31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878");

    /* HSS/LMS algorithm OID 1.2.840.113549.1.9.16.3.17 as a DER TLV. */
    private static final byte[] HSS_LMS_OID = new byte[] {
        (byte) 0x06, (byte) 0x0B, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
        (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x09,
        (byte) 0x10, (byte) 0x03, (byte) 0x11
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

    /* Wrap a raw HSS/LMS public key as an RFC 9708 (unwrapped) SPKI:
     * SEQUENCE { SEQUENCE { OID }, BIT STRING { rawPub } }. */
    private static byte[] spki(byte[] rawPub) {

        byte[] algId = tlv(0x30, HSS_LMS_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 }, rawPub));

        return tlv(0x30, concat(algId, bitString));
    }

    /* Import the RFC 8554 TC1 (SHA-256/256) KAT public key via the given
     * KeyFactory. Parameter family may be compiled out of native wolfCrypt,
     * in which case underlying import throws NOT_COMPILED_IN. Treat that as
     * "skip". */
    private static PublicKey importTc1Key(KeyFactory kf) throws Exception {

        try {
            return kf.generatePublic(
                new X509EncodedKeySpec(spki(RFC8554_TC1_PK)));

        } catch (java.security.spec.InvalidKeySpecException e) {
            if (isNotCompiledIn(e)) {
                Assume.assumeTrue(
                    "LMS SHA-256/256 parameter set not compiled in", false);
            }
            throw e;
        }
    }

    /* True if throwable cause chain contains NOT_COMPILED_IN. */
    private static boolean isNotCompiledIn(Throwable t) {

        for (; t != null; t = t.getCause()) {
            if (t instanceof WolfCryptException &&
                ((WolfCryptException) t).getError() ==
                    WolfCryptError.NOT_COMPILED_IN) {
                return true;
            }
        }

        return false;
    }

    @Test
    public void aliasesResolve() throws Exception {
        assumeEnabled();

        /* KeyFactory (public-key handling) is always available. */
        KeyFactory.getInstance("LMS", "wolfJCE");
        KeyFactory.getInstance("HSS/LMS", "wolfJCE");
    }

    @Test
    public void publicKeyRoundTrip() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);
        assertEquals("HSS/LMS", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());

        byte[] x509 = pub.getEncoded();
        assertNotNull(x509);

        /* Re-import the produced X.509 encoding; it must be stable. */
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(x509));
        assertEquals(pub, pub2);
        assertArrayEquals(x509, pub2.getEncoded());

        /* round-trip via getKeySpec */
        X509EncodedKeySpec spec =
            kf.getKeySpec(pub2, X509EncodedKeySpec.class);
        assertArrayEquals(x509, spec.getEncoded());
    }

    /* JDK <= 17 re-encodes an LMS SubjectPublicKeyInfo with an explicit NULL
     * parameter before passing it here, so wolfJCE must accept the NULL form
     * as equivalent to the parameters-absent form. This is what lets LMS
     * certificates load via CertificateFactory on older JDKs. */
    @Test
    public void generatePublicAcceptsNullAlgorithmParameters()
        throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey noParams = importTc1Key(kf);

        /* AlgorithmIdentifier SEQUENCE { OID, NULL } instead of { OID }. */
        byte[] algId = tlv(0x30, concat(HSS_LMS_OID,
            new byte[] { (byte) 0x05, (byte) 0x00 }));
        byte[] bitString =
            tlv(0x03, concat(new byte[] { 0x00 }, RFC8554_TC1_PK));
        byte[] spkiWithNull = tlv(0x30, concat(algId, bitString));

        PublicKey withNull =
            kf.generatePublic(new X509EncodedKeySpec(spkiWithNull));

        /* Same key, and getEncoded() normalizes to the canonical (no
         * parameters) SubjectPublicKeyInfo. */
        assertEquals(noParams, withNull);
        assertArrayEquals(noParams.getEncoded(), withNull.getEncoded());
    }

    /* Both SPKI body forms are accepted: RFC 9708 with the raw key directly
     * in the BIT STRING, and RFC 8708 with an inner OCTET STRING wrapping
     * it. Both normalize to the canonical RFC 9708 encoding, so getEncoded()
     * and getKeySpec() output can differ from the bytes a caller passed in. */
    @Test
    public void wrappedFormNormalizesToUnwrapped() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey unwrapped = importTc1Key(kf);
        byte[] canonical = unwrapped.getEncoded();

        /* BIT STRING carries OCTET STRING { raw key } instead of the raw
         * key directly. */
        byte[] algId = tlv(0x30, HSS_LMS_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 },
            tlv(0x04, RFC8554_TC1_PK)));
        final byte[] spkiWrapped = tlv(0x30, concat(algId, bitString));

        PublicKey wrapped =
            kf.generatePublic(new X509EncodedKeySpec(spkiWrapped));

        assertEquals(unwrapped, wrapped);
        assertArrayEquals(canonical, wrapped.getEncoded());

        /* getKeySpec() of a foreign key holding the wrapped encoding also
         * returns the canonical unwrapped form: keys are normalized
         * through translateKey(), not passed through byte-for-byte. */
        PublicKey foreign = new PublicKey() {
            public String getAlgorithm() { return "HSS/LMS"; }
            public String getFormat() { return "X.509"; }
            public byte[] getEncoded() { return spkiWrapped.clone(); }
        };
        X509EncodedKeySpec spec =
            kf.getKeySpec(foreign, X509EncodedKeySpec.class);
        assertArrayEquals(canonical, spec.getEncoded());
    }

    @Test
    public void privateKeySpecRejected() throws Exception {
        assumeEnabled();

        /* Private keys are not supported (verify-only). */
        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        try {
            kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(new byte[] { 0 }));
            fail("expected LMS private keys to be unsupported");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    /* A byte-identical public key reporting the JDK standard name "HSS/LMS"
     * (or "LMS", case-insensitively) must compare equal, since this provider
     * registers both names for the same algorithm. */
    @Test
    public void equalsAcceptsHssLmsAlgorithmName() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);
        byte[] enc = pub.getEncoded();

        assertTrue("HSS/LMS name should compare equal",
            pub.equals(stubKey("HSS/LMS", enc)));
        assertTrue("LMS name should compare equal",
            pub.equals(stubKey("LMS", enc)));
        assertTrue("name match should be case-insensitive",
            pub.equals(stubKey("hss/lms", enc)));

        /* Different algorithm name, same bytes -> not equal. */
        assertFalse("non-LMS name should not compare equal",
            pub.equals(stubKey("RSA", enc)));

        /* Same name, different bytes -> not equal. */
        byte[] diff = enc.clone();
        diff[diff.length - 1] ^= (byte) 0xFF;
        assertFalse("different encoding should not compare equal",
            pub.equals(stubKey("HSS/LMS", diff)));
    }

    @Test
    public void generatePublicRejectsNonX509Spec() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        try {
            kf.generatePublic(new java.security.spec.PKCS8EncodedKeySpec(
                spki(RFC8554_TC1_PK)));
            fail("expected non-X509EncodedKeySpec to be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void generatePublicRejectsMalformedDer() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        try {
            kf.generatePublic(
                new X509EncodedKeySpec(new byte[] { 0x01, 0x02, 0x03 }));
            fail("expected malformed DER to be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void generatePublicRejectsWrongOid() throws Exception {
        assumeEnabled();

        /* Valid SPKI structure but the RSA OID, not HSS/LMS. */
        byte[] rsaOid = new byte[] {
            (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01,
            (byte) 0x01
        };
        byte[] der = tlv(0x30, concat(tlv(0x30, rsaOid),
            tlv(0x03, concat(new byte[] { 0x00 }, RFC8554_TC1_PK))));

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        try {
            kf.generatePublic(new X509EncodedKeySpec(der));
            fail("expected wrong-OID SPKI to be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void getKeySpecRejectsUnsupportedSpecClass() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);
        try {
            kf.getKeySpec(pub,
                java.security.spec.PKCS8EncodedKeySpec.class);
            fail("expected unsupported KeySpec class to be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void translateKeyRoundTrips() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);

        /* Our own key object is returned as-is. */
        assertSame(pub, kf.translateKey(pub));

        /* A foreign X.509 key with the same encoding translates to an
         * equal wolfJCE key. */
        assertEquals(pub,
            kf.translateKey(stubKey("HSS/LMS", pub.getEncoded())));
    }

    @Test
    public void translateKeyRejectsNonX509Format() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        try {
            kf.translateKey(rawFormatKey());
            fail("expected non-X.509 key format to be rejected");
        } catch (java.security.InvalidKeyException e) {
            /* expected */
        }
    }

    /* Minimal PublicKey returning a fixed algorithm name and X.509 encoding,
     * to stand in for an equal key produced by another provider. */
    private static PublicKey stubKey(final String algorithm,
        final byte[] encoded) {

        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return algorithm;
            }
            @Override
            public String getFormat() {
                return "X.509";
            }
            @Override
            public byte[] getEncoded() {
                return encoded.clone();
            }
        };
    }

    /* Minimal PublicKey reporting a non-X.509 format, for exercising
     * translateKey() format rejection. */
    private static PublicKey rawFormatKey() {

        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "LMS";
            }
            @Override
            public String getFormat() {
                return "RAW";
            }
            @Override
            public byte[] getEncoded() {
                return new byte[] { 0x00 };
            }
        };
    }
}
