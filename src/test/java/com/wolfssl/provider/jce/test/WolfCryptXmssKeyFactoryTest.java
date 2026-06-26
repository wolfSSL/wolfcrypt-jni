/* WolfCryptXmssKeyFactoryTest.java
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
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * wolfJCE tests for the XMSS/XMSS^MT KeyFactory service (verify-only), via the
 * JCE API.
 *
 * <p>wolfJCE XMSS is verify-only, so the public key is built from a raw XMSS
 * public key wrapped in an RFC 9802 X.509 SubjectPublicKeyInfo rather than
 * generated. The raw key is the XMSS-SHA2_10_256 public key from the
 * independent xmss-reference implementation, so this also exercises
 * interoperability with externally-produced keys.</p>
 */
public class WolfCryptXmssKeyFactoryTest {

    private static boolean xmssEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptXmssKeyFactoryTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        xmssEnabled = FeatureDetect.XmssEnabled();
    }

    private void assumeEnabled() {
        Assume.assumeTrue("XMSS not compiled in", xmssEnabled);
    }

    /* XMSS-SHA2_10_256 raw public key (OID || root || SEED, 68 bytes) from the
     * xmss-reference implementation. */
    private static final byte[] XMSS_SHA2_10_256_PK = Util.h2b(
        "00000001a54131960af9f3b24b2e5b3eca74ad6ca589ad2c0e96b354fb5b6350" +
        "9681e25972100954bb39acee78ef95ec011df03668e2c4a52f60427ed38eaa27" +
        "c9b7394e");

    /* id-alg-xmss-hashsig 1.3.6.1.5.5.7.6.34 as a DER OID TLV (RFC 9802). */
    private static final byte[] XMSS_OID = new byte[] {
        (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01,
        (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x06, (byte) 0x22
    };

    /* id-alg-xmssmt-hashsig 1.3.6.1.5.5.7.6.35 as a DER OID TLV (RFC 9802). */
    private static final byte[] XMSSMT_OID = new byte[] {
        (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01,
        (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x06, (byte) 0x23
    };

    /* XMSSMT-SHA2_20/2_256 raw public key (68 bytes), generated with the
     * installed wolfSSL. Note the same 4-byte OID prefix as the single-tree
     * key above, so the family must come from the SPKI OID (.35). */
    private static final byte[] XMSSMT_SHA2_20_2_256_PK = Util.h2b(
        "00000001e10ba1f14edccd6f3234fd5745f027ad5ed98a5652cf66e421ae3856" +
        "6e20819daf80f1c796a85f36764c1b37e5d17ad86106296c2aa53143e748cf96" +
        "71e057b1");

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

    /* Wrap a raw XMSS public key as an RFC 9802 SPKI:
     * SEQUENCE { SEQUENCE { OID }, BIT STRING { rawPub } }. */
    private static byte[] spki(byte[] rawPub) {
        byte[] algId = tlv(0x30, XMSS_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 }, rawPub));
        return tlv(0x30, concat(algId, bitString));
    }

    /* Wrap a raw XMSS^MT public key as an RFC 9802 SPKI (XMSSMT OID). */
    private static byte[] spkiMt(byte[] rawPub) {
        byte[] algId = tlv(0x30, XMSSMT_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 }, rawPub));
        return tlv(0x30, concat(algId, bitString));
    }

    @Test
    public void aliasesResolve() throws Exception {
        assumeEnabled();

        /* KeyFactory (public-key handling) is always available under both
         * family names and the RFC 9802 OIDs. */
        KeyFactory.getInstance("XMSS", "wolfJCE");
        KeyFactory.getInstance("XMSSMT", "wolfJCE");
        KeyFactory.getInstance("1.3.6.1.5.5.7.6.34", "wolfJCE");
        KeyFactory.getInstance("1.3.6.1.5.5.7.6.35", "wolfJCE");
    }

    @Test
    public void publicKeyRoundTrip() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        PublicKey pub = kf.generatePublic(
            new X509EncodedKeySpec(spki(XMSS_SHA2_10_256_PK)));
        assertEquals("XMSS", pub.getAlgorithm());
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

    @Test
    public void xmssMtPublicKeyFamily() throws Exception {
        assumeEnabled();

        /* An XMSSMT SPKI (OID .35) must produce a key whose algorithm is
         * XMSSMT, even though its raw OID prefix matches a single-tree key. */
        KeyFactory kf = KeyFactory.getInstance("XMSSMT", "wolfJCE");
        PublicKey pub = kf.generatePublic(
            new X509EncodedKeySpec(spkiMt(XMSSMT_SHA2_20_2_256_PK)));
        assertEquals("XMSSMT", pub.getAlgorithm());
        assertEquals("X.509", pub.getFormat());

        /* Stable round-trip. */
        PublicKey pub2 = kf.generatePublic(
            new X509EncodedKeySpec(pub.getEncoded()));
        assertEquals(pub, pub2);
        assertArrayEquals(pub.getEncoded(), pub2.getEncoded());
    }

    @Test
    public void nonMinimalDerLengthRejected() throws Exception {
        assumeEnabled();

        /* Outer SEQUENCE with a non-minimal long-form length
         * (0x82 0x00 0x03 instead of 0x03): the strict DER reader must
         * reject it rather than silently accept the redundant leading zero. */
        byte[] malformed = new byte[] {
            (byte) 0x30, (byte) 0x82, (byte) 0x00, (byte) 0x03,
            (byte) 0x01, (byte) 0x02, (byte) 0x03
        };
        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        try {
            kf.generatePublic(new X509EncodedKeySpec(malformed));
            fail("non-minimal DER length should be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void privateKeySpecRejected() throws Exception {
        assumeEnabled();

        /* Private keys are not supported (verify-only). */
        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        try {
            kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(new byte[] { 0 }));
            fail("expected XMSS private keys to be unsupported");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void wrappedOctetStringSpkiAccepted() throws Exception {
        assumeEnabled();

        /* Some encoders wrap the raw RFC 8391 public key in an inner OCTET
         * STRING inside the BIT STRING; WolfCryptXmssUtil accepts that form
         * and normalizes it to the same RFC 9802 (unwrapped) encoding. */
        byte[] octet = tlv(0x04, XMSS_SHA2_10_256_PK);
        byte[] algId = tlv(0x30, XMSS_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 }, octet));
        byte[] spkiWrapped = tlv(0x30, concat(algId, bitString));

        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        PublicKey pub = kf.generatePublic(
            new X509EncodedKeySpec(spkiWrapped));
        assertEquals("XMSS", pub.getAlgorithm());

        /* Wrapped and unwrapped inputs normalize to the same encoding. */
        PublicKey unwrapped = kf.generatePublic(
            new X509EncodedKeySpec(spki(XMSS_SHA2_10_256_PK)));
        assertArrayEquals(unwrapped.getEncoded(), pub.getEncoded());
    }

    @Test
    public void nullAlgorithmIdParametersAccepted() throws Exception {
        assumeEnabled();

        /* RFC 9802 omits the AlgorithmIdentifier parameters for XMSS, but JDK
         * X.509 re-encodes the SubjectPublicKeyInfo with an explicit NULL
         * parameters field when it hands a certificate public key to this
         * KeyFactory by OID. Accept that form and normalize it to the
         * canonical RFC 9802 (no-parameters) encoding. */
        byte[] algIdNull = tlv(0x30, concat(XMSS_OID,
            new byte[] { (byte) 0x05, (byte) 0x00 }));
        byte[] bitString = tlv(0x03,
            concat(new byte[] { 0x00 }, XMSS_SHA2_10_256_PK));
        byte[] spkiNull = tlv(0x30, concat(algIdNull, bitString));

        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spkiNull));
        assertEquals("XMSS", pub.getAlgorithm());

        /* NULL-parameter and absent-parameter inputs normalize to the same
         * canonical encoding. */
        PublicKey canonical = kf.generatePublic(
            new X509EncodedKeySpec(spki(XMSS_SHA2_10_256_PK)));
        assertArrayEquals(canonical.getEncoded(), pub.getEncoded());
    }

    @Test
    public void nonNullAlgorithmIdParametersRejected() throws Exception {
        assumeEnabled();

        /* Only an absent or NULL parameters field is allowed. Any other
         * AlgorithmIdentifier parameters (here an INTEGER) must be rejected. */
        byte[] algIdInt = tlv(0x30, concat(XMSS_OID,
            tlv(0x02, new byte[] { 0x01 })));
        byte[] bitString = tlv(0x03,
            concat(new byte[] { 0x00 }, XMSS_SHA2_10_256_PK));
        byte[] spkiInt = tlv(0x30, concat(algIdInt, bitString));

        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        try {
            kf.generatePublic(new X509EncodedKeySpec(spkiInt));
            fail("non-NULL AlgorithmIdentifier parameters should be rejected");
        } catch (java.security.spec.InvalidKeySpecException e) {
            /* expected */
        }
    }
}
