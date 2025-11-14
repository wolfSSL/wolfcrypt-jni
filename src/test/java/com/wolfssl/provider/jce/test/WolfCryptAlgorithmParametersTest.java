/* WolfCryptAlgorithmParametersTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Test;
import org.junit.BeforeClass;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.Provider;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGenerator;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfCryptAlgorithmParametersTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        System.out.println("JCE WolfCryptAlgorithmParametersTest Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    @Test
    public void testGetAlgorithmParametersFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        AlgorithmParameters params;

        /* DH should be available */
        params = AlgorithmParameters.getInstance("DH", "wolfJCE");
        assertNotNull(params);

        /* Getting a garbage algorithm should throw an exception */
        try {
            params = AlgorithmParameters.getInstance(
                "NotValid", "wolfJCE");

            fail("AlgorithmParameters.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersInitWithDHParameterSpec()
        throws Exception {

        /* Create known DH parameters */
        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);

        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        assertNotNull(params);

        params.init(spec);

        /* Retrieve the parameters back */
        DHParameterSpec retrievedSpec =
            params.getParameterSpec(DHParameterSpec.class);
        assertNotNull(retrievedSpec);
        assertEquals(p, retrievedSpec.getP());
        assertEquals(g, retrievedSpec.getG());
    }

    @Test
    public void testDHParametersInitWithDHParameterSpecIncludingL()
        throws Exception {

        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);
        int l = 256;

        DHParameterSpec spec = new DHParameterSpec(p, g, l);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        DHParameterSpec retrievedSpec =
            params.getParameterSpec(DHParameterSpec.class);
        assertEquals(p, retrievedSpec.getP());
        assertEquals(g, retrievedSpec.getG());
        assertEquals(l, retrievedSpec.getL());
    }

    @Test
    public void testDHParametersInitWithInvalidParameterSpec()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        /* Try to initialize with wrong type of ParameterSpec */
        try {
            AlgorithmParameterSpec invalidSpec =
                new AlgorithmParameterSpec() {};
            params.init(invalidSpec);

            fail("AlgorithmParameters.init should throw " +
                 "InvalidParameterSpecException when given wrong spec type");

        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersGetParameterSpecWithWrongClass()
        throws Exception {

        BigInteger p = new BigInteger("123456789");
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        /* Try to get base AlgorithmParameterSpec class - this succeeds
         * because DHParameterSpec implements AlgorithmParameterSpec
         * and the implementation correctly returns a DHParameterSpec which
         * can be cast to AlgorithmParameterSpec */
        AlgorithmParameterSpec retrievedSpec =
            params.getParameterSpec(AlgorithmParameterSpec.class);
        assertNotNull(retrievedSpec);
        assertTrue(retrievedSpec instanceof DHParameterSpec);

        /* Try with a completely wrong spec type that DH doesn't support */
        try {
            IvParameterSpec ivSpec =
                params.getParameterSpec(IvParameterSpec.class);

            fail("AlgorithmParameters.getParameterSpec should throw " +
                 "InvalidParameterSpecException when given unsupported class");

        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersGetParameterSpecWithNull()
        throws Exception {

        BigInteger p = new BigInteger("123456789");
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        /* Try to get ParameterSpec with null class */
        try {
            params.getParameterSpec(null);

            fail("AlgorithmParameters.getParameterSpec should throw " +
                 "InvalidParameterSpecException when given null");

        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersGetParameterSpecBeforeInit()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        /* Try to get ParameterSpec before initialization */
        try {
            params.getParameterSpec(DHParameterSpec.class);

            fail("AlgorithmParameters.getParameterSpec should throw " +
                 "InvalidParameterSpecException when not initialized");

        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersEncodingDER()
        throws Exception {

        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);

        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        /* Get DER encoding */
        byte[] encoded = params.getEncoded();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);

        /* Verify it starts with SEQUENCE tag (0x30) */
        assertEquals(0x30, encoded[0] & 0xFF);

        /* Create new AlgorithmParameters and init with encoded bytes */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params2.init(encoded);

        DHParameterSpec spec2 =
            params2.getParameterSpec(DHParameterSpec.class);
        assertEquals(p, spec2.getP());
        assertEquals(g, spec2.getG());
    }

    @Test
    public void testDHParametersEncodingWithFormat()
        throws Exception {

        BigInteger p = new BigInteger("123456789");
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        /* Test ASN.1 format */
        byte[] asnEncoded = params.getEncoded("ASN.1");
        assertNotNull(asnEncoded);

        /* Test DER format */
        byte[] derEncoded = params.getEncoded("DER");
        assertNotNull(derEncoded);

        /* ASN.1 and DER should be the same for DH params */
        assertTrue(Arrays.equals(asnEncoded, derEncoded));

        /* Test case insensitivity */
        byte[] lowerEncoded = params.getEncoded("asn.1");
        assertTrue(Arrays.equals(asnEncoded, lowerEncoded));
    }

    @Test
    public void testDHParametersEncodingUnsupportedFormat()
        throws Exception {

        BigInteger p = new BigInteger("123456789");
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        /* Try unsupported format */
        try {
            params.getEncoded("PEM");
            fail("AlgorithmParameters.getEncoded should throw " +
                 "IOException for unsupported format");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersEncodingBeforeInit()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        /* Try to encode before initialization */
        try {
            params.getEncoded();
            fail("AlgorithmParameters.getEncoded should throw " +
                 "IOException when not initialized");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersInitWithDERBytes()
        throws Exception {

        /* Generate parameters to get valid DER encoding */
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        paramGen.init(2048);
        AlgorithmParameters params1 = paramGen.generateParameters();
        byte[] encoded = params1.getEncoded();

        /* Create new AlgorithmParameters and init with DER bytes */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params2.init(encoded);

        /* Verify we get the same parameters back */
        DHParameterSpec spec1 =
            params1.getParameterSpec(DHParameterSpec.class);
        DHParameterSpec spec2 =
            params2.getParameterSpec(DHParameterSpec.class);

        assertEquals(spec1.getP(), spec2.getP());
        assertEquals(spec1.getG(), spec2.getG());
    }

    @Test
    public void testDHParametersInitWithDERBytesAndFormat()
        throws Exception {

        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        paramGen.init(2048);
        AlgorithmParameters params1 = paramGen.generateParameters();
        byte[] encoded = params1.getEncoded();

        /* Test init with explicit format */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params2.init(encoded, "DER");

        DHParameterSpec spec1 =
            params1.getParameterSpec(DHParameterSpec.class);
        DHParameterSpec spec2 =
            params2.getParameterSpec(DHParameterSpec.class);

        assertEquals(spec1.getP(), spec2.getP());
        assertEquals(spec1.getG(), spec2.getG());

        /* Test with ASN.1 format */
        AlgorithmParameters params3 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params3.init(encoded, "ASN.1");

        DHParameterSpec spec3 =
            params3.getParameterSpec(DHParameterSpec.class);
        assertEquals(spec1.getP(), spec3.getP());
        assertEquals(spec1.getG(), spec3.getG());
    }

    @Test
    public void testDHParametersInitWithInvalidDERBytes()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        /* Try to init with invalid DER bytes */
        byte[] invalidDER = new byte[] { 0x01, 0x02, 0x03 };

        try {
            params.init(invalidDER);
            fail("AlgorithmParameters.init should throw " +
                 "IOException for invalid DER encoding");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersInitWithUnsupportedFormat()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        byte[] data = new byte[] { 0x30, 0x00 };

        try {
            params.init(data, "PEM");
            fail("AlgorithmParameters.init should throw " +
                 "IOException for unsupported format");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testDHParametersToString()
        throws Exception {

        BigInteger p = new BigInteger("123456789");
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec spec = new DHParameterSpec(p, g);

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params.init(spec);

        String str = params.toString();
        assertNotNull(str);
        assertTrue(str.contains("DH Parameters"));
        assertTrue(str.contains("p:"));
        assertTrue(str.contains("g:"));
    }

    @Test
    public void testDHParametersToStringBeforeInit()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("DH", "wolfJCE");

        /* Note: The standard Java AlgorithmParameters.toString() may return
         * null or an implementation-specific string. The JCA specification
         * doesn't mandate a specific format. Our engineToString() method
         * returns a proper string, but the standard Java wrapper doesn't
         * always call it. Just verify toString() doesn't throw an exception. */
        String str = params.toString();
        /* No assertions - just making sure it doesn't throw */
    }

    @Test
    public void testDHParametersInteropWithSunJCE()
        throws Exception {

        /* Generate parameters with wolfJCE */
        AlgorithmParameterGenerator wolfParamGen =
            AlgorithmParameterGenerator.getInstance("DH", "wolfJCE");
        wolfParamGen.init(2048);
        AlgorithmParameters wolfParams = wolfParamGen.generateParameters();

        byte[] wolfEncoded = wolfParams.getEncoded();

        /* Try to parse with SunJCE */
        try {
            AlgorithmParameters sunParams =
                AlgorithmParameters.getInstance("DH", "SunJCE");
            sunParams.init(wolfEncoded);

            /* Verify parameters match */
            DHParameterSpec wolfSpec =
                wolfParams.getParameterSpec(DHParameterSpec.class);
            DHParameterSpec sunSpec =
                sunParams.getParameterSpec(DHParameterSpec.class);

            assertEquals(wolfSpec.getP(), sunSpec.getP());
            assertEquals(wolfSpec.getG(), sunSpec.getG());

            /* Now test the reverse: SunJCE -> wolfJCE */
            byte[] sunEncoded = sunParams.getEncoded();

            AlgorithmParameters wolfParams2 =
                AlgorithmParameters.getInstance("DH", "wolfJCE");
            wolfParams2.init(sunEncoded);

            DHParameterSpec wolfSpec2 =
                wolfParams2.getParameterSpec(DHParameterSpec.class);

            assertEquals(sunSpec.getP(), wolfSpec2.getP());
            assertEquals(sunSpec.getG(), wolfSpec2.getG());

        } catch (NoSuchProviderException e) {
            /* SunJCE provider not available, skip interop test */
            System.out.println("\tSkipping SunJCE interop test, " +
                "provider not available");
        }
    }

    @Test
    public void testDHParametersRoundTrip()
        throws Exception {

        /* Test multiple round trips: spec -> params -> encoded ->
         * params -> spec.
         * NOTE: The 'l' parameter is not preserved through encoding/decoding
         * since standard DH ASN.1 encoding only includes p and g. */
        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);

        DHParameterSpec originalSpec = new DHParameterSpec(p, g);

        /* Round trip 1 */
        AlgorithmParameters params1 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params1.init(originalSpec);

        byte[] encoded1 = params1.getEncoded();

        /* Round trip 2 */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params2.init(encoded1);

        byte[] encoded2 = params2.getEncoded();

        /* Round trip 3 */
        AlgorithmParameters params3 =
            AlgorithmParameters.getInstance("DH", "wolfJCE");
        params3.init(encoded2);

        DHParameterSpec finalSpec =
            params3.getParameterSpec(DHParameterSpec.class);

        /* Verify all parameters match original (p and g only, not l) */
        assertEquals(originalSpec.getP(), finalSpec.getP());
        assertEquals(originalSpec.getG(), finalSpec.getG());

        /* Verify encodings are identical */
        assertTrue(Arrays.equals(encoded1, encoded2));
    }

    @Test
    public void testRSAPSSParametersGetInstance()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        AlgorithmParameters params;
        params = AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        assertNotNull(params);
    }

    @Test
    public void testRSAPSSParametersInitWithDefaultSpec()
        throws Exception {

        /* Create default PSS parameters (SHA-256, MGF1-SHA256, salt=32) */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        assertNotNull(params);

        params.init(spec);

        /* Retrieve parameters back */
        PSSParameterSpec retrievedSpec =
            params.getParameterSpec(PSSParameterSpec.class);
        assertNotNull(retrievedSpec);
        assertEquals("SHA-256", retrievedSpec.getDigestAlgorithm());
        assertEquals("MGF1", retrievedSpec.getMGFAlgorithm());
        assertEquals(32, retrievedSpec.getSaltLength());
        assertEquals(1, retrievedSpec.getTrailerField());

        /* Check MGF1 parameters */
        assertTrue(
            retrievedSpec.getMGFParameters() instanceof MGF1ParameterSpec);
        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) retrievedSpec.getMGFParameters();
        assertEquals("SHA-256", mgf1Spec.getDigestAlgorithm());
    }

    @Test
    public void testRSAPSSParametersInitWithSHA1Spec()
        throws Exception {

        /* SHA-1 with MGF1-SHA1, salt=20 */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        PSSParameterSpec retrievedSpec =
            params.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-1", retrievedSpec.getDigestAlgorithm());
        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) retrievedSpec.getMGFParameters();
        assertEquals("SHA-1", mgf1Spec.getDigestAlgorithm());
        assertEquals(20, retrievedSpec.getSaltLength());
    }

    @Test
    public void testRSAPSSParametersInitWithSHA384Spec()
        throws Exception {

        /* SHA-384 with MGF1-SHA384, salt=48 */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        PSSParameterSpec retrievedSpec =
            params.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-384", retrievedSpec.getDigestAlgorithm());
        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) retrievedSpec.getMGFParameters();
        assertEquals("SHA-384", mgf1Spec.getDigestAlgorithm());
        assertEquals(48, retrievedSpec.getSaltLength());
    }

    @Test
    public void testRSAPSSParametersInitWithSHA512Spec()
        throws Exception {

        /* SHA-512 with MGF1-SHA512, salt=64 */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        PSSParameterSpec retrievedSpec =
            params.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-512", retrievedSpec.getDigestAlgorithm());
        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) retrievedSpec.getMGFParameters();
        assertEquals("SHA-512", mgf1Spec.getDigestAlgorithm());
        assertEquals(64, retrievedSpec.getSaltLength());
    }

    @Test
    public void testRSAPSSParametersEncodingDERWithDefaults()
        throws Exception {

        /* RFC 4055 defaults: SHA-1, MGF1-SHA1, salt=20 */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        /* Get DER encoding */
        byte[] encoded = params.getEncoded();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);

        /* With all defaults, should be minimal SEQUENCE */
        /* SEQUENCE { } = 0x30 0x00 */
        assertEquals(0x30, encoded[0] & 0xFF);
        assertEquals(0x00, encoded[1] & 0xFF);

        /* Decode and verify */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params2.init(encoded);

        PSSParameterSpec spec2 =
            params2.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-1", spec2.getDigestAlgorithm());
        assertEquals(20, spec2.getSaltLength());
    }

    @Test
    public void testRSAPSSParametersEncodingDERWithNonDefaults()
        throws Exception {

        /* Non-default values: SHA-256, MGF1-SHA256, salt=32 */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        /* Get DER encoding */
        byte[] encoded = params.getEncoded();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);

        /* Should start with SEQUENCE tag */
        assertEquals(0x30, encoded[0] & 0xFF);

        /* Should be longer than minimal since we have non-defaults */
        assertTrue(encoded.length > 2);

        /* Decode and verify round trip */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params2.init(encoded);

        PSSParameterSpec spec2 =
            params2.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-256", spec2.getDigestAlgorithm());
        assertEquals("MGF1", spec2.getMGFAlgorithm());
        assertEquals(32, spec2.getSaltLength());
        assertEquals(1, spec2.getTrailerField());

        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) spec2.getMGFParameters();
        assertEquals("SHA-256", mgf1Spec.getDigestAlgorithm());
    }

    @Test
    public void testRSAPSSParametersEncodingAllHashAlgorithms()
        throws Exception {

        /* Test all supported hash algorithms */
        String[] hashAlgs = {
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA-512/224", "SHA-512/256"
        };

        MGF1ParameterSpec[] mgf1Specs = {
            MGF1ParameterSpec.SHA1,
            MGF1ParameterSpec.SHA224,
            MGF1ParameterSpec.SHA256,
            MGF1ParameterSpec.SHA384,
            MGF1ParameterSpec.SHA512,
            new MGF1ParameterSpec("SHA-512/224"),
            new MGF1ParameterSpec("SHA-512/256")
        };

        for (int i = 0; i < hashAlgs.length; i++) {
            PSSParameterSpec spec = new PSSParameterSpec(
                hashAlgs[i], "MGF1", mgf1Specs[i], 32, 1
            );

            AlgorithmParameters params =
                AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
            params.init(spec);

            byte[] encoded = params.getEncoded();
            assertNotNull(encoded);

            /* Decode and verify */
            AlgorithmParameters params2 =
                AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
            params2.init(encoded);

            PSSParameterSpec spec2 =
                params2.getParameterSpec(PSSParameterSpec.class);
            assertEquals(hashAlgs[i], spec2.getDigestAlgorithm());

            MGF1ParameterSpec mgf1Retrieved =
                (MGF1ParameterSpec) spec2.getMGFParameters();
            assertEquals(hashAlgs[i], mgf1Retrieved.getDigestAlgorithm());
        }
    }

    @Test
    public void testRSAPSSParametersEncodingVariousSaltLengths()
        throws Exception {

        int[] saltLengths = {0, 1, 16, 20, 32, 48, 64, 128, 255};

        for (int saltLen : saltLengths) {
            PSSParameterSpec spec = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1
            );

            AlgorithmParameters params =
                AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
            params.init(spec);

            byte[] encoded = params.getEncoded();
            assertNotNull(encoded);

            /* Decode and verify salt length preserved */
            AlgorithmParameters params2 =
                AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
            params2.init(encoded);

            PSSParameterSpec spec2 =
                params2.getParameterSpec(PSSParameterSpec.class);
            assertEquals(saltLen, spec2.getSaltLength());
        }
    }

    @Test
    public void testRSAPSSParametersEncodingMixedHashAlgorithms()
        throws Exception {

        /* Test with different hash for digest and MGF */
        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        byte[] encoded = params.getEncoded();

        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params2.init(encoded);

        PSSParameterSpec spec2 =
            params2.getParameterSpec(PSSParameterSpec.class);
        assertEquals("SHA-256", spec2.getDigestAlgorithm());

        MGF1ParameterSpec mgf1Spec =
            (MGF1ParameterSpec) spec2.getMGFParameters();
        assertEquals("SHA-1", mgf1Spec.getDigestAlgorithm());
    }

    @Test
    public void testRSAPSSParametersRoundTrip()
        throws Exception {

        PSSParameterSpec originalSpec = new PSSParameterSpec(
            "SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1
        );

        /* Round trip 1: spec -> params -> encoded */
        AlgorithmParameters params1 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params1.init(originalSpec);
        byte[] encoded1 = params1.getEncoded();

        /* Round trip 2: encoded -> params -> encoded */
        AlgorithmParameters params2 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params2.init(encoded1);
        byte[] encoded2 = params2.getEncoded();

        /* Round trip 3: encoded -> params -> spec */
        AlgorithmParameters params3 =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params3.init(encoded2);
        PSSParameterSpec finalSpec =
            params3.getParameterSpec(PSSParameterSpec.class);

        /* Verify all parameters match original */
        assertEquals(originalSpec.getDigestAlgorithm(),
            finalSpec.getDigestAlgorithm());
        assertEquals(originalSpec.getMGFAlgorithm(),
            finalSpec.getMGFAlgorithm());
        assertEquals(originalSpec.getSaltLength(),
            finalSpec.getSaltLength());
        assertEquals(originalSpec.getTrailerField(),
            finalSpec.getTrailerField());

        /* Verify encodings are identical */
        assertTrue(Arrays.equals(encoded1, encoded2));
    }

    @Test
    public void testRSAPSSParametersInitWithInvalidParameterSpec()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        /* Try to initialize with wrong type of ParameterSpec */
        try {
            DHParameterSpec invalidSpec =
                new DHParameterSpec(
                    BigInteger.valueOf(123), BigInteger.valueOf(2));
            params.init(invalidSpec);

            fail("AlgorithmParameters.init should throw " +
                 "InvalidParameterSpecException when given wrong spec type");

        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersInitWithNullBytes()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        try {
            params.init((byte[]) null);
            fail("Should throw IOException for null parameters");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersInitWithEmptyBytes()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        try {
            params.init(new byte[0]);
            fail("Should throw IOException for empty parameters");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersInitWithInvalidDERBytes()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        /* Invalid DER: not a SEQUENCE */
        byte[] invalidDER = new byte[] {0x02, 0x01, 0x00};

        try {
            params.init(invalidDER);
            fail("Should throw IOException for invalid DER encoding");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersInitWithTruncatedDER()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        /* SEQUENCE with length > actual data */
        byte[] truncatedDER = new byte[] {0x30, 0x10, 0x00};

        try {
            params.init(truncatedDER);
            fail("Should throw IOException for truncated DER encoding");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersGetEncodedBeforeInit()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        try {
            params.getEncoded();
            fail("Should throw IOException when getEncoded " +
                 "called before init");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersGetParameterSpecBeforeInit()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        try {
            params.getParameterSpec(PSSParameterSpec.class);
            fail("Should throw InvalidParameterSpecException " +
                 "when called before init");
        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersGetParameterSpecWithWrongClass()
        throws Exception {

        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        try {
            params.getParameterSpec(DHParameterSpec.class);
            fail("Should throw InvalidParameterSpecException for wrong class");
        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersGetParameterSpecWithNull()
        throws Exception {

        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        try {
            params.getParameterSpec(null);
            fail("Should throw InvalidParameterSpecException for null class");
        } catch (InvalidParameterSpecException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersToString()
        throws Exception {

        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        String str = params.toString();
        assertNotNull(str);
        assertTrue(str.contains("PSS Parameters"));
        assertTrue(str.contains("SHA-256"));
    }

    @Test
    public void testRSAPSSParametersEncodingWithFormat()
        throws Exception {

        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        /* Test ASN.1 format */
        byte[] asnEncoded = params.getEncoded("ASN.1");
        assertNotNull(asnEncoded);

        /* ASN.1 and default should be the same */
        byte[] defaultEncoded = params.getEncoded();
        assertTrue(Arrays.equals(asnEncoded, defaultEncoded));

        /* Test case insensitivity */
        byte[] lowerEncoded = params.getEncoded("asn.1");
        assertTrue(Arrays.equals(asnEncoded, lowerEncoded));
    }

    @Test
    public void testRSAPSSParametersEncodingUnsupportedFormat()
        throws Exception {

        PSSParameterSpec spec = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");
        params.init(spec);

        try {
            params.getEncoded("PEM");
            fail("Should throw IOException for unsupported format");
        } catch (IOException e) {
            /* expected */
        }
    }

    @Test
    public void testRSAPSSParametersInitWithUnsupportedFormat()
        throws Exception {

        AlgorithmParameters params =
            AlgorithmParameters.getInstance("RSASSA-PSS", "wolfJCE");

        byte[] data = new byte[] {0x30, 0x00};

        try {
            params.init(data, "PEM");
            fail("Should throw IOException for unsupported format");
        } catch (IOException e) {
            /* expected */
        }
    }
}

