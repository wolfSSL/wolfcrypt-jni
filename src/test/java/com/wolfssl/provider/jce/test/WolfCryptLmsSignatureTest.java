/* WolfCryptLmsSignatureTest.java
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * wolfJCE tests for the LMS/HSS Signature service (verify-only), via JCE API.
 */
public class WolfCryptLmsSignatureTest {

    private static boolean lmsEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptLmsSignatureTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        lmsEnabled = FeatureDetect.LmsEnabled();
    }

    private void assumeEnabled() {
        Assume.assumeTrue("LMS not compiled in", lmsEnabled);
    }

    private static boolean verify(PublicKey pub, byte[] sig, byte[] msg)
        throws Exception {

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        s.initVerify(pub);
        s.update(msg);

        return s.verify(sig);
    }

    @Test
    public void aliasesResolve() throws Exception {
        assumeEnabled();

        /* Verification is always available under both names + OID. */
        Signature.getInstance("LMS", "wolfJCE");
        Signature.getInstance("HSS/LMS", "wolfJCE");
        Signature.getInstance("1.2.840.113549.1.9.16.3.17", "wolfJCE");
    }

    /* RFC 8554 Appendix F Test Case 1 (HSS L2, SHA256 H5/W8).
     * Exercises raw HSS public key -> RFC 9708 SPKI ->
     * KeyFactory.generatePublic() -> Signature.verify(). The JNI-level RFC
     * 8554 / 9858 KAT matrix lives in com.wolfssl.wolfcrypt.test.LmsTest. */

    /* Short local alias of Util.h2b() to keep KAT declarations readable. */
    private static byte[] hex(String s) {
        return Util.h2b(s);
    }

    private static final byte[] RFC8554_TC1_PK = hex(
        "00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b" +
        "31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878");

    private static final byte[] RFC8554_TC1_MSG = hex(
        "54686520706f77657273206e6f742064656c65676174656420746f2074686520" +
        "556e69746564205374617465732062792074686520436f6e737469747574696f" +
        "6e2c206e6f722070726f6869626974656420627920697420746f207468652053" +
        "74617465732c2061726520726573657276656420746f20746865205374617465" +
        "7320726573706563746976656c792c206f7220746f207468652070656f706c65" +
        "2e0a");

    private static final byte[] RFC8554_TC1_SIG = hex(
        "000000010000000500000004d32b56671d7eb98833c49b433c272586bc4a1c8a" +
        "8970528ffa04b966f9426eb9965a25bfd37f196b9073f3d4a232feb69128ec45" +
        "146f86292f9dff9610a7bf95a64c7f60f6261a62043f86c70324b7707f5b4a8a" +
        "6e19c114c7be866d488778a0e05fd5c6509a6e61d559cf1a77a970de927d60c7" +
        "0d3de31a7fa0100994e162a2582e8ff1b10cd99d4e8e413ef469559f7d7ed12c" +
        "838342f9b9c96b83a4943d1681d84b15357ff48ca579f19f5e71f18466f2bbef" +
        "4bf660c2518eb20de2f66e3b14784269d7d876f5d35d3fbfc7039a462c716bb9" +
        "f6891a7f41ad133e9e1f6d9560b960e7777c52f060492f2d7c660e1471e07e72" +
        "655562035abc9a701b473ecbc3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f" +
        "428bab6f3a30f55dd9625563f0a75ee390e385e3ae0b906961ecf41ae073a059" +
        "0c2eb6204f44831c26dd768c35b167b28ce8dc988a3748255230cef99ebf14e7" +
        "30632f27414489808afab1d1e783ed04516de012498682212b07810579b25036" +
        "5941bcc98142da13609e9768aaf65de7620dabec29eb82a17fde35af15ad238c" +
        "73f81bdb8dec2fc0e7f932701099762b37f43c4a3c20010a3d72e2f606be108d" +
        "310e639f09ce7286800d9ef8a1a40281cc5a7ea98d2adc7c7400c2fe5a101552" +
        "df4e3cccfd0cbf2ddf5dc6779cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0" +
        "a750b73ccdcf3c79e6580c154f8a58f7f24335eec5c5eb5e0cf01dcf44394240" +
        "95fceb077f66ded5bec73b27c5b9f64a2a9af2f07c05e99e5cf80f00252e39db" +
        "32f6c19674f190c9fbc506d826857713afd2ca6bb85cd8c107347552f30575a5" +
        "417816ab4db3f603f2df56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fe" +
        "a1220403466b1afe78b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf" +
        "947f698ce9c6ceb696ed70e9e87b0144417e8d7baf25eb5f70f09f016fc925b4" +
        "db048ab8d8cb2a661ce3b57ada67571f5dd546fc22cb1f97e0ebd1a65926b123" +
        "4fd04f171cf469c76b884cf3115cce6f792cc84e36da58960c5f1d760f32c12f" +
        "aef477e94c92eb75625b6a371efc72d60ca5e908b3a7dd69fef0249150e3eebd" +
        "fed39cbdc3ce9704882a2072c75e13527b7a581a556168783dc1e97545e31865" +
        "ddc46b3c957835da252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023c" +
        "ef626e0af1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b73" +
        "00e882360a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f488431606cb1" +
        "3f9241f40f44e537d302c64a4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510" +
        "f150c85fb525bf25703df7209b6066f09c37280d59128d2f0f637c7d7d7fad4e" +
        "d1c1ea04e628d221e3d8db77b7c878c9411cafc5071a34a00f4cf07738912753" +
        "dfce48f07576f0d4f94f42c6d76f7ce973e9367095ba7e9a3649b7f461d9f9ac" +
        "1332a4d1044c96aefee67676401b64457c54d65fef6500c59cdfb69af7b6dddf" +
        "cb0f086278dd8ad0686078dfb0f3f79cd893d314168648499898fbc0ced5f95b" +
        "74e8ff14d735cdea968bee7400000005d8b8112f9200a5e50c4a262165bd342c" +
        "d800b8496810bc716277435ac376728d129ac6eda839a6f357b5a04387c5ce97" +
        "382a78f2a4372917eefcbf93f63bb59112f5dbe400bd49e4501e859f885bf073" +
        "6e90a509b30a26bfac8c17b5991c157eb5971115aa39efd8d564a6b90282c316" +
        "8af2d30ef89d51bf14654510a12b8a144cca1848cf7da59cc2b3d9d0692dd2a2" +
        "0ba3863480e25b1b85ee860c62bf51360000000500000004d2f14ff6346af964" +
        "569f7d6cb880a1b66c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15" +
        "cda93cfec582d7ab0000000a000000040703c491e7558b35011ece3592eaa5da" +
        "4d918786771233e8353bc4f62323185c95cae05b899e35dffd71705470620998" +
        "8ebfdf6e37960bb5c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b31" +
        "7587c6ba4bffcc428e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1" +
        "865a73caf96557eb39ed3e3f426933ac9eeddb03a1d2374af7bf771855774562" +
        "37f9de2d60113c23f846df26fa942008a698994c0827d90e86d43e0df7f4bfcd" +
        "b09b86a373b98288b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f" +
        "5ebe48f584d7159b8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff07" +
        "4f771760b26f9c04884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26c" +
        "e8aea2ce8a2990d7ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb" +
        "044beee4fac2603a442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8" +
        "690dbf59b28386b2315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201" +
        "043f65f5a3ef6bbd61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c" +
        "1c0a55e48a0e729f9184fcb1407c31529db268f6fe50032a363c9801306837fa" +
        "fabdf957fd97eafc80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3" +
        "ed95eea64c2d402f4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc6" +
        "57034f287ccb0f0e1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215" +
        "c812a0970789c83de51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5" +
        "a1c63b72c82653605d1dcce51596b3c2b45696689f2eb382007497557692caac" +
        "4d57b5de9f5569bc2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e" +
        "9f38182de994cff192ec0e82fd6d4cb7f3fe00812589b7a7ce51544045643301" +
        "6b84a59bec6619a1c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d217" +
        "6fc1cf2cc06fa8c82bed4d944e71339ece780fd025bd41ec34ebff9d4270a322" +
        "4e019fcb444474d482fd2dbe75efb20389cc10cd600abb54c47ede93e08c114e" +
        "db04117d714dc1d525e11bed8756192f929d15462b939ff3f52f2252da2ed64d" +
        "8fae88818b1efa2c7b08c8794fb1b214aa233db3162833141ea4383f1a6f120b" +
        "e1db82ce3630b3429114463157a64e91234d475e2f79cbf05e4db6a9407d72c6" +
        "bff7d1198b5c4d6aad2831db61274993715a0182c7dc8089e32c8531deed4f74" +
        "31c07c02195eba2ef91efb5613c37af7ae0c066babc69369700e1dd26eddc0d2" +
        "16c781d56e4ce47e3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888" +
        "395b2526391a724996a44156beac808212858792bf8e74cba49dee5e8812e019" +
        "da87454bff9e847ed83db07af313743082f880a278f682c2bd0ad6887cb59f65" +
        "2e155987d61bbf6a88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8" +
        "058dc9fb6f2ab3d3b3539eb77b248a661091d05eb6e2f297774fe6053598457c" +
        "c61908318de4b826f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43" +
        "a703ad9f5b5806163d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2" +
        "c6cef305b3ed633941ebc8b3bec9738754cddd60e1920ada52f43d055b5031ce" +
        "e6192520d6a5115514851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a96" +
        "9394843bdcf6d14c48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bf" +
        "d368e5e3ec9cb70ac7b8399003f175c40885081a09ab3034911fe125631051df" +
        "0408b3946b0bde790911e8978ba07dd56c73e7ee");

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
     * KeyFactory. That parameter family can be compiled out of wolfCrypt,
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

    /* True if the throwable's cause chain contains a wolfCrypt
     * NOT_COMPILED_IN error. */
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
    public void rfc8554TestCase1JceVerify() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);
        assertEquals("HSS/LMS", pub.getAlgorithm());

        assertTrue("RFC 8554 TC1 verify",
            verify(pub, RFC8554_TC1_SIG, RFC8554_TC1_MSG));
        assertFalse("RFC 8554 TC1 wrong message",
            verify(pub, RFC8554_TC1_SIG, "not the message".getBytes()));

        byte[] tampered = RFC8554_TC1_SIG.clone();
        tampered[tampered.length / 2] ^= (byte) 0xFF;
        assertFalse("RFC 8554 TC1 tampered signature",
            verify(pub, tampered, RFC8554_TC1_MSG));
    }

    @Test
    public void initSignRejected() throws Exception {
        assumeEnabled();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.initSign(stubPrivateKey());
            fail("expected LMS signing to be rejected (verify-only)");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void updateBeforeInitRejected() throws Exception {
        assumeEnabled();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.update(new byte[] { 0x00 });
            fail("expected update before init to be rejected");
        } catch (SignatureException e) {
            /* expected */
        }
    }

    @Test
    public void setParameterSpecRejected() throws Exception {
        assumeEnabled();

        AlgorithmParameterSpec spec = new AlgorithmParameterSpec() { };
        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.setParameter(spec);
            fail("expected AlgorithmParameterSpec to be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void setParameterStringRejected() throws Exception {
        assumeEnabled();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.setParameter("anything", "value");
            fail("expected string parameter to be rejected");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }

    @Test
    public void initVerifyRejectsMalformedKey() throws Exception {
        assumeEnabled();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.initVerify(stubPublicKey("X.509", new byte[] { 0x01, 0x02 }));
            fail("expected malformed public key to be rejected");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void destroyedKeyRejectedByInitVerify() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);
        ((javax.security.auth.Destroyable) pub).destroy();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.initVerify(pub);
            fail("expected destroyed key to be rejected");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void byteAtATimeUpdateMatchesArray() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        s.initVerify(pub);
        for (byte b : RFC8554_TC1_MSG) {
            s.update(b);
        }
        assertTrue("byte-at-a-time verify", s.verify(RFC8554_TC1_SIG));
    }

    @Test
    public void serializeRoundTripThenVerify() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("LMS", "wolfJCE");
        PublicKey pub = importTc1Key(kf);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(pub);
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(bos.toByteArray()));
        PublicKey restored = (PublicKey) ois.readObject();
        ois.close();

        assertArrayEquals(pub.getEncoded(), restored.getEncoded());
        assertTrue("verify after deserialize",
            verify(restored, RFC8554_TC1_SIG, RFC8554_TC1_MSG));
    }

    @Test
    @SuppressWarnings("deprecation")
    public void getParameterStringRejected() throws Exception {
        assumeEnabled();

        Signature s = Signature.getInstance("LMS", "wolfJCE");
        try {
            s.getParameter("anything");
            fail("expected getParameter(String) to be rejected");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }

    /* Minimal PublicKey with a chosen format and X.509 encoding. */
    private static PublicKey stubPublicKey(final String format,
        final byte[] encoded) {

        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "LMS";
            }
            @Override
            public String getFormat() {
                return format;
            }
            @Override
            public byte[] getEncoded() {
                return encoded.clone();
            }
        };
    }

    /* Minimal PrivateKey for exercising the signing-rejected path. */
    private static java.security.PrivateKey stubPrivateKey() {

        return new java.security.PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "LMS";
            }
            @Override
            public String getFormat() {
                return "PKCS#8";
            }
            @Override
            public byte[] getEncoded() {
                return new byte[] { 0x00 };
            }
        };
    }
}
