/* WolfCryptXmssSignatureTest.java
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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * wolfJCE tests for the XMSS/XMSS^MT Signature service (verify-only), via the
 * JCE API.
 *
 * <p>Exercises raw XMSS public key to RFC 9802 SPKI to
 * KeyFactory.generatePublic() to Signature.verify(). The vector is the
 * XMSS-SHA2_10_256 public key, message, and signature from the xmss-reference
 * implementation.</p>
 */
public class WolfCryptXmssSignatureTest {

    private static boolean xmssEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptXmssSignatureTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        xmssEnabled = FeatureDetect.XmssEnabled();
    }

    private void assumeEnabled() {
        Assume.assumeTrue("XMSS not compiled in", xmssEnabled);
    }

    private static boolean verify(PublicKey pub, byte[] sig, byte[] msg)
        throws Exception {

        Signature s = Signature.getInstance("XMSS", "wolfJCE");
        s.initVerify(pub);
        s.update(msg);

        return s.verify(sig);
    }

    /* XMSS-SHA2_10_256 (xmss-reference) raw public key, message, signature. */
    private static final byte[] XMSS_SHA2_10_256_PK = Util.h2b(
        "00000001a54131960af9f3b24b2e5b3eca74ad6ca589ad2c0e96b354fb5b6350" +
        "9681e25972100954bb39acee78ef95ec011df03668e2c4a52f60427ed38eaa27" +
        "c9b7394e");

    private static final byte[] XMSS_SHA2_10_256_MSG = Util.h2b(
        "079f8086db7627dfed5b2a8160607db4e87a6945206ba296c021a54629639b37");

    private static final byte[] XMSS_SHA2_10_256_SIG = Util.h2b(
        "00000005f01534ba92036ab9a5238611ae650a5c782cc9be7ea6dca28ba99c50" +
        "f6618d9dd7e9c0f867cd8ac49b7496075df2c9cc2805b1be5ea4babeabd8216b" +
        "215fabb76cec2fc8c6743e971bc34557afaa1ea8f286a8aa436d66e98114de09" +
        "39d2afd14ce775180daa29a19253cce9f30b1e3be2ae800ce77a7c138a28c65f" +
        "0aa4a3730a3ac2a63bb43067c03618a158cdad543664cefd52ff707e09fb13a2" +
        "eadf678d6c42b278f57d5c4bf78ecf3eb7c6c123fa65ded2fa4051970d523276" +
        "7e828dd0b91e62d91ec1db4043374a238a1d35faf453115ab56d1e8b22c87d2a" +
        "e494aa25204096db8262ba8f8b45cb4f358833ebefb3baa70972b34cecf2c3c7" +
        "5e026c4193cb3c89120968548eec6a7e20e1703d8cebb436be91be97b5a63416" +
        "950f1026a91380889caa68ec34704a159b5e5705871cf8354529e96ef2701342" +
        "894e77c018c7556de7fa0d63831619012dfd311494ca3e0ed61134815758ec24" +
        "a41763d32500bf7d785dc5d8c6c1bd8cd0940ab133a54b3125f5afe78426aa05" +
        "bbf39aaf583640ef3da2bdcaa18d2f6d54d2623309aee673d644e87c5c392b78" +
        "9414c7c9afec7736a16161f1d009a2eee755d73589899bcffaa6091e3bbd5dd9" +
        "25e7eddd7cf01c57e006bb083959dfd7af4b880d878f4af31cd44bb3e2f31b86" +
        "4fcd3575e203f91dbf3ed17bc72311755f920d98ee14e1da7a0217476b41ea47" +
        "a1af06791a526f19317071bdc2618db7ee6b692ae8217a95be862aa1f4e22f17" +
        "02fdad179f0a0a78a9923021722b28f8f23e05d5acc082f8d2dad0a3bc93dba5" +
        "46de141ed43a5d793d314b06ce22293c98b6188aaef7ba2288a1eec0144c4aa0" +
        "570ad318a23dddc78373fc389b31a3e11776a1a269fcab0880728df5e414b76b" +
        "03ffe8114b06557e36212fd75482c931b4856841ef75b03aea4fe0ec72cc3396" +
        "ce7daddd0d27056ea2d41107d87d27d4808f0022e4fc2c9dd5d8187f4ef4b97f" +
        "efd600085c05041e9ac68dcc19d90b06cc6a17e20323db1cbca2b9a2953c73d8" +
        "ffe60eae04b2fc914fef8a58b731684c1ed05b85cc03dcf4acdb039b35330871" +
        "d0508ddce33a98404180dd35e1a2af149adbd36814e2507a763fe4a41baac106" +
        "879a92f9be9e868c921d74b17f2743c0ee2ec26c6daa0c0e71c956d63a56cb90" +
        "d17e6e1c6a002d022c96f02a373718070bf4b48c30f2a4ab66fb8b22c0007e05" +
        "b6f9954933a1dc970c5c6146e2d7874bc4c75f260684d74705f133ff8585b2bd" +
        "1f44c6c27d51be0eb5c4442ffe735ff4a4efe2f1730bef3e2bd7cc9fda1a7e92" +
        "39a155bf600adb2374fee70563a985529fccc3fff66c1b4e4f01bdc3eb37ec29" +
        "213b2cc92e93203e19c08be833cdc66a6e721315a190200c1466edcca4dd7f58" +
        "53bc4a68fc863eaaf1170f3e205493f498bfb40705bd70e7d734fde369dfcdf5" +
        "1a736ec92b21fbb87e44108356ced5159a75fc918e6b9e1a3a333935b40d74f4" +
        "fb4c0e37fe8295466bd26eeecd4d38af0aaaf1d5a47c04d8b9db1168883541de" +
        "31330cdc2d4ca820cc2c4c63abbadf4884d525bc70e349aa43ca8be79fdd2076" +
        "9b38f4ba4d4e344aaf81e70bece959c135227f694662d2186e1f79d1adc38495" +
        "96b218585e7e0c250a0f69a31dec29cbdaa2d11a10a552c3621ec583ffa356c2" +
        "fd873b5752983695776be549108e39ddca4bb39f4c0c1162f32278db48eb68fe" +
        "e42ae9aa8f7a2f69a5c5032def62a87165064084100ff2edbc70716924a2bf83" +
        "39ddfaa27be5ec3dfe3b526e3d82a62a8601615163bff90a0672f1d5390cbac9" +
        "78c67722e4966eb1486284622dea495650863f90c3014245ede69a6519937f48" +
        "16f250a770b3f5db0e5e229e64042669c116ee6508822765ec3ddf515e2de876" +
        "f2e3e4240488060fb27b9b723d4c7d6a1fb2a2d235d64025c20b25f9df26e4dc" +
        "fbb18484771b455160d5f0b609e6bce31c70962cd39d7d7fb170da79b87499bf" +
        "8495cc93d751dd66d3700c75860906fd661480cdf359b4925fe4ee00a8b08b5c" +
        "3edb8a9c0bb599c20d8109066c28c07ea5077064d741f4c366611ca851f63cba" +
        "e094a3118c2eba13b2474893b41a2c9a6e8e30667bd3bb3b5d970de4ea24289e" +
        "b488ce1d7d6f39b38721e50893f0d49d2d91c9fd0c7434b41ffedadc105b8d2b" +
        "87d342b4ae329cae4c99d8ed444107e08fbda57c5adf912900b54bc33a406c48" +
        "ab2af302cbb369da060c4d5c45c328ac7a01d4f8cb076389093478a71439cf2d" +
        "948d7a4e4ebdc432ab21c9da3f5f046b144018182ff9461757549b287bbdf9a2" +
        "13ac6924b13139bf8d75c3fd03545afdd47ab7564f6643571bfbf9927a83e6ff" +
        "b4ba83d2618e4a8282a8f50cd24353a8850ad4697b04713b8049274712b6b0ea" +
        "900afaa8c87861de3012bbdca65756306ef1a83bf60907ea31e20823310fd434" +
        "e360c22bdb5a99cfd46b4e756535e88b937dca1147f03e115cd1ee4b11b4652b" +
        "6b79c08660a44b24a05c7034c37ce74f97894dfe22893ae907b91a86b87a1238" +
        "e12446bc9b21cdac30ab982131c5173f1e56c318cef0a1ccff9da853af747754" +
        "029a8fa4d4bdb21aba522e19be49114502017abf28d618edbdcee4deb5f1535d" +
        "65f95f838f2df282a02d28d30a9e0f7fc7c4437fc30e06eb4eb42dfadd48abf4" +
        "7d4148335ae67002e7718dd96b0c5a8fa4c1b74e9683d6a71df188b36ef412a9" +
        "f6316966fefe02f2866dbb57518c4ce97c923e3ad32da88253842689bbcc1312" +
        "3d94bbdf3d4cdf279b1fb8b6e4eaa207f84d428f2990fe2120e95502ad90a777" +
        "4e29b6d91494b225a4b20e9631ab9e9349aca9cb6822bab8575c9d65c1f1fc99" +
        "7c3ce9ea4b29222fdb17218db013bfee7de48b6d17e053920b326bb1652ea783" +
        "fd6262e3aa81e8d6f7b13065809f771e4aeae84532123afb22e9a9f6cbaba80c" +
        "20a87cf9f753c1b4c05d0645dd7ea734a121c262ab22453d734c26d11ab2f0b2" +
        "6d117058aaf5a4f5f80b3dc1f6177015cd72027e4e94960a56cca5a3b37edd5a" +
        "72d2fbac3d0e6665e9086cb01ce21a82f6f3348973025b426d4061b6e0e65332" +
        "a572174f3b514fbc00e06926a9ae83e3737f7197e0dc7c639c855fdf7de46cd8" +
        "a93a6f5e4a2eb0e78b45e2900537e8ab49484cc0591d8c465b84e083ceea4bf9" +
        "d4dc63df79b75c11257f902e0a3803eaeaa126522019a3befc9db76ea6588e6d" +
        "c558e9ed2f55438b038be6a4c2254b36bad32748402e87a2d412c60536031151" +
        "d1f2ac712cb6c3a5570faf4bbdcd474c3a526f47e70bb7d5f7a6396382084c41" +
        "0e2a52425aea59c794fbd0884727f697039e29b83a67e6f395a742c196d19aa6" +
        "f0090ceae0ab0f15e9c3eba58986983283ab3033ae908d2eb3aa91a6d9a44a54" +
        "e0d308cc79cee41531a6ce61cf0306ee8ee26429d1549bd05f092b8bd5f8d47d" +
        "f19732d9ea5a0e108c4dfb55e6270cbac173c173e31c09b36fb412faf329dc23" +
        "32ed808783c2f607b5a922de661aa74a86f1399bf4e750154a553c93b9f9fddc" +
        "b35d7352");

    /* id-alg-xmss-hashsig 1.3.6.1.5.5.7.6.34 as a DER OID TLV (RFC 9802). */
    private static final byte[] XMSS_OID = new byte[] {
        (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01,
        (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x06, (byte) 0x22
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

    /* Wrap a raw XMSS public key as an RFC 9802 SPKI. */
    private static byte[] spki(byte[] rawPub) {

        byte[] algId = tlv(0x30, XMSS_OID);
        byte[] bitString = tlv(0x03, concat(new byte[] { 0x00 }, rawPub));

        return tlv(0x30, concat(algId, bitString));
    }

    private PublicKey publicKey() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("XMSS", "wolfJCE");
        return kf.generatePublic(
            new X509EncodedKeySpec(spki(XMSS_SHA2_10_256_PK)));
    }

    @Test
    public void aliasesResolve() throws Exception {
        assumeEnabled();

        /* Verification available under both family names and RFC 9802 OIDs */
        Signature.getInstance("XMSS", "wolfJCE");
        Signature.getInstance("XMSSMT", "wolfJCE");
        Signature.getInstance("1.3.6.1.5.5.7.6.34", "wolfJCE");
        Signature.getInstance("1.3.6.1.5.5.7.6.35", "wolfJCE");
    }

    @Test
    public void xmssReferenceVectorJceVerify() throws Exception {
        assumeEnabled();

        PublicKey pub = publicKey();
        assertEquals("XMSS", pub.getAlgorithm());

        assertTrue("xmss-reference vector verify",
            verify(pub, XMSS_SHA2_10_256_SIG, XMSS_SHA2_10_256_MSG));

        assertFalse("wrong message must not verify",
            verify(pub, XMSS_SHA2_10_256_SIG, "not the message".getBytes()));

        byte[] tampered = XMSS_SHA2_10_256_SIG.clone();
        tampered[tampered.length / 2] ^= (byte) 0xFF;
        assertFalse("tampered signature must not verify",
            verify(pub, tampered, XMSS_SHA2_10_256_MSG));
    }

    @Test
    public void initSignRejected() throws Exception {
        assumeEnabled();

        /* Signing is not supported (verify-only). Use a non-null dummy
         * PrivateKey so the rejection comes from the provider's engineInitSign
         * rather than a framework null-check. */
        PrivateKey dummy = new PrivateKey() {
            public String getAlgorithm() {
                return "XMSS";
            }
            public String getFormat() {
                return "PKCS#8";
            }
            public byte[] getEncoded() {
                return new byte[] { 0 };
            }
        };

        Signature s = Signature.getInstance("XMSS", "wolfJCE");
        try {
            s.initSign(dummy);
            fail("expected XMSS signing to be unsupported");
        } catch (InvalidKeyException e) {
            /* expected: verify-only provider */
        }
    }
}
