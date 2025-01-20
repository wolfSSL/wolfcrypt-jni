/* RsaFipsTest.java
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

package com.wolfssl.wolfcrypt.test.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.Util;

public class RsaFipsTest extends FipsTest {
    private ByteBuffer privKey = ByteBuffer.allocateDirect(2048);
    private ByteBuffer cipher = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);
    private ByteBuffer plain = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_1024_BITS);
    private ByteBuffer n = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);
    private ByteBuffer e = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);
    private ByteBuffer message = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_1024_BITS);
    private ByteBuffer signature = ByteBuffer
            .allocateDirect(WolfCrypt.SIZE_OF_2048_BITS);
    private ByteBuffer hash = ByteBuffer.allocateDirect(Sha256.DIGEST_SIZE);
    private ByteBuffer encoded = ByteBuffer
            .allocateDirect(Asn.MAX_ENCODED_SIG_SIZE);
    private ByteBuffer result = ByteBuffer
            .allocateDirect(Asn.MAX_ENCODED_SIG_SIZE);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI FIPS RSA Tests");
    }

    @Test
    public void initShouldReturnZero() {
        Rsa key = new Rsa();

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(key, null));
        assertEquals(WolfCrypt.SUCCESS, Fips.FreeRsaKey_fips(key));
    }

    @Test
    public void VerifyShouldMatchUsingByteBuffer() {
        String[] messages = new String[] {
                "e6fd961dc2977a9c08be5c31d8de89450945a53d79299ea2a1ed" +
                "de7f6da0c50b4ac75688805c306bc216c0bd03ebb6c18cd4b5d7" +
                "4cd04fa06f2b3063320099b0f5fd11439166572aed5c9a2bcc60" +
                "ec60e913f524463fe433c11bab0ce8cb6c9a0e272e149fbdd522" +
                "b0195141da441568498acbec108046a1bf46b842380a2512",

                "e9ebe4ea39974ea1730cc4072d5c9d649facf7adfa3baca8fba1" +
                "8251bf55a27dd9724cbda2bbc885d0dca08d4af30c783b4eaeb4" +
                "65767fa1b96d0af52435d85fab912b6aba10efa5b946ed01e15d" +
                "427a4ecd0ff9556773791798b66956ecc75288d1e9ba2a9ea948" +
                "57d3132999a225b1ffaf844670156e7a3ea9f077fe8259a0",

                "b486fb4b03d8912cb4019db651ba040612a6f26b9932296cdfc1" +
                "990c6f06314cd2b0f6f24a4d5289c368aea906f5437830f02c71" +
                "6240c064bbe120be83420c0ba9ecfbb970656a1f655474be94e5" +
                "a3c6fb6f06dc3f55831a9e2a6f5725185ca923823229dde882f6" +
                "830b167d6352cdf75d6da63297381a9572e2af5fbc4eca2f", };

        Rng rng  = new Rng();
        Rsa priv = new Rsa();

        byte[] n_out = new byte[256];
        byte[] e_out = new byte[3];
        long[] n_len = new long[1];
        long[] e_len = new long[1];
        n_len[0] = n_out.length;
        e_len[0] = e_out.length;

        priv.decodePrivateKey(Util
            .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
               + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
               + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
               + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
               + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
               + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
               + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
               + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
               + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
               + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
               + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
               + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
               + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
               + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
               + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
               + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
               + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
               + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
               + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
               + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
               + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
               + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
               + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
               + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
               + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
               + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
               + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
               + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
               + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
               + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
               + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
               + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
               + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
               + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
               + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
               + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
               + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
               + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
               + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
               + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
               + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
               + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
               + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
               + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
               + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
               + "abca5ce7935334a1455d1339654246a19fcdf5bf"));

        priv.exportRawPublicKey(n_out, n_len, e_out, e_len);
        priv.setRng(rng);

        Rsa pub = new Rsa();
        pub.decodeRawPublicKey(n_out, e_out);

        for (int i = 0; i < messages.length; i++) {

            /* build encoded hash */
            message.put(Util.h2b(messages[i])).rewind();
            Sha256 sha = new Sha256();

            assertEquals(WolfCrypt.SUCCESS, Fips.InitSha256_fips(sha));
            assertEquals(WolfCrypt.SUCCESS,
                Fips.Sha256Update_fips(sha, message, message.limit()));
            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Final_fips(sha, hash));

            encoded.limit(Asn.MAX_ENCODED_SIG_SIZE);

            Asn.encodeSignature(encoded, hash, Sha256.DIGEST_SIZE,
                Asn.getCTC_HashOID(Sha256.TYPE));

            /* sign encoded message */
            assertEquals(signature.limit(), Fips.RsaSSL_Sign_fips(encoded,
                encoded.limit(), signature, signature.limit(),
                priv, rng));

            /* verify message */
            result.limit(Asn.MAX_ENCODED_SIG_SIZE);

            assertEquals(encoded.limit(), Fips.RsaSSL_Verify_fips(signature,
                signature.limit(), result, result.limit(), pub));

            result.limit(encoded.limit());

            assertEquals(encoded, result);
        }
    }

    @Test
    public void VerifyShouldMatchUsingByteArray() {
        String[] messages = new String[] {
                "e6fd961dc2977a9c08be5c31d8de89450945a53d79299ea2a1ed" +
                "de7f6da0c50b4ac75688805c306bc216c0bd03ebb6c18cd4b5d7" +
                "4cd04fa06f2b3063320099b0f5fd11439166572aed5c9a2bcc60" +
                "ec60e913f524463fe433c11bab0ce8cb6c9a0e272e149fbdd522" +
                "b0195141da441568498acbec108046a1bf46b842380a2512",

                "e9ebe4ea39974ea1730cc4072d5c9d649facf7adfa3baca8fba1" +
                "8251bf55a27dd9724cbda2bbc885d0dca08d4af30c783b4eaeb4" +
                "65767fa1b96d0af52435d85fab912b6aba10efa5b946ed01e15d" +
                "427a4ecd0ff9556773791798b66956ecc75288d1e9ba2a9ea948" +
                "57d3132999a225b1ffaf844670156e7a3ea9f077fe8259a0",

                "b486fb4b03d8912cb4019db651ba040612a6f26b9932296cdfc1" +
                "990c6f06314cd2b0f6f24a4d5289c368aea906f5437830f02c71" +
                "6240c064bbe120be83420c0ba9ecfbb970656a1f655474be94e5" +
                "a3c6fb6f06dc3f55831a9e2a6f5725185ca923823229dde882f6" +
                "830b167d6352cdf75d6da63297381a9572e2af5fbc4eca2f", };

        Rng rng  = new Rng();
        Rsa priv = new Rsa();

        byte[] n_out = new byte[WolfCrypt.SIZE_OF_2048_BITS];
        byte[] e_out = new byte[3];
        long[] n_len = new long[1];
        long[] e_len = new long[1];
        n_len[0] = n_out.length;
        e_len[0] = e_out.length;

        priv.decodePrivateKey(Util
            .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
               + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
               + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
               + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
               + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
               + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
               + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
               + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
               + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
               + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
               + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
               + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
               + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
               + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
               + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
               + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
               + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
               + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
               + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
               + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
               + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
               + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
               + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
               + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
               + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
               + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
               + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
               + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
               + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
               + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
               + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
               + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
               + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
               + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
               + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
               + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
               + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
               + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
               + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
               + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
               + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
               + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
               + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
               + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
               + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
               + "abca5ce7935334a1455d1339654246a19fcdf5bf"));

        priv.exportRawPublicKey(n_out, n_len, e_out, e_len);
        priv.setRng(rng);

        Rsa pub = new Rsa();
        pub.decodeRawPublicKey(n_out, e_out);

        for (int i = 0; i < messages.length; i++) {

            byte[] message = Util.h2b(messages[i]);
            byte[] encoded = new byte[Asn.MAX_ENCODED_SIG_SIZE];
            byte[] hash = new byte[Sha256.DIGEST_SIZE];
            byte[] result = new byte[Asn.MAX_ENCODED_SIG_SIZE];
            byte[] sig = new byte[WolfCrypt.SIZE_OF_2048_BITS];

            /* build encoded hash */
            Sha256 sha = new Sha256();

            assertEquals(WolfCrypt.SUCCESS, Fips.InitSha256_fips(sha));
            assertEquals(WolfCrypt.SUCCESS,
                Fips.Sha256Update_fips(sha, message, message.length));
            assertEquals(WolfCrypt.SUCCESS, Fips.Sha256Final_fips(sha, hash));

            long encodedSz = Asn.encodeSignature(encoded, hash,
                Sha256.DIGEST_SIZE, Asn.getCTC_HashOID(Sha256.TYPE));

            /* sign encoded message digest */
            assertEquals(WolfCrypt.SIZE_OF_2048_BITS,
                Fips.RsaSSL_Sign_fips(encoded, encodedSz,
                    sig, sig.length, priv, rng));

            /* verify signature */
            assertEquals(encodedSz, Fips.RsaSSL_Verify_fips(sig,
                sig.length, result, result.length, pub));

            assertArrayEquals(encoded, result);
        }
    }

    @Test
    public void PrivateKeyDecodeUsingByteBuffer() {
        Rsa rsa = new Rsa();
        long[] idx = { 0 };

        privKey.put(Util.h2b("308204a40201000282010100c303d12bfe39a432453b53c8"
                + "842b2a7c749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed481"
                + "48fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e7b9b"
                + "03479abf65cc7f652469a6e814895be434f7c5b01493f5677b3a7a78e1"
                + "01565691a613428dd23c409c4cefd186df37511b0ca13bf5f1a34a35e4"
                + "e1ce96df1b7ebf4e97d010e8a8083081af200b4314c57467b432826f8d"
                + "86c28840993683ba1e40722217d752652473b0ceef19cdaeff786c7bc0"
                + "1203d44e720d506d3ba33ba3995e9dc8d90c85b3d98ad95426db6dfaac"
                + "bbff254cc4d179f471d386401813b063b5724e30c49784862d562fd715"
                + "f77fc0aef5fc5be5fba1bad302030100010282010100a2e6d85f107164"
                + "089e2e6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e0c9f6f"
                + "e5593f766f49b111c25a2e16290ddeb78edc40d5a2eee01ea1f4be97db"
                + "86639614cd9809602d30769c3ccde688ee4792790b5a00e25e5f117c7d"
                + "f908b72006892a5dfd00ab22e1f0b3bc24a95e260e1f002dfe219a535b"
                + "6dd32bab9482684336d8f62fc622fcb5415d0d3360eaa47d7ee84b5591"
                + "56d35c578f1f94172faadee99ea8f4cf8a4c8ea0e45673b2cf4f86c569"
                + "3cf324208b5c960cfa6b123b9a67c1dfc696b2a5d5920d9b0942682410"
                + "45d450e4173948d0358b946d11de8fca5902818100ea24a7f96933e971"
                + "dc527d8821282f49deba7216e9cc477a880d94578458163a81b03fa2cf"
                + "a66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38900014bb"
                + "b40f5894e72f6a7e1c4f4121d431591f4e8a1a8da7576c22d8e5f47e32"
                + "a610cb64a5550387a627058cc3d7b627b24dba30da478f54d33d8b848d"
                + "949858a502818100d5381bc38fc5930c470b6f3592c5b08d46c892188f"
                + "f5800af7efa1fe80b9b52abaca18b05da507d0938dd89c041cd4628ea6"
                + "268101ffce8a2a63343540aa6d80de89236a574d9e6ead934e56900b6d"
                + "9d738b0cae273dde4ef0aac56c78676c94529c37676c2defbbafdfa690"
                + "3cc447cf8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba"
                + "7ca2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e766c"
                + "5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f5ddee59e0a"
                + "ca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc16edd3760ce2ec7f"
                + "b269136b780e5a4664b45eb725a05a753a4befc73c3ef7fd26b820c499"
                + "0a9a73bec31902818100ba449314ac34193b5f9160acf7b4d681053651"
                + "533de865dcaf2edc613ec97db87f87f03b9b03822937ce724e11d5b1c1"
                + "0c07a099914a8d7fec79cff139b5e985ec62f7da7dbc644d223c0ef2d6"
                + "51f587d899c011205d0f29fd5be2aed91cd921566dfc84d05fed10151c"
                + "1821e7c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3c8627c"
                + "a8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e32da3750d1e4d"
                + "2134d557705c89bf72ec4a6e68d5cd1874334e8c3a458fe69640eb63f9"
                + "19863a51dd894bb0f3f99f5d289538be35abca5ce7935334a1455d1339"
                + "654246a19fcdf5bf"));

        privKey.limit(privKey.position());
        privKey.rewind();

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(rsa, null));

        assertEquals(
                WolfCrypt.SUCCESS,
                Fips.RsaPrivateKeyDecode_fips(privKey, idx, rsa,
                        privKey.remaining()));

        Fips.FreeRsaKey_fips(rsa);
    }

    @Test
    public void PrivateKeyDecodeUsingByteArray() {
        byte[] privKey = Util
                .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
                        + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
                        + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
                        + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
                        + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
                        + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
                        + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
                        + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
                        + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
                        + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
                        + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
                        + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                        + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
                        + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
                        + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
                        + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
                        + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
                        + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
                        + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
                        + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
                        + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
                        + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
                        + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
                        + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
                        + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
                        + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
                        + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
                        + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
                        + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
                        + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
                        + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
                        + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
                        + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
                        + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
                        + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
                        + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
                        + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
                        + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
                        + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
                        + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
                        + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                        + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
                        + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
                        + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
                        + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
                        + "abca5ce7935334a1455d1339654246a19fcdf5bf");
        Rsa rsa = new Rsa();
        long[] idx = { 0 };

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(rsa, null));

        assertEquals(WolfCrypt.SUCCESS, Fips.RsaPrivateKeyDecode_fips(privKey,
                idx, rsa, privKey.length));

        Fips.FreeRsaKey_fips(rsa);
    }

    @Test
    public void EncryptShouldMatchUsingByteBuffer() {
        Rsa rsa = new Rsa();
        Rng rng = new Rng();
        long[] idx = { 0 };

        privKey.put(Util.h2b("308204a40201000282010100c303d12bfe39a432453b53c8"
                + "842b2a7c749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed481"
                + "48fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e7b9b"
                + "03479abf65cc7f652469a6e814895be434f7c5b01493f5677b3a7a78e1"
                + "01565691a613428dd23c409c4cefd186df37511b0ca13bf5f1a34a35e4"
                + "e1ce96df1b7ebf4e97d010e8a8083081af200b4314c57467b432826f8d"
                + "86c28840993683ba1e40722217d752652473b0ceef19cdaeff786c7bc0"
                + "1203d44e720d506d3ba33ba3995e9dc8d90c85b3d98ad95426db6dfaac"
                + "bbff254cc4d179f471d386401813b063b5724e30c49784862d562fd715"
                + "f77fc0aef5fc5be5fba1bad302030100010282010100a2e6d85f107164"
                + "089e2e6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e0c9f6f"
                + "e5593f766f49b111c25a2e16290ddeb78edc40d5a2eee01ea1f4be97db"
                + "86639614cd9809602d30769c3ccde688ee4792790b5a00e25e5f117c7d"
                + "f908b72006892a5dfd00ab22e1f0b3bc24a95e260e1f002dfe219a535b"
                + "6dd32bab9482684336d8f62fc622fcb5415d0d3360eaa47d7ee84b5591"
                + "56d35c578f1f94172faadee99ea8f4cf8a4c8ea0e45673b2cf4f86c569"
                + "3cf324208b5c960cfa6b123b9a67c1dfc696b2a5d5920d9b0942682410"
                + "45d450e4173948d0358b946d11de8fca5902818100ea24a7f96933e971"
                + "dc527d8821282f49deba7216e9cc477a880d94578458163a81b03fa2cf"
                + "a66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38900014bb"
                + "b40f5894e72f6a7e1c4f4121d431591f4e8a1a8da7576c22d8e5f47e32"
                + "a610cb64a5550387a627058cc3d7b627b24dba30da478f54d33d8b848d"
                + "949858a502818100d5381bc38fc5930c470b6f3592c5b08d46c892188f"
                + "f5800af7efa1fe80b9b52abaca18b05da507d0938dd89c041cd4628ea6"
                + "268101ffce8a2a63343540aa6d80de89236a574d9e6ead934e56900b6d"
                + "9d738b0cae273dde4ef0aac56c78676c94529c37676c2defbbafdfa690"
                + "3cc447cf8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba"
                + "7ca2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e766c"
                + "5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f5ddee59e0a"
                + "ca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc16edd3760ce2ec7f"
                + "b269136b780e5a4664b45eb725a05a753a4befc73c3ef7fd26b820c499"
                + "0a9a73bec31902818100ba449314ac34193b5f9160acf7b4d681053651"
                + "533de865dcaf2edc613ec97db87f87f03b9b03822937ce724e11d5b1c1"
                + "0c07a099914a8d7fec79cff139b5e985ec62f7da7dbc644d223c0ef2d6"
                + "51f587d899c011205d0f29fd5be2aed91cd921566dfc84d05fed10151c"
                + "1821e7c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3c8627c"
                + "a8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e32da3750d1e4d"
                + "2134d557705c89bf72ec4a6e68d5cd1874334e8c3a458fe69640eb63f9"
                + "19863a51dd894bb0f3f99f5d289538be35abca5ce7935334a1455d1339"
                + "654246a19fcdf5bf"));

        privKey.limit(privKey.position());
        privKey.rewind();

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(rsa, null));
        assertEquals(
                WolfCrypt.SUCCESS,
                Fips.RsaPrivateKeyDecode_fips(privKey, idx, rsa,
                        privKey.remaining()));

        message.put(
                Util.h2b("54686520717569636b2062726f776e20666f78206a756d707320"
                        + "6f76657220746865206c617a7920646f67")).rewind();

        assertEquals(cipher.capacity(), Fips.RsaPublicEncrypt_fips(message,
                message.remaining(), cipher, cipher.capacity(), rsa, rng));

        assertEquals(message.remaining(), Fips.RsaPrivateDecrypt_fips(cipher,
                cipher.capacity(), plain, plain.capacity(), rsa));

        assertEquals(plain, message);

        Fips.FreeRsaKey_fips(rsa);
        Fips.FreeRng_fips(rng);
    }

    @Test
    public void EncryptShouldMatchUsingByteArray() {
        byte[] privKey = Util
                .h2b("308204a40201000282010100c303d12bfe39a432453b53c8842b2a7c"
                        + "749abdaa2a520747d6a636b207328ed0ba697bc6c3449ed48148"
                        + "fd2d68a28b67bba175c8362c4ad21bf78bbacf0df9efecf1811e"
                        + "7b9b03479abf65cc7f652469a6e814895be434f7c5b01493f567"
                        + "7b3a7a78e101565691a613428dd23c409c4cefd186df37511b0c"
                        + "a13bf5f1a34a35e4e1ce96df1b7ebf4e97d010e8a8083081af20"
                        + "0b4314c57467b432826f8d86c28840993683ba1e40722217d752"
                        + "652473b0ceef19cdaeff786c7bc01203d44e720d506d3ba33ba3"
                        + "995e9dc8d90c85b3d98ad95426db6dfaacbbff254cc4d179f471"
                        + "d386401813b063b5724e30c49784862d562fd715f77fc0aef5fc"
                        + "5be5fba1bad302030100010282010100a2e6d85f107164089e2e"
                        + "6dd16d1e85d20ab18c47ce2c516aa0129e53de914c1d6dea597b"
                        + "f277aad9c6d98aabd8e116e46326ffb56c1359b8e3a5c872172e"
                        + "0c9f6fe5593f766f49b111c25a2e16290ddeb78edc40d5a2eee0"
                        + "1ea1f4be97db86639614cd9809602d30769c3ccde688ee479279"
                        + "0b5a00e25e5f117c7df908b72006892a5dfd00ab22e1f0b3bc24"
                        + "a95e260e1f002dfe219a535b6dd32bab9482684336d8f62fc622"
                        + "fcb5415d0d3360eaa47d7ee84b559156d35c578f1f94172faade"
                        + "e99ea8f4cf8a4c8ea0e45673b2cf4f86c5693cf324208b5c960c"
                        + "fa6b123b9a67c1dfc696b2a5d5920d9b094268241045d450e417"
                        + "3948d0358b946d11de8fca5902818100ea24a7f96933e971dc52"
                        + "7d8821282f49deba7216e9cc477a880d94578458163a81b03fa2"
                        + "cfa66c1eb00629008fe77776acdbcac7d95e9b3f269052aefc38"
                        + "900014bbb40f5894e72f6a7e1c4f4121d431591f4e8a1a8da757"
                        + "6c22d8e5f47e32a610cb64a5550387a627058cc3d7b627b24dba"
                        + "30da478f54d33d8b848d949858a502818100d5381bc38fc5930c"
                        + "470b6f3592c5b08d46c892188ff5800af7efa1fe80b9b52abaca"
                        + "18b05da507d0938dd89c041cd4628ea6268101ffce8a2a633435"
                        + "40aa6d80de89236a574d9e6ead934e56900b6d9d738b0cae273d"
                        + "de4ef0aac56c78676c94529c37676c2defbbafdfa6903cc447cf"
                        + "8d969e98a9b49fc5a650dcb3f0fb74170281805e830962bdba7c"
                        + "a2bf4274f57c1cd269c9040d857e3e3d2412c3187bf329f35f0e"
                        + "766c5975e44184699d32f3cd22abb035ba4ab23ce5d958b6624f"
                        + "5ddee59e0aca53b22cf79eb36b0a5b7965ec6e914e9220f6fcfc"
                        + "16edd3760ce2ec7fb269136b780e5a4664b45eb725a05a753a4b"
                        + "efc73c3ef7fd26b820c4990a9a73bec31902818100ba449314ac"
                        + "34193b5f9160acf7b4d681053651533de865dcaf2edc613ec97d"
                        + "b87f87f03b9b03822937ce724e11d5b1c10c07a099914a8d7fec"
                        + "79cff139b5e985ec62f7da7dbc644d223c0ef2d651f587d899c0"
                        + "11205d0f29fd5be2aed91cd921566dfc84d05fed10151c1821e7"
                        + "c43d4bd7d09e6a95cf22c9037b9ee36001fc2f02818011d04bcf"
                        + "1b67b99f1075478665ae31c2c630ac590650d90fb57006f7f0d3"
                        + "c8627ca8da6ef6213fd37f5fea8aab3fd92a5ef351d2c23037e3"
                        + "2da3750d1e4d2134d557705c89bf72ec4a6e68d5cd1874334e8c"
                        + "3a458fe69640eb63f919863a51dd894bb0f3f99f5d289538be35"
                        + "abca5ce7935334a1455d1339654246a19fcdf5bf");
        Rsa rsa = new Rsa();
        Rng rng = new Rng();
        long[] idx = { 0 };

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.InitRsaKey_fips(rsa, null));
        assertEquals(WolfCrypt.SUCCESS, Fips.RsaPrivateKeyDecode_fips(privKey,
                idx, rsa, privKey.length));

        byte[] cipher = new byte[Fips.RsaEncryptSize_fips(rsa)];
        byte[] message = Util
                .h2b("54686520717569636b2062726f776e20666f78206a756d7073206f76"
                        + "657220746865206c617a7920646f67");
        byte[] plain = new byte[message.length];

        assertEquals(cipher.length, Fips.RsaPublicEncrypt_fips(message,
                message.length, cipher, cipher.length, rsa, rng));

        assertEquals(message.length, Fips.RsaPrivateDecrypt_fips(cipher,
                cipher.length, plain, plain.length, rsa));

        assertArrayEquals(plain, message);

        Fips.FreeRsaKey_fips(rsa);
        Fips.FreeRng_fips(rng);
    }
}
