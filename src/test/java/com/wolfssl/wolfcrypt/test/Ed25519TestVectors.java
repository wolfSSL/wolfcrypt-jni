/* Ed25519TestVectors.java
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

/**
 * Ed25519 known-answer test vectors, copied from native wolfSSL
 * wolfcrypt/test/test.c: ed25519_kat_test(), ed25519ctx_test(),
 * ed25519ph_test() and ed25519_rare_sig_test().
 */
public final class Ed25519TestVectors {

    /* Utility class, not instantiable. */
    private Ed25519TestVectors() {
    }

    /* ed25519_kat_test(): RFC 8032 Section 7.1 vectors. Index n of the
     * SKEY/PKEY/SIG/MSG arrays is native loop index i:
     *
     *   [0] TEST 1    : empty message
     *   [1] TEST 2    : 1-byte message 0x72
     *   [2] TEST 3    : 2-byte message 0xaf82
     *   [3] TEST 1    : same key and signature as [0], public key in
     *                   65-byte uncompressed form (0x04 || x || y)
     *   [4] TEST 1    : same key and signature as [0], public key with a
     *                   0x40 prefix byte (33 bytes)
     *   [5] TEST 1024 : 1023-byte message
     *
     * The native KAT omits the "TEST SHA(abc)" vector. Native msg1 is a
     * one-byte placeholder always passed with length 0, so MSG1 is empty.
     */

    /* TEST 1 secret key */
    public static final byte[] SKEY1 = Util.h2b(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    /* TEST 2 secret key */
    public static final byte[] SKEY2 = Util.h2b(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

    /* TEST 3 secret key */
    public static final byte[] SKEY3 = Util.h2b(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");

    /* TEST 1 secret key again (uncompressed public key test) */
    public static final byte[] SKEY4 = Util.h2b(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    /* TEST 1 secret key again (compressed prefix test) */
    public static final byte[] SKEY5 = Util.h2b(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    /* TEST 1024 secret key */
    public static final byte[] SKEY6 = Util.h2b(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");

    /* TEST 1 public key */
    public static final byte[] PKEY1 = Util.h2b(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    /* TEST 2 public key */
    public static final byte[] PKEY2 = Util.h2b(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");

    /* TEST 3 public key */
    public static final byte[] PKEY3 = Util.h2b(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

    /* TEST 1 public key, 65-byte uncompressed (0x04 || x || y) */
    public static final byte[] PKEY4 = Util.h2b(
        "0455d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645" +
        "ce1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985a" +
        "d7");

    /* TEST 1 public key with 0x40 prefix byte, 33 bytes */
    public static final byte[] PKEY5 = Util.h2b(
        "40d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f70751" +
        "1a");

    /* TEST 1024 public key */
    public static final byte[] PKEY6 = Util.h2b(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");

    /* TEST 1 signature */
    public static final byte[] SIG1 = Util.h2b(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /* TEST 2 signature */
    public static final byte[] SIG2 = Util.h2b(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    /* TEST 3 signature */
    public static final byte[] SIG3 = Util.h2b(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

    /* TEST 1 signature again (uncompressed public key test) */
    public static final byte[] SIG4 = Util.h2b(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /* TEST 1 signature again (compressed prefix test) */
    public static final byte[] SIG5 = Util.h2b(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /* TEST 1024 signature */
    public static final byte[] SIG6 = Util.h2b(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");

    /* TEST 1 message, empty */
    public static final byte[] MSG1 = new byte[0];

    /* TEST 2 message, 1 byte */
    public static final byte[] MSG2 = Util.h2b(
        "72");

    /* TEST 3 message, 2 bytes */
    public static final byte[] MSG3 = Util.h2b(
        "af82");

    /* TEST 1024 message, 1023 bytes */
    public static final byte[] MSG4 = Util.h2b(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

    /* Indexed as native sKeys[] */
    public static final byte[][] SKEY = {
        SKEY1, SKEY2, SKEY3, SKEY4, SKEY5, SKEY6
    };

    /* Indexed as native pKeys[], lengths 32, 32, 32, 65, 33, 32 */
    public static final byte[][] PKEY = {
        PKEY1, PKEY2, PKEY3, PKEY4, PKEY5, PKEY6
    };

    /* Indexed as native sigs[] */
    public static final byte[][] SIG = {
        SIG1, SIG2, SIG3, SIG4, SIG5, SIG6
    };

    /* Indexed as native msgs[] with the msgSz[] lengths applied */
    public static final byte[][] MSG = {
        MSG1, MSG2, MSG3, MSG1, MSG1, MSG4
    };

    /* ed25519ctx_test(): RFC 8032 Section 7.2 Ed25519ctx vector.
     * CTX_SIG_FOO is the RFC signature with context "foo". CTX_SIG_EMPTY
     * is the wolfSSL-computed signature over the same message with an
     * empty context, which RFC 8032 does not publish.
     */

    /* Ed25519ctx secret key */
    public static final byte[] CTX_SKEY = Util.h2b(
        "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6");

    /* Ed25519ctx public key */
    public static final byte[] CTX_PKEY = Util.h2b(
        "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292");

    /* Ed25519ctx signature, context "foo" */
    public static final byte[] CTX_SIG_FOO = Util.h2b(
        "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a" +
        "8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d");

    /* Ed25519ctx signature, empty context (native sigCtx2) */
    public static final byte[] CTX_SIG_EMPTY = Util.h2b(
        "cc5e63a27e94afd3418338d2486fa92af9917c2d989e06e50277721c343818b4" +
        "2196bc292e68f34d859bbead179f54542d4b04dcfbfa4a684e3950fb1ccd8d0d");

    /* Ed25519ctx message, 16 bytes */
    public static final byte[] CTX_MSG = Util.h2b(
        "f726936d19c800494e3fdaff20b276a8");

    /* Ed25519ctx context "foo" */
    public static final byte[] CTX_CONTEXT = Util.h2b(
        "666f6f");

    /* ed25519ph_test(): RFC 8032 Section 7.3 Ed25519ph vector. PH_SIG is
     * the RFC signature over PH_MSG ("abc") with no context. PH_SIG_FOO is
     * the wolfSSL-computed signature with context "foo", which RFC 8032
     * does not publish. PH_HASH is SHA-512(PH_MSG) for the sign_hash and
     * verify_hash APIs.
     */

    /* Ed25519ph secret key */
    public static final byte[] PH_SKEY = Util.h2b(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");

    /* Ed25519ph public key */
    public static final byte[] PH_PKEY = Util.h2b(
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");

    /* Ed25519ph signature, no context (native sigPh1) */
    public static final byte[] PH_SIG = Util.h2b(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41" +
        "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");

    /* Ed25519ph signature, context "foo" (native sigPh2) */
    public static final byte[] PH_SIG_FOO = Util.h2b(
        "e039702b4c2595a6a541ac8509236e2990474795330c9b34a75f58a660129e08" +
        "fd736943fb1943a55720b9e0957b1ed6734816619f1388f43f73e6e3baa81c0e");

    /* Ed25519ph message "abc" */
    public static final byte[] PH_MSG = Util.h2b(
        "616263");

    /* SHA-512(PH_MSG), 64 bytes (native hashPh) */
    public static final byte[] PH_HASH = Util.h2b(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    /* Ed25519ph context "foo" (native contextPh2) */
    public static final byte[] PH_CONTEXT = Util.h2b(
        "666f6f");

    /* ed25519_rare_sig_test(): signature encoding edge cases. The key is
     * RFC 8032 Section 7.1 TEST 1 and the message is empty. Each RARE_SIGn
     * has an all-zero R half and an S half (little-endian, bytes 32..63)
     * chosen against the group order
     * L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed:
     *
     *   RARE_SIG1 : S == L                       -> BAD_FUNC_ARG
     *   RARE_SIG2 : S > L in the high part       -> BAD_FUNC_ARG
     *   RARE_SIG3 : S > L in the low part        -> BAD_FUNC_ARG
     *   RARE_SIG4 : S < L, not a valid signature -> SIG_VERIFY_E
     *
     * Those are the native codes, the Java verify API reports all four as
     * false.
     */

    /* TEST 1 public key (native pKey) */
    public static final byte[] RARE_PKEY = Util.h2b(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    /* Empty message */
    public static final byte[] RARE_MSG = new byte[0];

    /* S exactly equal to the order */
    public static final byte[] RARE_SIG1 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

    /* S larger than the order in the high part */
    public static final byte[] RARE_SIG2 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000010010");

    /* S larger than the order in the low part */
    public static final byte[] RARE_SIG3 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "edd3f55c1a631258d69cf9a2def9de1400000000000000000000000000000010");

    /* S smaller than the order */
    public static final byte[] RARE_SIG4 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "edd3f55c1a631258d69cf1a2def9de1400000000000000000000000000000010");

    /* In the order the native test verifies them */
    public static final byte[][] RARE_SIGS = {
        RARE_SIG1, RARE_SIG2, RARE_SIG3, RARE_SIG4
    };
}
