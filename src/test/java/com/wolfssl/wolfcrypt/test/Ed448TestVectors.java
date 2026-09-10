/* Ed448TestVectors.java
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
 * Ed448 known-answer test vectors, from native wolfSSL
 * wolfcrypt/test/test.c: ed448_kat_test(), ed448_ctx_test() and ed448ph_test().
 */
public final class Ed448TestVectors {

    /* Utility class, not instantiable. */
    private Ed448TestVectors() {
    }

    /* ed448_kat_test(): RFC 8032 Section 7.4 vectors. Index n of the
     * SKEY/PKEY/SIG/MSG arrays is native loop index i:
     *
     *   [0] "Blank"       : empty message
     *   [1] "1 octet"     : 1-byte message 0x03
     *   [2] "12 octets"   : 12-byte message
     *   [3] "Blank"       : plain repeat of [0] (native "uncompressed
     *                       test", Ed448 has no uncompressed form)
     *   [4] "Blank"       : key and signature of [0], public key with a
     *                       0x40 prefix byte (58 bytes)
     *   [5] "1023 octets" : 1023-byte message
     *
     * The native KAT omits the "1 octet (with context)" (see
     * ed448_ctx_test() below), "11 octets", "13 octets", "64 octets" and
     * "256 octets" vectors. Native msg1 is a one-byte placeholder always
     * passed with length 0, so MSG1 is empty.
     */

    /* "Blank" secret key */
    public static final byte[] SKEY1 = Util.h2b(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3" +
        "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");

    /* "1 octet" secret key */
    public static final byte[] SKEY2 = Util.h2b(
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a" +
        "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");

    /* "12 octets" secret key */
    public static final byte[] SKEY3 = Util.h2b(
        "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d93" +
        "9f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b");

    /* "Blank" secret key again (uncompressed test) */
    public static final byte[] SKEY4 = Util.h2b(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3" +
        "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");

    /* "Blank" secret key again (compressed prefix test) */
    public static final byte[] SKEY5 = Util.h2b(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3" +
        "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");

    /* "1023 octets" secret key */
    public static final byte[] SKEY6 = Util.h2b(
        "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec" +
        "44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8");

    /* "Blank" public key */
    public static final byte[] PKEY1 = Util.h2b(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778" +
        "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");

    /* "1 octet" public key */
    public static final byte[] PKEY2 = Util.h2b(
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086" +
        "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");

    /* "12 octets" public key */
    public static final byte[] PKEY3 = Util.h2b(
        "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc" +
        "24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580");

    /* "Blank" public key again (uncompressed test) */
    public static final byte[] PKEY4 = Util.h2b(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778" +
        "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");

    /* "Blank" public key with a 0x40 prefix byte, 58 bytes */
    public static final byte[] PKEY5 = Util.h2b(
        "405fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e967" +
        "78edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");

    /* "1023 octets" public key */
    public static final byte[] PKEY6 = Util.h2b(
        "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799d" +
        "a08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400");

    /* "Blank" signature */
    public static final byte[] SIG1 = Util.h2b(
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f" +
        "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a" +
        "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db" +
        "b61149f05a7363268c71d95808ff2e652600");

    /* "1 octet" signature */
    public static final byte[] SIG2 = Util.h2b(
        "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435" +
        "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb" +
        "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f" +
        "f3348ab21aa4adafd1d234441cf807c03a00");

    /* "12 octets" signature */
    public static final byte[] SIG3 = Util.h2b(
        "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4a" +
        "e90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457e" +
        "b1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861" +
        "e72003cbae6d6b8b827e4e6c143064ff3c00");

    /* "Blank" signature again (uncompressed test) */
    public static final byte[] SIG4 = Util.h2b(
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f" +
        "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a" +
        "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db" +
        "b61149f05a7363268c71d95808ff2e652600");

    /* "Blank" signature again (compressed prefix test) */
    public static final byte[] SIG5 = Util.h2b(
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f" +
        "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a" +
        "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db" +
        "b61149f05a7363268c71d95808ff2e652600");

    /* "1023 octets" signature */
    public static final byte[] SIG6 = Util.h2b(
        "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bd" +
        "df7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d" +
        "76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed57" +
        "3603ce30d8bb761785dc30dbc320869e1a00");

    /* "Blank" message, empty */
    public static final byte[] MSG1 = new byte[0];

    /* "1 octet" message */
    public static final byte[] MSG2 = Util.h2b(
        "03");

    /* "12 octets" message */
    public static final byte[] MSG3 = Util.h2b(
        "64a65f3cdedcdd66811e2915");

    /* "1023 octets" message */
    public static final byte[] MSG4 = Util.h2b(
        "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412" +
        "a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd" +
        "86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc" +
        "3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9" +
        "72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9" +
        "b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321" +
        "9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab79717" +
        "2b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813" +
        "a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0" +
        "596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520" +
        "96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1" +
        "526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998" +
        "d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee" +
        "85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6" +
        "155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4" +
        "c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9" +
        "77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f041" +
        "0a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456" +
        "f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab" +
        "0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3" +
        "120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535" +
        "aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf969614" +
        "9e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67" +
        "a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605" +
        "9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263" +
        "be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d" +
        "02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c" +
        "392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e" +
        "79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd" +
        "7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4" +
        "b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695" +
        "568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87");

    /* Indexed as native sKeys[] */
    public static final byte[][] SKEY = {
        SKEY1, SKEY2, SKEY3, SKEY4, SKEY5, SKEY6
    };

    /* Indexed as native pKeys[], lengths 57, 57, 57, 57, 58, 57 */
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

    /* ed448_ctx_test(): RFC 8032 Section 7.4 "1 octet (with context)".
     * CTX_SKEY and CTX_PKEY are the "1 octet" key pair (SKEY2 / PKEY2);
     * CTX_SIG_FOO is the RFC signature over CTX_MSG (0x03) with context
     * "foo".
     */

    /* "1 octet (with context)" secret key */
    public static final byte[] CTX_SKEY = Util.h2b(
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a" +
        "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");

    /* "1 octet (with context)" public key */
    public static final byte[] CTX_PKEY = Util.h2b(
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086" +
        "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");

    /* "1 octet (with context)" signature, context "foo" (native sigCtx) */
    public static final byte[] CTX_SIG_FOO = Util.h2b(
        "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2" +
        "151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da" +
        "1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d" +
        "5428407e85dcbc98a49155c13764e66c3c00");

    /* "1 octet (with context)" message */
    public static final byte[] CTX_MSG = Util.h2b(
        "03");

    /* Context "foo" */
    public static final byte[] CTX_CONTEXT = Util.h2b(
        "666f6f");

    /* ed448ph_test(): RFC 8032 Section 7.5 Ed448ph vectors. PH_SIG is
     * the RFC signature over PH_MSG ("abc") with no context, PH_SIG_FOO
     * the RFC signature with context "foo". PH_HASH is SHAKE256(PH_MSG)
     * with 64-byte output for the sign_hash and verify_hash APIs (the
     * native comment on hashPh says SHA-512, but the bytes are SHAKE256
     * as RFC 8032 Section 5.2 requires).
     */

    /* Ed448ph secret key */
    public static final byte[] PH_SKEY = Util.h2b(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42" +
        "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49");

    /* Ed448ph public key */
    public static final byte[] PH_PKEY = Util.h2b(
        "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743" +
        "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880");

    /* Ed448ph signature, no context (native sigPh1) */
    public static final byte[] PH_SIG = Util.h2b(
        "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae38" +
        "1f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd" +
        "433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3" +
        "ad203df7dc7ce360c3cd3696d9d9fab90f00");

    /* Ed448ph signature, context "foo" (native sigPh2) */
    public static final byte[] PH_SIG_FOO = Util.h2b(
        "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa48" +
        "1065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3" +
        "653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128" +
        "4f8d0704a608c54a6b62d97beb511d132100");

    /* Ed448ph message "abc" */
    public static final byte[] PH_MSG = Util.h2b(
        "616263");

    /* SHAKE256(PH_MSG), 64 bytes (native hashPh) */
    public static final byte[] PH_HASH = Util.h2b(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");

    /* Ed448ph context "foo" (native contextPh2) */
    public static final byte[] PH_CONTEXT = Util.h2b(
        "666f6f");

    /* Signature encoding edge cases, modelled on the Ed25519 rare_sig vectors.
     * The key is PKEY1 with the empty MSG1. Each RARE_SIGn has an all zero
     * R half and an S half (little-endian, bytes 57..113) chosen against the
     * group order L (RFC 8032 Section 5.2)
     *   L = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff
     *       7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3
     *
     *   RARE_SIG1 : S == L                         -> BAD_FUNC_ARG
     *   RARE_SIG2 : S > L in the high part         -> BAD_FUNC_ARG
     *   RARE_SIG3 : S > L in the low part          -> BAD_FUNC_ARG
     *   RARE_SIG4 : S == L - 1, not a valid signature -> SIG_VERIFY_E
     *
     * verify() returns false for all four, the top bit of the last byte
     * stays clear so none of them is caught by the sign-bit check. */
    public static final byte[] RARE_SIG1 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000f34458ab92c278" +
        "23558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffff3f00");

    public static final byte[] RARE_SIG2 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000f34458ab92c278" +
        "23558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffff7f00");

    public static final byte[] RARE_SIG3 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000f44458ab92c278" +
        "23558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffff3f00");

    public static final byte[] RARE_SIG4 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00000000000000000000000000000000000000000000000000f24458ab92c278" +
        "23558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffff" +
        "ffffffffffffffffffffffffffffffff3f00");

    public static final byte[][] RARE_SIGS = {
        RARE_SIG1, RARE_SIG2, RARE_SIG3, RARE_SIG4
    };
}
