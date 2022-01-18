/* WolfCryptError.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt;

import java.util.*;

/**
 * wolfCrypt error codes
 */
public enum WolfCryptError {

    /** No error found */
    NO_ERROR_FOUND      (-1),

    /* error codes match <wolfssl>/wolfssl/wolfcrypt/error-crypt.h */

    /** errors -101 - -299 */
    MAX_CODE_E          (-100),
    /** opening random device error */
    OPEN_RAN_E          (-101),
    /** reading random device error */
    READ_RAN_E          (-102),
    /** windows crypt init error */
    WINCRYPT_E          (-103),
    /** windows crypt generation error */
    CRYPTGEN_E          (-104),
    /** reading random device would block */
    RAN_BLOCK_E         (-105),
    /** Bad mutex operation */
    BAD_MUTEX_E         (-106),
    /** timeout error */
    WC_TIMEOUT_E        (-107),
    /** wolfCrypt operation pending (would block) */
    WC_PENDING_E        (-108),
    /** wolfCrypt operation not pending */
    WC_NOT_PENDING_E    (-109),

    /** mp_init error state */
    MP_INIT_E           (-110),
    /** mp_read error state */
    MP_READ_E           (-111),
    /** mp_exptmod error state */
    MP_EXPTMOD_E        (-112),
    /** mp_to_xxx error state, can't covert */
    MP_TO_E             (-113),
    /** mp_sub error state, can't subtract */
    MP_SUB_E            (-114),
    /** mp_add error state, can't add */
    MP_ADD_E            (-115),
    /** mp_mul error state, can't multiply */
    MP_MUL_E            (-116),
    /** mp_mulmod error state, can't multiply mod */
    MP_MULMOD_E         (-117),
    /** mp_mod error state, can't mod */
    MP_MOD_E            (-118),
    /** mp_invmod error state, can't inv mod */
    MP_INVMOD_E         (-119),
    /** mp_cmp error state */
    MP_CMP_E            (-120),
    /** got a mp zero result, not expected */
    MP_ZERO_E           (-121),

    /** out of memory error */
    MEMORY_E            (-125),
    /** var state modified by different thread */
    VAR_STATE_CHANGE_E  (-126),

    /** RSA wrong block type for RSA function */
    RSA_WRONG_TYPE_E    (-130),
    /** RSA buffer error, output too small or input too large */
    RSA_BUFFER_E        (-131),
    /** output buffer too small or input too large */
    BUFFER_E            (-132),
    /** setting algo id error */
    ALGO_ID_E           (-133),
    /** setting public key error */
    PUBLIC_KEY_E        (-134),
    /** setting date validity error */
    DATE_E              (-135),
    /** setting subject name error */
    SUBJECT_E           (-136),
    /** setting issuer name error */
    ISSUER_E            (-137),
    /** setting CA basic constraint true error */
    CA_TRUE_E           (-138),
    /** setting extensions error */
    EXTENSIONS_E        (-139),

    /** ASN parsing error, invalid input */
    ASN_PARSE_E         (-140),
    /** ASN version error, invalid number */
    ASN_VERSION_E       (-141),
    /** ASN get big int error, invalid data */
    ASN_GETINT_E        (-142),
    /** ASN key init error, invalid input */
    ASN_RSA_KEY_E       (-143),
    /** ASN object id error, invalid id */
    ASN_OBJECT_ID_E     (-144),
    /** ASN tag error, not null */
    ASN_TAG_NULL_E      (-145),
    /** ASN expect error, not zero */
    ASN_EXPECT_0_E      (-146),
    /** ASN bit string error, wrong id */
    ASN_BITSTR_E        (-147),
    /** ASN oid error, unknown sum id */
    ASN_UNKNOWN_OID_E   (-148),
    /** ASN date error, bad size */
    ASN_DATE_SZ_E       (-149),
    /** ASN date error, current date before */
    ASN_BEFORE_DATE_E   (-150),
    /** ASN date error, current date after */
    ASN_AFTER_DATE_E    (-151),
    /** ASN signature error, mismatched oid */
    ASN_SIG_OID_E       (-152),
    /** ASN time error, unknown time type */
    ASN_TIME_E          (-153),
    /** ASN input error, not enough data */
    ASN_INPUT_E         (-154),
    /** ASN sig error, confirm failure */
    ASN_SIG_CONFIRM_E   (-155),
    /** ASN sig error, unsupported hash type */
    ASN_SIG_HASH_E      (-156),
    /** ASN sig error, unsupported key type */
    ASN_SIG_KEY_E       (-157),
    /** ASN key init error, invalid input */
    ASN_DH_KEY_E        (-158),
    /** ASN ntru key decode error, invalid input */
    ASN_NTRU_KEY_E      (-159),
    /** ASN unsupported critical extension */
    ASN_CRIT_EXT_E      (-160),
    /** ASN alternate name error */
    ASN_ALT_NAME_E      (-161),
    /** ASN no PEM header found */
    ASN_NO_PEM_HEADER   (-162),

    /** ECC input argument of wrong type */
    ECC_BAD_ARG_E       (-170),
    /** ASN ECC bad input */
    ASN_ECC_KEY_E       (-171),
    /** Unsupported ECC OID curve type */
    ECC_CURVE_OID_E     (-172),
    /** Bad function argument provided */
    BAD_FUNC_ARG        (-173),
    /** Feature not compiled in */
    NOT_COMPILED_IN     (-174),
    /** Unicode password too big */
    UNICODE_SIZE_E      (-175),
    /** no password provided by user */
    NO_PASSWORD         (-176),
    /** alt name size problem, too big */
    ALT_NAME_E          (-177),
    /** missing key usage extension */
    BAD_OCSP_RESPONDER  (-178),

    /** AES-GCM Authentication check failure */
    AES_GCM_AUTH_E      (-180),
    /** AES-CCM Authentication check failure */
    AES_CCM_AUTH_E      (-181),

    /** Async Init type error */
    ASYNC_INIT_E        (-182),

    /** Compress init error */
    COMPRESS_INIT_E     (-183),
    /** Comrpess error */
    COMPRESS_E          (-184),
    /** DeCompress int error */
    DECOMPRESS_INIT_E   (-185),
    /** DeCompress error */
    DECOMPRESS_E        (-186),

    /** Bad alignment for operation, no alloc */
    BAD_ALIGN_E          (-187),
    /** ASN no signer to confirm failure */
    ASN_NO_SIGNER_E      (-188),
    /** ASN CRL signature confirm failure */
    ASN_CRL_CONFIRM_E    (-189),
    /** ASN CRL no signer to confirm failure */
    ASN_CRL_NO_SIGNER_E  (-190),
    /** ASN OCSP signature confirm failure */
    ASN_OCSP_CONFIRM_E   (-191),

    /** Bad state operation */
    BAD_STATE_E          (-192),
    /** Bad padding, msg not correct length */
    BAD_PADDING_E        (-193),

    /** setting cert request attributes error */
    REQ_ATTRIBUTE_E      (-194),

    /** PKCS#7, mismatched OID error */
    PKCS7_OID_E          (-195),
    /** PKCS#7, recipient error */
    PKCS7_RECIP_E        (-196),
    /** FIPS not allowed error */
    FIPS_NOT_ALLOWED_E   (-197),
    /** ASN name constraint error */
    ASN_NAME_INVALID_E   (-198),

    /** RNG Failed, Reinitialize */
    RNG_FAILURE_E        (-199),
    /** FIPS Mode HMAC Minimum Key Length error */
    HMAC_MIN_KEYLEN_E    (-200),
    /** RSA Padding Error */
    RSA_PAD_E            (-201),
    /** Returning output length only */
    LENGTH_ONLY_E        (-202),

    /** In Core Integrity check failure */
    IN_CORE_FIPS_E       (-203),
    /** AES KAT failure */
    AES_KAT_FIPS_E       (-204),
    /** DES3 KAT failure */
    DES3_KAT_FIPS_E      (-205),
    /** HMAC KAT failure */
    HMAC_KAT_FIPS_E      (-206),
    /** RSA KAT failure */
    RSA_KAT_FIPS_E       (-207),
    /** HASH DRBG KAT failure */
    DRBG_KAT_FIPS_E      (-208),
    /** HASH DRBG Continuous test failure */
    DRBG_CONT_FIPS_E     (-209),
    /** AESGCM KAT failure */
    AESGCM_KAT_FIPS_E    (-210),
    /** Thread local storage key create failure */
    THREAD_STORE_KEY_E   (-211),
    /** Thread local storage key set failure */
    THREAD_STORE_SET_E   (-212),

    /** MAC comparison failed */
    MAC_CMP_FAILED_E     (-213),
    /** ECC is point on curve failed */
    IS_POINT_E           (-214),
    /** ECC point infinity error */
    ECC_INF_E            (-215),
    /** ECC private key not valid error */
    ECC_PRIV_KEY_E       (-216),
    /** ECC key component out of range */
    ECC_OUT_OF_RANGE_E   (-217),

    /** SRP function called in the wrong order */
    SRP_CALL_ORDER_E     (-218),
    /** SRP proof verification failed */
    SRP_VERIFY_E         (-219),
    /** SRP bad ephemeral values */
    SRP_BAD_KEY_E        (-220),

    /** ASN no Subject Key Identifier found */
    ASN_NO_SKID          (-221),
    /** ASN no Authority Key Identifier found */
    ASN_NO_AKID          (-222),
    /** ASN no Key Usage found */
    ASN_NO_KEYUSAGE      (-223),
    /** setting Subject Key Identifier error */
    SKID_E               (-224),
    /** setting Authority Key Identifier error */
    AKID_E               (-225),
    /** Bad Key Usage value */
    KEYUSAGE_E           (-226),
    /** setting Certificate Policies error */
    CERTPOLICIES_E       (-227),

    /** wolfcrypt failed to initialize */
    WC_INIT_E            (-228),
    /** wolfcrypt signature verify error */
    SIG_VERIFY_E         (-229),
    /** Bad condition variable operation */
    BAD_COND_E           (-230),
    /** Signature Type not enabled/available */
    SIG_TYPE_E           (-231),
    /** Hash Type not enabled/available */
    HASH_TYPE_E          (-232),

    /** Key size error, either too small or large */
    WC_KEY_SIZE_E        (-234),
    /** ASN Cert Gen, invalid country code size */
    ASN_COUNTRY_SIZE_E   (-235),
    /** RNG required but not provided */
    MISSING_RNG_E        (-236),
    /** ASN CA path length too large error */
    ASN_PATHLEN_SIZE_E   (-237),
    /** ASN CA path length inversion error */
    ASN_PATHLEN_INV_E    (-238),

    /** Bad AES key wrap algorithm */
    BAD_KEYWRAP_ALG_E    (-239),
    /** Decrypted AES key wrap IV incorrect */
    BAD_KEYWRAP_IV_E     (-240),
    /** wolfcrypt cleanup failed */
    WC_CLEANUP_E         (-241),
    /** ECC CDH Known Answer Test failure */
    ECC_CDH_KAT_FIPS_E   (-242),
    /** DH Check Pub Key error */
    DH_CHECK_PUB_E       (-243),
    /** Bad path for opendir */
    BAD_PATH_ERROR       (-244),

    /** Async operation error */
    ASYNC_OP_E           (-245),

    /** Invalid use of private only ECC key */
    ECC_PRIVATEONLY_E    (-246),
    /** Bad Extended Key Usage value */
    EXTKEYUSAGE_E        (-247),
    /** Error with hardware crypto use */
    WC_HW_E              (-248),
    /** Hardware waiting on resource */
    WC_HW_WAIT_E         (-249),

    /** PSS length of salt is too long for hash */
    PSS_SALTLEN_E        (-250),
    /** Failure finding a prime */
    PRIME_GEN_E          (-251),
    /** Cannot decode indefinite length BER */
    BER_INDEF_E          (-252),
    /** Ciphertext to decrypt out of range */
    RSA_OUT_OF_RANGE_E   (-253),
    /** RSA-PSS PAT failure */
    RSAPSS_PAT_FIPS_E    (-254),
    /** ECDSA PAT failure */
    ECDSA_PAT_FIPS_E     (-255),
    /** DH KAT failure */
    DH_KAT_FIPS_E        (-256),

    /** Update this to indicate last error */
    WC_LAST_E            (-256),

    /** errors -101 - -299 */
    MIN_CODE_E           (-300);

    private final int code;

    private static final Map<Integer, WolfCryptError> intToErrMap =
        new HashMap<Integer, WolfCryptError>();

    static {
        for (WolfCryptError err : WolfCryptError.values()) {
            intToErrMap.put(err.code, err);
        }
    }

    private WolfCryptError(int code) {
        this.code = code;
    }

    /**
     * Get wolfCrypt error code
     *
     * @return current wolfCrypt error code
     */
    public int getCode() {
        return this.code;
    }

    /**
     * Get wolfCrypt description of current error
     *
     * @return String description of current error
     */
    public String getDescription() {
        if (this == WolfCryptError.NO_ERROR_FOUND)
            return "No error code found in JNI WolfCryptError enum";
        return wc_GetErrorString(this.code);
    }

    /**
     * Get WolfCryptError from error code int value
     *
     * @param code wolfCrypt error code
     *
     * @return WolfCryptError object matching error code
     */
    public static WolfCryptError fromInt(int code) {
        WolfCryptError err = intToErrMap.get(Integer.valueOf(code));

        if (err == null)
            return WolfCryptError.NO_ERROR_FOUND;

        return err;
    }

    private static native String wc_GetErrorString(int error);

    @Override
    public String toString() {
        return "(" + code + ") " + this.getDescription();
    }
}
