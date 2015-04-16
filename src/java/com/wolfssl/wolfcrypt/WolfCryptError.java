package com.wolfssl.wolfcrypt;

import java.util.*;

public enum WolfCryptError {

    NO_ERROR_FOUND      (-1),

    /* error codes match <wolfssl>/wolfssl/wolfcrypt/error-crypt.h */
    MAX_CODE_E          (-100),
    OPEN_RAN_E          (-101),
    READ_RAN_E          (-102),
    WINCRYPT_E          (-103),
    CRYPTGEN_E          (-104),
    RAN_BLOCK_E         (-105),
    BAD_MUTEX_E         (-106),

    MP_INIT_E           (-110),
    MP_READ_E           (-111),
    MP_EXPTMOD_E        (-112),
    MP_TO_E             (-113),
    MP_SUB_E            (-114),
    MP_ADD_E            (-115),
    MP_MUL_E            (-116),
    MP_MULMOD_E         (-117),
    MP_MOD_E            (-118),
    MP_INVMOD_E         (-119),
    MP_CMP_E            (-120),
    MP_ZERO_E           (-121),

    MEMORY_E            (-125),

    RSA_WRONG_TYPE_E    (-130),
    RSA_BUFFER_E        (-131),

    BUFFER_E            (-132),
    ALGO_ID_E           (-133),
    PUBLIC_KEY_E        (-134),
    DATE_E              (-135),
    SUBJECT_E           (-136),
    ISSUER_E            (-137),
    CA_TRUE_E           (-138),
    EXTENSIONS_E        (-139),

    ASN_PARSE_E         (-140),
    ASN_VERSION_E       (-141),
    ASN_GETINT_E        (-142),
    ASN_RSA_KEY_E       (-143),
    ASN_OBJECT_ID_E     (-144),
    ASN_TAG_NULL_E      (-145),
    ASN_EXPECT_0_E      (-146),
    ASN_BITSTR_E        (-147),
    ASN_UNKNOWN_OID_E   (-148),
    ASN_DATE_SZ_E       (-149),
    ASN_BEFORE_DATE_E   (-150),
    ASN_AFTER_DATE_E    (-151),
    ASN_SIG_OID_E       (-152),
    ASN_TIME_E          (-153),
    ASN_INPUT_E         (-154),
    ASN_SIG_CONFIRM_E   (-155),
    ASN_SIG_HASH_E      (-156),
    ASN_SIG_KEY_E       (-157),
    ASN_DH_KEY_E        (-158),
    ASN_NTRU_KEY_E      (-159),
    ASN_CRIT_EXT_E      (-160),

    ECC_BAD_ARG_E       (-170),
    ASN_ECC_KEY_E       (-171),
    ECC_CURVE_OID_E     (-172),
    BAD_FUNC_ARG        (-173),
    NOT_COMPILED_IN     (-174),
    UNICODE_SIZE_E      (-175),
    NO_PASSWORD         (-176),
    ALT_NAME_E          (-177),

    AES_GCM_AUTH_E      (-180),
    AES_CCM_AUTH_E      (-181),

    CAVIUM_INIT_E       (-182),

    COMPRESS_INIT_E     (-183),
    COMPRESS_E          (-184),
    DECOMPRESS_INIT_E   (-185),
    DECOMPRESS_E        (-186),

    BAD_ALIGN_E         (-187),
    ASN_NO_SIGNER_E     (-188),
    ASN_CRL_CONFIRM_E   (-189),
    ASN_CRL_NO_SIGNER_E (-190),
    ASN_OCSP_CONFIRM_E  (-191),

    BAD_ENC_STATE_E     (-192),
    BAD_PADDING_E       (-193),

    REQ_ATTRIBUTE_E     (-194),

    PKCS7_OID_E         (-195),
    PKCS7_RECIP_E       (-196),
    FIPS_NOT_ALLOWED_E  (-197),
    ASN_NAME_INVALID_E  (-198),

    RNG_FAILURE_E       (-199),
    HMAC_MIN_KEYLEN_E   (-200),
    RSA_PAD_E           (-201),
    LENGTH_ONLY_E       (-202),

    IN_CORE_FIPS_E      (-203),
    AES_KAT_FIPS_E      (-204),
    DES3_KAT_FIPS_E     (-205),
    HMAC_KAT_FIPS_E     (-206),
    RSA_KAT_FIPS_E      (-207),
    DRBG_KAT_FIPS_E     (-208),
    DRBG_CONT_FIPS_E    (-209),
    AESGCM_KAT_FIPS_E   (-210),
    THREAD_STORE_KEY_E  (-211),
    THREAD_STORE_SET_E  (-212),

    MAC_CMP_FAILED_E    (-213),

    MIN_CODE_E          (-300);

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

    public int getCode() {
        return this.code;
    }

    public String getDescription() {
        if (this == WolfCryptError.NO_ERROR_FOUND)
            return "No error code found in JNI WolfCryptError enum";
        return wc_GetErrorString(this.code);
    }

    public static WolfCryptError fromInt(int code) {
        WolfCryptError err = intToErrMap.get(Integer.valueOf(code));
        if (err == null)
            return WolfCryptError.NO_ERROR_FOUND;
        return err;
    }

    private static native String wc_GetErrorString(int error);

    @Override
    public String toString() {
        return code + ": " + this.getDescription();
    }
}

