/* WolfCryptError.java
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

    /** Cannot export private key */
    FIPS_PRIVATE_KEY_LOCKED_E (-287),

    /** Update this to indicate last error */
    WC_LAST_E            (-299),

    /** errors -101 - -299 */
    MIN_CODE_E           (-300),

    /** OCSP Certificate revoked */
    OCSP_CERT_REVOKED    (-360),
    /** OCSP need an URL for lookup */
    OCSP_NEED_URL        (-365),
    /** OCSP responder doesn't know */
    OCSP_CERT_UNKNOWN    (-366),
    /** OCSP lookup not successful */
    OCSP_LOOKUP_FAIL     (-367),
    /** Invalid OCSP Status */
    OCSP_INVALID_STATUS  (-407),
    /** OCSP callback response WOLFSSL_CBIO_ERR_WANT_READ */
    OCSP_WANT_READ       (-408),
    /** HTTP timeout for OCSP or CRL req */
    HTTP_TIMEOUT         (-417),
    /** HTTP Receive error */
    HTTP_RECV_ERR        (-444),
    /** HTTP Header error */
    HTTP_HEADER_ERR      (-445),
    /** HTTP Protocol error */
    HTTP_PROTO_ERR       (-446),
    /** HTTP Status error */
    HTTP_STATUS_ERR      (-447),
    /** HTTP Version error */
    HTTP_VERSION_ERR     (-448),
    /** HTTP Application string error */
    HTTP_APPSTR_ERR      (-449),

    /* Additional SSL/TLS error codes from error-ssl.h */

    /** Process input state error */
    INPUT_CASE_ERROR     (-301),
    /** Bad index to key rounds */
    PREFIX_ERROR         (-302),
    /** Out of memory (SSL) */
    MEMORY_ERROR         (-303),
    /** Verify problem on finished */
    VERIFY_FINISHED_ERROR (-304),
    /** Verify MAC problem */
    VERIFY_MAC_ERROR     (-305),
    /** Parse error on header */
    PARSE_ERROR          (-306),
    /** Weird handshake type */
    UNKNOWN_HANDSHAKE_TYPE (-307),
    /** Error state on socket */
    SOCKET_ERROR_E       (-308),
    /** Expected data not there */
    SOCKET_NODATA        (-309),
    /** Incomplete data */
    INCOMPLETE_DATA      (-310),
    /** Unknown type in record header */
    UNKNOWN_RECORD_TYPE  (-311),
    /** Error during decryption */
    DECRYPT_ERROR        (-312),
    /** Received alert fatal error */
    FATAL_ERROR          (-313),
    /** Error during encryption */
    ENCRYPT_ERROR        (-314),
    /** fread problem */
    FREAD_ERROR          (-315),
    /** Need peer key */
    NO_PEER_KEY          (-316),
    /** Need the private key */
    NO_PRIVATE_KEY       (-317),
    /** Error during RSA private op */
    RSA_PRIVATE_ERROR    (-318),
    /** Server missing DH params */
    NO_DH_PARAMS         (-319),
    /** Build message failure */
    BUILD_MSG_ERROR      (-320),
    /** Client hello malformed */
    BAD_HELLO            (-321),
    /** Peer subject name mismatch */
    DOMAIN_NAME_MISMATCH (-322),
    /** Want read, call again */
    WANT_READ            (-323),
    /** Handshake layer not ready */
    NOT_READY_ERROR      (-324),
    /** Peer IP address mismatch */
    IPADDR_MISMATCH      (-325),
    /** Record layer version error */
    VERSION_ERROR        (-326),
    /** Want write, call again */
    WANT_WRITE           (-327),
    /** Malformed buffer input */
    BUFFER_ERROR_SSL     (-328),
    /** Verify cert error */
    VERIFY_CERT_ERROR    (-329),
    /** Verify sign error */
    VERIFY_SIGN_ERROR    (-330),
    /** PSK client identity error */
    CLIENT_ID_ERROR      (-331),
    /** PSK server hint error */
    SERVER_HINT_ERROR    (-332),
    /** PSK key error */
    PSK_KEY_ERROR        (-333),
    /** gettimeofday failed */
    GETTIME_ERROR        (-337),
    /** getitimer failed */
    GETITIMER_ERROR      (-338),
    /** sigaction failed */
    SIGACT_ERROR         (-339),
    /** setitimer failed */
    SETITIMER_ERROR      (-340),
    /** Record layer length error */
    LENGTH_ERROR         (-341),
    /** Can't decode peer key */
    PEER_KEY_ERROR       (-342),
    /** Peer sent close notify */
    ZERO_RETURN          (-343),
    /** Wrong client/server type */
    SIDE_ERROR           (-344),
    /** Peer didn't send cert */
    NO_PEER_CERT         (-345),
    /** Bad ECC curve type */
    ECC_CURVETYPE_ERROR  (-350),
    /** Bad ECC curve */
    ECC_CURVE_ERROR      (-351),
    /** Bad peer ECC key */
    ECC_PEERKEY_ERROR    (-352),
    /** Bad make ECC key */
    ECC_MAKEKEY_ERROR    (-353),
    /** Bad ECC export key */
    ECC_EXPORT_ERROR     (-354),
    /** Bad ECC shared secret */
    ECC_SHARED_ERROR     (-355),
    /** Not a CA cert error */
    NOT_CA_ERROR         (-357),
    /** Bad cert manager */
    BAD_CERT_MANAGER_ERROR (-359),
    /** CRL certificate revoked */
    CRL_CERT_REVOKED     (-361),
    /** CRL not loaded */
    CRL_MISSING          (-362),
    /** CRL monitor setup error */
    MONITOR_SETUP_E      (-363),
    /** Thread create error */
    THREAD_CREATE_E      (-364),
    /** Max chain depth exceeded */
    MAX_CHAIN_ERROR      (-368),
    /** DTLS cookie error */
    COOKIE_ERROR         (-369),
    /** DTLS sequence error */
    SEQUENCE_ERROR       (-370),
    /** Suites pointer error */
    SUITES_ERROR         (-371),
    /** Max cert extension exceeded */
    MAX_CERT_EXTENSIONS_ERR (-372),
    /** Out of order message */
    OUT_OF_ORDER_E       (-373),
    /** Bad KEA type found */
    BAD_KEA_TYPE_E       (-374),
    /** Sanity check on cipher error */
    SANITY_CIPHER_E      (-375),
    /** RXCB returned more than read */
    RECV_OVERFLOW_E      (-376),
    /** Generate cookie error */
    GEN_COOKIE_E         (-377),
    /** Need peer cert verify error */
    NO_PEER_VERIFY       (-378),
    /** fwrite problem */
    FWRITE_ERROR         (-379),
    /** Cache header match error */
    CACHE_MATCH_ERROR    (-380),
    /** Unrecognized host name error */
    UNKNOWN_SNI_HOST_NAME_E (-381),
    /** Unrecognized max frag len error */
    UNKNOWN_MAX_FRAG_LEN_E (-382),
    /** KeyUse digSignature error */
    KEYUSE_SIGNATURE_E   (-383),
    /** KeyUse keyEncipher error */
    KEYUSE_ENCIPHER_E    (-385),
    /** ExtKeyUse server/client auth */
    EXTKEYUSE_AUTH_E     (-386),
    /** Send callback out of bounds read */
    SEND_OOB_READ_E      (-387),
    /** Invalid renegotiation info */
    SECURE_RENEGOTIATION_E (-388),
    /** Session ticket too large */
    SESSION_TICKET_LEN_E (-389),
    /** Session ticket missing */
    SESSION_TICKET_EXPECT_E (-390),
    /** SCR different cert error */
    SCR_DIFFERENT_CERT_E (-391),
    /** Session secret callback failure */
    SESSION_SECRET_CB_E  (-392),
    /** Finished before change cipher */
    NO_CHANGE_CIPHER_E   (-393),
    /** Sanity check on msg order error */
    SANITY_MSG_E         (-394),
    /** Duplicate message error */
    DUPLICATE_MSG_E      (-395),
    /** SSL 3.0 does not support SNI */
    SNI_UNSUPPORTED      (-396),
    /** Underlying transport closed */
    SOCKET_PEER_CLOSED_E (-397),
    /** Bad session ticket key cb size */
    BAD_TICKET_KEY_CB_SZ (-398),
    /** Bad session ticket msg size */
    BAD_TICKET_MSG_SZ    (-399),
    /** Bad user ticket encrypt */
    BAD_TICKET_ENCRYPT   (-400),
    /** DH key too small */
    DH_KEY_SIZE_E        (-401),
    /** No SNI request */
    SNI_ABSENT_ERROR     (-402),
    /** RSA sign fault */
    RSA_SIGN_FAULT       (-403),
    /** Handshake message too large */
    HANDSHAKE_SIZE_ERROR (-404),
    /** Unrecognized protocol name error */
    UNKNOWN_ALPN_PROTOCOL_NAME_E (-405),
    /** Bad certificate status message */
    BAD_CERTIFICATE_STATUS_ERROR (-406),
    /** RSA key too small */
    RSA_KEY_SIZE_E       (-409),
    /** ECC key too small */
    ECC_KEY_SIZE_E       (-410),
    /** Export version error */
    DTLS_EXPORT_VER_E    (-411),
    /** Input size too big error */
    INPUT_SIZE_E         (-412),
    /** Initialize ctx mutex error */
    CTX_INIT_MUTEX_E     (-413),
    /** Need EMS enabled to resume */
    EXT_MASTER_SECRET_NEEDED_E (-414),
    /** Exceeded DTLS pool size */
    DTLS_POOL_SZ_E       (-415),
    /** Decode handshake message error */
    DECODE_E             (-416),
    /** Write dup write side can't read */
    WRITE_DUP_READ_E     (-418),
    /** Write dup read side can't write */
    WRITE_DUP_WRITE_E    (-419),
    /** TLS cert ctx not matching */
    INVALID_CERT_CTX_E   (-420),
    /** Key share data invalid */
    BAD_KEY_SHARE_DATA   (-421),
    /** Handshake message missing data */
    MISSING_HANDSHAKE_DATA (-422),
    /** Binder does not match */
    BAD_BINDER           (-423),
    /** Extension not allowed in msg */
    EXT_NOT_ALLOWED      (-424),
    /** Security parameter invalid */
    INVALID_PARAMETER    (-425),
    /** Multicast highwater cb err */
    MCAST_HIGHWATER_CB_E (-426),
    /** Alert count exceeded err */
    ALERT_COUNT_E        (-427),
    /** Required extension not found */
    EXT_MISSING          (-428),
    /** TLSX not requested by client */
    UNSUPPORTED_EXTENSION (-429),
    /** PRF not compiled in */
    PRF_MISSING          (-430),
    /** Retransmit DTLS flight over */
    DTLS_RETX_OVER_TX    (-431),
    /** DH params from server not FFDHE */
    DH_PARAMS_NOT_FFDHE_E (-432),
    /** TLSX TCA ID type invalid */
    TCA_INVALID_ID_TYPE  (-433),
    /** TLSX TCA ID no response */
    TCA_ABSENT_ERROR     (-434),
    /** Invalid MAC size for TSIP */
    TSIP_MAC_DIGSZ_E     (-435),
    /** Client cert callback error */
    CLIENT_CERT_CB_ERROR (-436),
    /** Shutdown called redundantly */
    SSL_SHUTDOWN_ALREADY_DONE_E (-437),
    /** Trying to send too much data */
    DTLS_SIZE_ERROR      (-439),
    /** TLS1.3 no cert set error */
    NO_CERT_ERROR        (-440),
    /** DTLS1.2 application data ready */
    APP_DATA_READY       (-441),
    /** Too much early data */
    TOO_MUCH_EARLY_DATA  (-442),
    /** Session stopped by network filter */
    SOCKET_FILTERED_E    (-443),
    /** Bad/unsupported protocol version */
    UNSUPPORTED_PROTO_VERSION (-450),
    /** Wrong key size for Falcon */
    FALCON_KEY_SIZE_E    (-451),
    /** QUIC transport parameter missing */
    QUIC_TP_MISSING_E    (-452),
    /** Wrong key size for Dilithium */
    DILITHIUM_KEY_SIZE_E (-453),
    /** Wrong or missing CID */
    DTLS_CID_ERROR       (-454),
    /** Received too many fragments */
    DTLS_TOO_MANY_FRAGMENTS_E (-455),
    /** QUIC data received on wrong encryption level */
    QUIC_WRONG_ENC_LEVEL (-456),
    /** Duplicate TLS extension in msg */
    DUPLICATE_TLS_EXT_E  (-457),
    /** TLS extension not found */
    WOLFSSL_ALPN_NOT_FOUND (-458),
    /** Certificate type not supported */
    WOLFSSL_BAD_CERTTYPE (-459),
    /** Not used */
    WOLFSSL_BAD_STAT     (-460),
    /** No certificates found at designated path */
    WOLFSSL_BAD_PATH     (-461),
    /** Data format not supported */
    WOLFSSL_BAD_FILETYPE (-462),
    /** Input/output error on file */
    WOLFSSL_BAD_FILE     (-463),
    /** Function not implemented */
    WOLFSSL_NOT_IMPLEMENTED (-464),
    /** Unknown algorithm (EVP) */
    WOLFSSL_UNKNOWN      (-465);

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
