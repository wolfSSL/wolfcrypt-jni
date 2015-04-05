#include <com_wolfssl_wolfcrypt_WolfCrypt.h>
#include <com_wolfssl_wolfcrypt_Fips.h>
#include <wolfcrypt_jni_NativeStruct.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* #define WOLFCRYPT_JNI_DEBUG_ON */
#include <wolfcrypt_jni_debug.h>

/*
 * ### FIPS Aprooved Security Methods ##########################################
 */

/*
 * wolfCrypt FIPS API - Symmetric encrypt/decrypt Service
 */

/* AES */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesSetKey_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject key_buffer,
    jlong size, jobject iv_buffer, jint dir)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_AES)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* key = getDirectBufferAddress(env, key_buffer);
    byte* iv = getDirectBufferAddress(env, iv_buffer);

    if (!aes || !key)
        return BAD_FUNC_ARG;

    ret = AesSetKey_fips(aes, key, size, iv, dir);

    LogStr("AesSetKey_fips(aes=%p, key, iv, %s) = %d\n", aes,
        dir ? "dec" : "enc", ret);
    LogStr("key:\n");
    LogHex(key, size);
    LogStr("iv:\n");
    LogHex(iv, AES_BLOCK_SIZE);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesSetIV_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject iv_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_AES)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* iv = getDirectBufferAddress(env, iv_buffer);

    if (!aes || !iv)
        return BAD_FUNC_ARG;

    ret = AesSetIV_fips(aes, iv);

    LogStr("AesSetIV_fips(aes=%p, iv) = %d\n", aes, ret);
    LogStr("iv:\n");
    LogHex(iv, AES_BLOCK_SIZE);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesCbcEncrypt_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject out_buffer,
    jobject in_buffer, jlong size)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_AES)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);

    if (!aes || !out || !in)
        return BAD_FUNC_ARG;

    ret = AesCbcEncrypt_fips(aes, out, in, (word32) size);

    LogStr("AesCbcEncrypt_fips(aes=%p, msg, cipher) = %d\n", aes, ret);
    LogStr("in:\n");
    LogHex(in, size);
    LogStr("out:\n");
    LogHex(out, size);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesCbcDecrypt_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject out_buffer,
    jobject in_buffer, jlong size)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_AES)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);

    if (!aes || !out || !in)
        return BAD_FUNC_ARG;

    ret = AesCbcDecrypt_fips(aes, out, in, (word32) size);

    LogStr("AesCbcDecrypt_fips(aes=%p, cipher, plain) = %d\n", aes, ret);
    LogStr("in:\n");
    LogHex(in, size);
    LogStr("out:\n");
    LogHex(out, size);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesGcmSetKey_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject key_buffer,
    jlong size)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(HAVE_AESGCM)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* key = getDirectBufferAddress(env, key_buffer);

    if (!aes || !key)
        return BAD_FUNC_ARG;

    ret = AesGcmSetKey_fips(aes, key, size);

    LogStr("AesGcmSetKey_fips(aes=%p, key) = %d\n", aes, ret);
    LogStr("key:\n");
    LogHex(key, size);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesGcmEncrypt_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject out_buffer,
    jobject in_buffer, jlong size, jobject iv_buffer, jlong ivSz,
    jobject authTag_buffer, jlong authTagSz, jobject authIn_buffer,
    jlong authInSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(HAVE_AESGCM)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);
    byte* iv = getDirectBufferAddress(env, iv_buffer);
    byte* authTag = getDirectBufferAddress(env, authTag_buffer);
    byte* authIn = getDirectBufferAddress(env, authIn_buffer);

    if (!aes || !out || !in || (!iv && ivSz) || (!authTag && authTagSz)
        || (!authIn && authInSz))
        return BAD_FUNC_ARG;

    ret = AesGcmEncrypt_fips(aes, out, in, (word32) size, iv, (word32) ivSz,
        authTag, (word32) authTagSz, authIn, (word32) authInSz);

    LogStr(
        "AesGcmEncrypt_fips(aes=%p, msg, cipher, iv, authTag, authIn) = %d\n",
        aes, ret);
    LogStr("in:\n");
    LogHex(in, size);
    LogStr("out:\n");
    LogHex(out, size);
    LogStr("iv:\n");
    LogHex(iv, ivSz);
    LogStr("authTag:\n");
    LogHex(authTag, authTagSz);
    LogStr("authIn:\n");
    LogHex(authIn, authInSz);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_AesGcmDecrypt_1fips(
    JNIEnv* env, jclass class, jobject aes_object, jobject out_buffer,
    jobject in_buffer, jlong size, jobject iv_buffer, jlong ivSz,
    jobject authTag_buffer, jlong authTagSz, jobject authIn_buffer,
    jlong authInSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(HAVE_AESGCM)

    Aes* aes = (Aes*) getNativeStruct(env, aes_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);
    byte* iv = getDirectBufferAddress(env, iv_buffer);
    byte* authTag = getDirectBufferAddress(env, authTag_buffer);
    byte* authIn = getDirectBufferAddress(env, authIn_buffer);

    if (!aes || !out || !in || (!iv && ivSz) || (!authTag && authTagSz)
        || (!authIn && authInSz))
        return BAD_FUNC_ARG;

    ret = AesGcmDecrypt_fips(aes, out, in, (word32) size, iv, (word32) ivSz,
        authTag, (word32) authTagSz, authIn, (word32) authInSz);

    LogStr(
        "AesGcmDecrypt_fips(aes=%p, cipher, plain, iv, authTag, authIn) = %d\n",
        aes, ret);
    LogStr("in:\n");
    LogHex(in, AES_BLOCK_SIZE);
    LogStr("out:\n");
    LogHex(out, AES_BLOCK_SIZE);
    LogStr("iv:\n");
    LogHex(iv, ivSz);
    LogStr("authTag:\n");
    LogHex(authTag, authTagSz);
    LogStr("authIn:\n");
    LogHex(authIn, authInSz);

#endif

    return ret;
}

/* DES3 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Des3_1SetKey_1fips(
    JNIEnv* env, jclass class, jobject des_object, jobject key_buffer,
    jobject iv_buffer, jint dir)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_DES3)

    Des3* des = (Des3*) getNativeStruct(env, des_object);
    byte* key = getDirectBufferAddress(env, key_buffer);
    byte* iv = getDirectBufferAddress(env, iv_buffer);

    if (!des || !key)
        return BAD_FUNC_ARG;

    ret = Des3_SetKey_fips(des, key, iv, dir);

    LogStr("Des3_SetKey_fips(des=%p, key, iv, %s) = %d\n", des,
        dir ? "dec" : "enc", ret);
    LogStr("key:\n");
    LogHex(key, DES3_KEYLEN);
    LogStr("iv:\n");
    LogHex(iv, DES3_IVLEN);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Des3_1SetIV_1fips(
    JNIEnv* env, jclass class, jobject des_object, jobject iv_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_DES3)

    Des3* des = (Des3*) getNativeStruct(env, des_object);
    byte* iv = getDirectBufferAddress(env, iv_buffer);

    if (!des || !iv)
        return BAD_FUNC_ARG;
    ret = Des3_SetIV_fips(des, iv);

    LogStr("Des3_SetIV_fips(des=%p, iv) = %d\n", des, ret);
    LogStr("iv:\n");
    LogHex(iv, DES_BLOCK_SIZE);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Des3_1CbcEncrypt_1fips(
    JNIEnv* env, jclass class, jobject des_object, jobject out_buffer,
    jobject in_buffer, jlong size)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_DES3)

    Des3* des = (Des3*) getNativeStruct(env, des_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);

    if (!des || !out || !in)
        return BAD_FUNC_ARG;

    ret = Des3_CbcEncrypt_fips(des, out, in, (word32) size);

    LogStr("Des3_CbcEncrypt_fips(des=%p, msg, cipher) = %d\n", des, ret);
    LogStr("in:\n");
    LogHex(in, size);
    LogStr("out:\n");
    LogHex(out, size);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Des3_1CbcDecrypt_1fips(
    JNIEnv* env, jclass class, jobject des_object, jobject out_buffer,
    jobject in_buffer, jlong size)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_DES3)

    Des3* des = (Des3*) getNativeStruct(env, des_object);
    byte* out = getDirectBufferAddress(env, out_buffer);
    byte* in = getDirectBufferAddress(env, in_buffer);

    if (!des || !out || !in)
        return BAD_FUNC_ARG;

    ret = Des3_CbcDecrypt_fips(des, out, in, (word32) size);

    LogStr("Des3_CbcDecrypt_fips(des=%p, cipher, plain) = %d\n", des, ret);
    LogStr("in:\n");
    LogHex(in, size);
    LogStr("out:\n");
    LogHex(out, size);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Keyed hash Service
 */

/* HMAC */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_HmacSetKey_1fips(
    JNIEnv* env, jclass class, jobject hmac_object, jint type,
    jobject key_buffer, jlong keySz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_HMAC)

    Hmac* hmac = (Hmac*) getNativeStruct(env, hmac_object);
    byte* key = getDirectBufferAddress(env, key_buffer);

    if (!hmac || !key)
        return BAD_FUNC_ARG;

    ret = HmacSetKey_fips(hmac, type, key, keySz);

    LogStr("HmacSetKey_fips(hmac=%p, type=%d, key, keySz) = %d\n", hmac, type,
        ret);
    LogStr("key:\n");
    LogHex(key, keySz);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_HmacUpdate_1fips(
    JNIEnv* env, jclass class, jobject hmac_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_HMAC)

    Hmac* hmac = (Hmac*) getNativeStruct(env, hmac_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!hmac || !data)
        return BAD_FUNC_ARG;

    ret = HmacUpdate_fips(hmac, data, len);

    LogStr("HmacUpdate_fips(hmac=%p, data, len) = %d\n", hmac, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_HmacFinal_1fips(
    JNIEnv* env, jclass class, jobject hmac_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_HMAC)

    Hmac* hmac = (Hmac*) getNativeStruct(env, hmac_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!hmac || !hash)
        return BAD_FUNC_ARG;

    ret = HmacFinal_fips(hmac, hash);

    LogStr("HmacFinal_fips(hmac=%p, hash) = %d\n", hmac, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Random number generation Service
 */

/* RNG */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitRng_1fips(
    JNIEnv* env, jclass class, jobject rng_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS)

    RNG* rng = (RNG*) getNativeStruct(env, rng_object);

    if (!rng)
        return BAD_FUNC_ARG;

    ret = InitRng_fips(rng);

    LogStr("InitRng_fips(rng=%p) = %d\n", rng, ret);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_FreeRng_1fips(
    JNIEnv* env, jclass class, jobject rng_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS)

    RNG* rng = (RNG*) getNativeStruct(env, rng_object);

    if (!rng)
        return BAD_FUNC_ARG;

    ret = FreeRng_fips(rng);

    LogStr("FreeRng_fips(rng=%p) = %d\n", rng, ret);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RNG_1GenerateBlock_1fips(
    JNIEnv* env, jclass class, jobject rng_object, jobject buf_buffer,
    jlong bufSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS)

    RNG* rng = (RNG*) getNativeStruct(env, rng_object);
    byte* buf = getDirectBufferAddress(env, buf_buffer);

    if (!rng || !buf)
        return BAD_FUNC_ARG;

    ret = RNG_GenerateBlock_fips(rng, buf, bufSz);

    LogStr("RNG_GenerateBlock_fips(rng=%p, buf, bufSz) = %d\n", rng, ret);
    LogStr("output:\n");
    LogHex(buf, bufSz);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RNG_1HealthTest_1fips(
    JNIEnv* env, jclass class, jint reseed, jobject entropyA_object,
    jlong entropyASz, jobject entropyB_object, jlong entropyBSz,
    jobject output_object, jlong outputSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS)

    const byte* entropyA = getDirectBufferAddress(env, entropyA_object);
    const byte* entropyB = getDirectBufferAddress(env, entropyB_object);
    byte* output = getDirectBufferAddress(env, output_object);

    if (!entropyA || (reseed && !entropyB) || !output)
        return BAD_FUNC_ARG;

    ret = RNG_HealthTest_fips(reseed, entropyA, entropyASz, entropyB,
        entropyBSz, output, outputSz);

    LogStr("RNG_HealthTest_fips(reseed=%d, entropyA, entropyASz, "
        "entropyB, entropyBSz, output, outputSz) = %d\n", reseed, ret);
    LogStr("entropyA:\n");
    LogHex((byte*) entropyA, entropyASz);
    LogStr("entropyB:\n");
    LogHex((byte*) entropyB, entropyBSz);
    LogStr("output:\n");
    LogHex(output, outputSz);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Digital signature Service
 */

/* RSA */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitRsaKey_1fips(
    JNIEnv* env, jclass class, jobject rsa_object, jobject heap_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);
    void* heap = getDirectBufferAddress(env, heap_object);

    if (!key)
        return BAD_FUNC_ARG;

    ret = InitRsaKey_fips(key, heap);

    LogStr("InitRsaKey_fips(key=%p, heap=%p) = %d\n", key, heap, ret);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_FreeRsaKey_1fips(
    JNIEnv* env, jclass class, jobject rsa_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!key)
        return BAD_FUNC_ARG;

    ret = FreeRsaKey_fips(key);

    LogStr("FreeRsaKey_fips(key=%p) = %d\n", key, ret);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaSSL_1Sign_1fips(
    JNIEnv* env, jclass class, jobject in_object, jlong inLen,
    jobject out_object, jlong outLen, jobject rsa_object, jobject rng_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    byte* in = getDirectBufferAddress(env, in_object);
    byte* out = getDirectBufferAddress(env, out_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);
    RNG* rng = (RNG*) getNativeStruct(env, rsa_object);

    /**
     * Providing an rng is optional. RNG_GenerateBlock will return BAD_FUNC_ARG
     * on a NULL rng if an RNG is needed by RsaPad.
     */
    if (!in || !out || !key)
        return BAD_FUNC_ARG;

    ret = RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);

    LogStr("RsaSSL_Sign_fips(in, inLen, out, outLen, key=%p, rng=%p) = %d\n",
        key, rng, ret);
    LogStr("in:\n");
    LogHex((byte*) in, inLen);
    LogStr("out:\n");
    LogHex((byte*) out, outLen);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaSSL_1Verify_1fips(
    JNIEnv* env, jclass class, jobject in_object, jlong inLen,
    jobject out_object, jlong outLen, jobject rsa_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    byte* in = getDirectBufferAddress(env, in_object);
    byte* out = getDirectBufferAddress(env, out_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!in || !out || !key)
        return BAD_FUNC_ARG;

    ret = RsaSSL_Verify_fips(in, inLen, out, outLen, key);

    LogStr("RsaSSL_Verify_fips(in, inLen, out, outLen, key=%p) = %d\n", key,
        ret);
    LogStr("in:\n");
    LogHex((byte*) in, inLen);
    LogStr("out:\n");
    LogHex((byte*) out, outLen);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaEncryptSize_1fips(
    JNIEnv* env, jclass class, jobject rsa_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!key)
        return BAD_FUNC_ARG;

    ret = RsaEncryptSize_fips(key);

    LogStr("RsaEncryptSize_fips(key=%p) = %d\n", key, ret);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaPrivateKeyDecode_1fips(
    JNIEnv* env, jclass class, jobject input_object, jlongArray inOutIdx,
    jobject rsa_object, jlong inSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    word32 tmpIdx;
    byte* input = getDirectBufferAddress(env, input_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!input || !key)
        return BAD_FUNC_ARG;

    (*env)->GetLongArrayRegion(env, inOutIdx, 0, 1, (jlong*) &tmpIdx);

    ret = RsaPrivateKeyDecode_fips(input, &tmpIdx, key, inSz);

    (*env)->SetLongArrayRegion(env, inOutIdx, 0, 1, (jlong*) &tmpIdx);

    LogStr("RsaPrivateKeyDecode_fips(input, inOutIdx, key=%p, inSz) = %d\n",
        key, ret);
    LogStr("input:\n");
    LogHex((byte*) input, inSz);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaPublicKeyDecode_1fips(
    JNIEnv* env, jclass class, jobject input_object, jlongArray inOutIdx,
    jobject rsa_object, jlong inSz)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    word32 tmpIdx;
    byte* input = getDirectBufferAddress(env, input_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!input || !key)
        return BAD_FUNC_ARG;

    (*env)->GetLongArrayRegion(env, inOutIdx, 0, 1, (jlong*) &tmpIdx);

    ret = RsaPublicKeyDecode_fips(input, &tmpIdx, key, inSz);

    (*env)->SetLongArrayRegion(env, inOutIdx, 0, 1, (jlong*) &tmpIdx);

    LogStr("RsaPublicKeyDecode_fips(input, inOutIdx, key=%p, inSz) = %d\n", key,
        ret);
    LogStr("input:\n");
    LogHex((byte*) input, inSz);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Message digest Service
 */

/* SHA */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitSha_1fips(
    JNIEnv* env, jclass class, jobject sha_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA)

    Sha* sha = (Sha*) getNativeStruct(env, sha_object);

    if (!sha)
        return BAD_FUNC_ARG;

    ret = InitSha_fips(sha);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_ShaUpdate_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA)

    Sha* sha = (Sha*) getNativeStruct(env, sha_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!sha || !data)
        return BAD_FUNC_ARG;

    ret = ShaUpdate_fips(sha, data, len);

    LogStr("ShaUpdate_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_ShaFinal_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA)

    Sha* sha = (Sha*) getNativeStruct(env, sha_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!sha || !hash)
        return BAD_FUNC_ARG;

    ret = ShaFinal_fips(sha, hash);

    LogStr("ShaFinal_fips(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}

/* SHA256 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitSha256_1fips(
    JNIEnv* env, jclass class, jobject sha_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA256)

    Sha256* sha = (Sha256*) getNativeStruct(env, sha_object);

    if (!sha)
        return BAD_FUNC_ARG;

    ret = InitSha256_fips(sha);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha256Update_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA256)

    Sha256* sha = (Sha256*) getNativeStruct(env, sha_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!sha || !data)
        return BAD_FUNC_ARG;

    ret = Sha256Update_fips(sha, data, len);

    LogStr("Sha256Update_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha256Final_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_SHA256)

    Sha256* sha = (Sha256*) getNativeStruct(env, sha_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!sha || !hash)
        return BAD_FUNC_ARG;

    ret = Sha256Final_fips(sha, hash);

    LogStr("Sha256Final_fips(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}

/* SHA384 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitSha384_1fips(
    JNIEnv* env, jclass class, jobject sha_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha384* sha = (Sha384*) getNativeStruct(env, sha_object);

    if (!sha)
        return BAD_FUNC_ARG;

    ret = InitSha384_fips(sha);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha384Update_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha384* sha = (Sha384*) getNativeStruct(env, sha_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!sha || !data)
        return BAD_FUNC_ARG;

    ret = Sha384Update_fips(sha, data, len);

    LogStr("Sha384Update_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha384Final_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha384* sha = (Sha384*) getNativeStruct(env, sha_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!sha || !hash)
        return BAD_FUNC_ARG;

    ret = Sha384Final_fips(sha, hash);

    LogStr("Sha384Final_fips(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}

/* SHA512 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitSha512_1fips(
    JNIEnv* env, jclass class, jobject sha_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha512* sha = (Sha512*) getNativeStruct(env, sha_object);

    if (!sha)
        return BAD_FUNC_ARG;

    ret = InitSha512_fips(sha);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha512Update_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha512* sha = (Sha512*) getNativeStruct(env, sha_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!sha || !data)
        return BAD_FUNC_ARG;

    ret = Sha512Update_fips(sha, data, len);

    LogStr("Sha512Update_fips(sha=%p, data, len) = %d\n", sha, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Sha512Final_1fips(
    JNIEnv* env, jclass class, jobject sha_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && defined(WOLFSSL_SHA512)

    Sha512* sha = (Sha512*) getNativeStruct(env, sha_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!sha || !hash)
        return BAD_FUNC_ARG;

    ret = Sha512Final_fips(sha, hash);

    LogStr("Sha512Final_fips(sha=%p, hash) = %d\n", sha, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Show status Service
 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_wolfCrypt_1GetStatus_1fips(
    JNIEnv* env, jclass class)
{
    return (jint) wolfCrypt_GetStatus_fips();
}

/*
 * ### FIPS Allowed Security Methods ###########################################
 */

/*
 * wolfCrypt FIPS API - Key transport Service
 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaPublicEncrypt_1fips(
    JNIEnv* env, jclass class, jobject in_object, jlong inLen,
    jobject out_object, jlong outLen, jobject rsa_object, jobject rng_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    byte* in = getDirectBufferAddress(env, in_object);
    byte* out = getDirectBufferAddress(env, out_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);
    RNG* rng = (RNG*) getNativeStruct(env, rsa_object);

    /**
     * Providing an rng is optional. RNG_GenerateBlock will return BAD_FUNC_ARG
     * on a NULL rng if an RNG is needed by RsaPad.
     */
    if (!in || !out || !key)
        return BAD_FUNC_ARG;

    ret = RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);

    LogStr(
        "RsaPublicEncrypt_fips(in, inLen, out, outLen, key=%p, rng=%p) = %d\n",
        key, rng, ret);
    LogStr("in:\n");
    LogHex((byte*) in, inLen);
    LogStr("out:\n");
    LogHex((byte*) out, outLen);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_RsaPrivateDecrypt_1fips(
    JNIEnv* env, jclass class, jobject in_object, jlong inLen,
    jobject out_object, jlong outLen, jobject rsa_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_RSA)

    byte* in = getDirectBufferAddress(env, in_object);
    byte* out = getDirectBufferAddress(env, out_object);
    RsaKey* key = (RsaKey*) getNativeStruct(env, rsa_object);

    if (!in || !out || !key)
        return BAD_FUNC_ARG;

    ret = RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);

    LogStr("RsaPrivateDecrypt_fips(in, inLen, out, outLen, key=%p) = %d\n", key,
        ret);
    LogStr("in:\n");
    LogHex((byte*) in, inLen);
    LogStr("out:\n");
    LogHex((byte*) out, outLen);

#endif

    return ret;
}

/*
 * wolfCrypt FIPS API - Message digest MD5 Service
 */

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_InitMd5_1fips(
    JNIEnv* env, jclass class, jobject md5_object)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_MD5)

    Md5* md5 = (Md5*) getNativeStruct(env, md5_object);

    if (!md5)
        return BAD_FUNC_ARG;

    InitMd5(md5);
    ret = com_wolfssl_wolfcrypt_WolfCrypt_SUCCESS;

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Md5Update_1fips(
    JNIEnv* env, jclass class, jobject md5_object, jobject data_buffer,
    jlong len)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_MD5)

    Md5* md5 = (Md5*) getNativeStruct(env, md5_object);
    byte* data = getDirectBufferAddress(env, data_buffer);

    if (!md5 || !data)
        return BAD_FUNC_ARG;

    Md5Update(md5, data, len);
    ret = com_wolfssl_wolfcrypt_WolfCrypt_SUCCESS;

    LogStr("Md5Update_fips(md5=%p, data, len) = %d\n", md5, ret);
    LogStr("data:\n");
    LogHex(data, len);

#endif

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_Fips_Md5Final_1fips(
    JNIEnv* env, jclass class, jobject md5_object, jobject hash_buffer)
{
    jint ret = NOT_COMPILED_IN;

#if defined(HAVE_FIPS) && !defined(NO_MD5)

    Md5* md5 = (Md5*) getNativeStruct(env, md5_object);
    byte* hash = getDirectBufferAddress(env, hash_buffer);

    if (!md5 || !hash)
        return BAD_FUNC_ARG;

    Md5Final(md5, hash);
    ret = com_wolfssl_wolfcrypt_WolfCrypt_SUCCESS;

    LogStr("Md5Final_fips(md5=%p, hash) = %d\n", md5, ret);
    LogStr("hash:\n");
    LogHex(hash, SHA_DIGEST_SIZE);

#endif

    return ret;
}
