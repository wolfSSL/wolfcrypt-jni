/* WolfSSLKeyStore.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl.provider.jce;

import java.util.Date;
import java.util.Enumeration;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.DestroyFailedException;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Pwdbased;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfSSL KeyStore implementation (WKS).
 *
 * This KeyStore has been designed to be compatible with wolfCrypt
 * FIPS 140-2 and 140-3, using algorithms and modes inside the wolfCrypt FIPS
 * module boundary.
 *
 * Private keys are protected inside this KeyStore implementation using
 * PKCS#5 PBKDF2 and AES-CBC with HMAC-SHA512, specifically:
 *
 *   1. PKCS#5 PBKDF2 derives an encryption key from provided user password
 *        + Password is converted from char[] to byte[] using UTF-8
 *        + Salt size = 16 bytes, Iteration count = 210,000
 *        + Iterations can be customized using wolfjce.wks.iterationCount
 *          Security property in a java.security file
 *
 *   2. AES-CBC encrypts the private key using derived password
 *        + IV length = 16 bytes
 *        + Key length = 32 bytes (256 bits)
 *
 *   3. HMAC-SHA512 is calculated over the encrypted key and associated
 *      parameters (Encrypt-then-MAC).
 *
 * When this KeyStore is stored (engineStore()), the following format is used.
 * There is an HMAC-SHA512 stored at the end which is calculated over the
 * entire HEADER + ENTRIES + PBKDF2 SALT LEN/SALT + PBKDF2 iterations, which
 * is used to check the KeyStore integrity when loaded back in (engineLoad())
 * to detect corrupt or tampered KeyStores.
 *
 *   HEADER:
 *     magicNumber                       (int / 7)
 *     keystoreVersion                   (int)
 *     entryCount                        (int)
 *   ENTRIES (can be any of below, depending on type)
 *     [WKSPrivateKey]
 *       entryId                         (int / 1)
 *       alias                           (UTF String)
 *       creationDate.getTime()          (long)
 *       kdfSalt.length                  (int)
 *       kdfSalt                         (byte[])
 *       kdfIterations                   (int)
 *       iv.length                       (int)
 *       iv                              (byte[])
 *       encryptedKey.length             (int)
 *       encryptedKey                    (byte[])
 *       chain.length                    (int)
 *       FOR EACH CERT:
 *         chain[i].getType()            (UTF String)
 *         chain[i].getEncoded().length  (int)
 *         chain[i].getEncoced()         (byte[])
 *       hmac.length                     (int)
 *       hmac (HMAC-SHA512)              (byte[])
 *     [WKSSecretKey]
 *       entryId                         (int / 3)
 *       alias                           (UTF String)
 *       creationDate.getTime()          (long)
 *       key.getAlgorithm()              (UTF String)
 *       kdfSalt.length                  (int)
 *       kdfIterations                   (int)
 *       kdfSalt                         (byte[])
 *       iv.length                       (int)
 *       iv                              (byte[])
 *       encryptedKey.length             (int)
 *       encryptedKey                    (byte[])
 *       hmac.length                     (int)
 *       hmac (HMAC-SHA512)              (byte[])
 *     [WKSCertificate]
 *       entryId                         (int / 2)
 *       alias                           (UTF String)
 *       creationDate.getTime()          (long)
 *       cert.getType()                  (UTF String)
 *       cert.getEncoded().length        (int)
 *       cert.getEncoced()               (byte[])
 *   HMAC PBKDF2 salt length             int
 *   HMAC PBKDF2 salt                    (byte[])
 *   HMAC PBKDF2 iterations              int
 *   HMAC length                         int
 *   HMAC (HMAC-SHA512)                  (byte[])
 *
 * When loading a KeyStore (engineLoad()), the password is optional. If a
 * password is provided, we recalculate the HMAC over the input KeyStore and
 * check against the HMAC encoded in the KeyStore bytes to detect if the
 * stored KeyStore has been tampered with. If a password is not provided,
 * the integrity check will be skipped. This is consistent with existing
 * (ie: JKS) KeyStore implementation behavior and allows for consistent use of
 * system KeyStores (ex: cacerts) where users do not normally have/use the
 * password when loading the KeyStore.
 *
 * Each PrivateKey and SecretKey entry includes a separate HMAC-SHA512.
 * That HMAC is loaded together with the entry and verified against the
 * provided password when the entry is retrieved by the user. This is
 * independent of the entire KeyStore integrity HMAC verification.
 */
public class WolfSSLKeyStore extends KeyStoreSpi {

    private static WolfCryptDebug debug;

    /* RNG used for generating random IVs and salts */
    private SecureRandom rand = null;
    private static final Object randLock = new Object();

    /* PBKDF2 parameters:
     *   [salt]: NIST SP 800-132 recommends salts should be at least 128 bits
     *   [iterations]: OWASP PBKDF2 guidance recommends 210,000 iterations
     *     of PBKDF2-HMAC-SHA512. HMAC-SHA512 was chosen since significantly
     *     fewer iterations are required as compared to HMAC-SHA256 (requires
     *     600,000 iterations to match OWASP recommendations). Iterations
     *     can be customized using Java Security property
     *     'wolfjce.wks.iterationCount' in java.security. Minimum iterations
     *     allowed is 10,000.
     *   [type]: SHA-512 (WolfCrypt.WC_HASH_TYPE_SHA512) */
    private static final int WKS_PBKDF2_SALT_SIZE = 16;
    private static final int WKS_PBKDF2_MIN_ITERATIONS = 10000;
    private static final int WKS_PBKDF2_DEFAULT_ITERATIONS = 210000;
    private static final int WKS_PBKDF2_ITERATION_COUNT;
    private static final int WKS_PBKDF2_TYPE = WolfCrypt.WC_HASH_TYPE_SHA512;

    /* AES-CBC parameters (bytes) */
    private static final int WKS_ENC_IV_LENGTH = 16;
    private static final int WKS_ENC_KEY_LENGTH = Aes.KEY_SIZE_256;

    /* HMAC parameters:
     *   64-bytes (512-bit) to match usage with HMAC-SHA512 */
    private static final int WKS_HMAC_KEY_LENGTH = 64;

    /* Max cert chain length, used in sanity check when loading a KeyStore.
     * Can be customized via 'wolfjce.wks.maxCertChainLength' Java Security
     * property in java.security file */
    private static final int WKS_DEFAULT_MAX_CHAIN_COUNT = 100;
    private static final int WKS_MAX_CHAIN_COUNT;

    /* WKS magic number, used when storing KeyStore to OutputStream */
    private static final int WKS_MAGIC_NUMBER = 7;

    /* WKS KeyStore version (may increment in future if behavior changes) */
    private static final int WKS_STORE_VERSION = 1;

    /* WKS entry IDs, used when storing/loading KeyStore */
    private static final int WKS_ENTRY_ID_PRIVATE_KEY = 1;
    private static final int WKS_ENTRY_ID_CERTIFICATE = 2;
    private static final int WKS_ENTRY_ID_SECRET_KEY  = 3;

    /**
     * KeyStore entries as ConcurrentHashMap.
     * Entry values are objects of one of the following types:
     * WKSPrivateKey, WKSCertificate, WKSSecretKey. Keys are Strings which
     * represent an alias name.
     */
    private ConcurrentHashMap<String, Object> entries =
        new ConcurrentHashMap<>();

    private enum EntryType {
        PRIVATE_KEY,    /* WKSPrivateKey */
        CERTIFICATE,    /* WKSCertificate */
        SECRET_KEY      /* WKSSecretKey */
    };

    static {
        int iCount = WKS_PBKDF2_DEFAULT_ITERATIONS;
        int cLength = WKS_DEFAULT_MAX_CHAIN_COUNT;
        String iterations = null;
        String chainCount = null;

        /* Set PBKDF2 iteration count, using default or one set by
         * user in 'wolfjce.wks.iterationCount' Security property in
         * java.security file */
        iterations = Security.getProperty("wolfjce.wks.iterationCount");
        if (iterations != null && !iterations.isEmpty()) {
            try {
                iCount = Integer.parseInt(iterations);
                if (iCount < WKS_PBKDF2_MIN_ITERATIONS) {
                    log("wolfjce.wks.iterationCount (" + iCount + ") lower " +
                        "than min allowed (" + WKS_PBKDF2_MIN_ITERATIONS +
                        ")");
                    iCount = WKS_PBKDF2_DEFAULT_ITERATIONS;
                }

            } catch (NumberFormatException e) {
                /* Error parsing property, fall back to default */
                log("error parsing wolfjce.wks.iterationCount property, " +
                    "using default instead");
            }
        }

        log("setting PBKDF2 iterations: " + iCount);
        WKS_PBKDF2_ITERATION_COUNT = iCount;

        /* Set max certificate chain length limitation, using default or one
         * set with `wolfjce.wks.maxCertChainLength` Security property in
         * java.security file */
        chainCount = Security.getProperty("wolfjce.wks.maxCertChainLength");
        if (chainCount != null && !chainCount.isEmpty()) {
            try {
                cLength = Integer.parseInt(chainCount);
                if (cLength <= 0) {
                    log("wolfjce.wks.maxCertChainLength (" + cLength +
                        ") lower than 0, using default");
                    cLength = WKS_DEFAULT_MAX_CHAIN_COUNT;
                }
            } catch (NumberFormatException e) {
                /* Error parsing property, fall back to default */
                log("error parsing wolfjce.wks.maxCertChainLength property, " +
                    "using default instead");
            }
        }

        log("setting max cert chain length: " + cLength);
        WKS_MAX_CHAIN_COUNT = cLength;
    }

    /**
     * Create new WolfSSLKeyStore object
     */
    public WolfSSLKeyStore() {
        log("created new KeyStore: type WKS (version: " +
            WKS_STORE_VERSION + ")");
    }

    /**
     * Native JNI method that calls wolfSSL_X509_check_private_key()
     * to confirm that the provided X.509 certificate matches the given
     * private key.
     *
     * @param derCert X.509 certificate encoded as DER byte array
     * @param pkcs8PrivKey Private key encoded as PKCS#8 byte array
     *
     * @return true if matches, otherwise false if no match
     *
     * @throws WolfCryptException on native wolfSSL error
     */
    private native boolean X509CheckPrivateKey(
        byte[] derCert, byte[] pkcs8PrivKey) throws WolfCryptException;

    /**
     * Return entry from internal map that matches alias and type.
     *
     * @param alias Alias for entry to retrieve
     * @param type type of entry that should be returned, either
     *        EntryType.PRIVATE_KEY, EntryType.CERTIFICATE, or
     *        EntryType.SECRET_KEY
     *
     * @return entry Object if found, otherwise null if not found or entry
     *         for given alias does not match type requested
     */
    private Object getEntryFromAlias(String alias, EntryType type) {

        Object entry = null;

        if (alias == null || alias.isEmpty()) {
            return null;
        }

        entry = entries.get(alias);
        if (entry == null) {
            return null;
        }

        switch (type) {
            case PRIVATE_KEY:
                if (entry instanceof WKSPrivateKey) {
                    return entry;
                }
                break;
            case CERTIFICATE:
                if (entry instanceof WKSCertificate) {
                    return entry;
                }
                break;
            case SECRET_KEY:
                if (entry instanceof WKSSecretKey) {
                    return entry;
                }
            default:
                break;
        }

        return null;
    }

    /**
     * Derive encryption and authentication keys from password using PBKDF2.
     *
     * @param pass password to use for key protection
     * @param salt salt for PBKDF2 derivation
     * @param iterations iterations for PBKDF2 derivation
     * @param kLen key length to generate
     *
     * @return byte array continaing derived key of specified length
     *
     * @throws KeyStoreException on error deriving key
     */
    private static byte[] deriveKeyFromPassword(char[] pass,
        byte[] salt, int iterations, int kLen) throws KeyStoreException {

        byte[] kek = null;

        if (pass == null || pass.length == 0 || salt == null ||
            salt.length == 0 || iterations <= 0 || kLen <= 0) {
            throw new KeyStoreException(
                "Invalid arguments when deriving key from password");
        }

        try {
            kek = Pwdbased.PBKDF2(
                WolfCryptSecretKeyFactory.passwordToByteArray(pass),
                salt, iterations, kLen, WKS_PBKDF2_TYPE);

            if (kek == null) {
                throw new KeyStoreException(
                    "Error deriving key encryption key with PBKDF2");
            }

        } catch (WolfCryptException e) {
            if (kek != null) {
                Arrays.fill(kek, (byte)0);
            }
            throw new KeyStoreException(e);
        }

        return kek;
    }

    /**
     * Generate HMAC over data using provided key.
     *
     * @param key HMAC key to be used
     * @param data data to be used as input for HMAC
     *
     * @return generated HMAC value on success, null on error
     *
     * @throws KeyStoreException on error generating HMAC
     */
    private static byte[] generateHmac(byte[] key, byte[] data)
        throws KeyStoreException {

        byte[] hmac = null;
        SecretKeySpec spec = null;
        Mac mac = null;

        if (key == null || key.length == 0 ||
            data == null || data.length == 0) {
            throw new KeyStoreException(
                "HMAC key or data null or zero length when generating");
        }

        try {
            mac = Mac.getInstance("HmacSHA512", "wolfJCE");
            spec = new SecretKeySpec(key, "SHA512");

            /* Generate HMAC-SHA512 */
            mac.init(spec);
            mac.update(data);
            hmac = mac.doFinal();

        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException(
                "HmacSHA512 not available in wolfJCE Mac service", e);

        } catch (NoSuchProviderException e) {
            throw new KeyStoreException(
                "WolfSSLKeyStore must currently use wolfJCE for " +
                "HmacSHA512", e);

        } catch (IllegalStateException e) {
            throw new KeyStoreException(
                "Error initializing Mac object", e);

        } catch (InvalidKeyException e) {
            throw new KeyStoreException(
                "Invalid SecretKeySpec passed to Mac.init()");

        } finally {
            if (spec != null) {
                try {
                    spec.destroy();
                } catch (DestroyFailedException e) {
                    log("SecretKeySpec.destroy() failed in generateHmac()");
                }
            }
        }

        return hmac;
    }

    /**
     * Encrypt plaintext key using AES-CBC.
     *
     * AES-CBC encryption uses Cipher.AES/CBC/PKCS5Padding mode.
     *
     * @param plainKey plaintext key to be encrypted/protected
     * @param kek key encryption key, used to encrypt plaintext key
     * @param pass password to use for key protection
     * @param iv initialization vector (IV) for encryption operation
     *
     * @return byte array containing encrypted/protected key
     *
     * @throws KeyStoreException on error encrypting key
     */
    private static byte[] encryptKey(byte[] plainKey, byte[] kek,
        byte[] iv) throws KeyStoreException {

        Cipher enc = null;
        SecretKeySpec keySpec = null;
        IvParameterSpec ivSpec = null;
        byte[] encrypted = null;

        if (plainKey == null || plainKey.length == 0 || kek == null ||
            kek.length != WKS_ENC_KEY_LENGTH || iv == null ||
            iv.length != Aes.BLOCK_SIZE) {
            throw new KeyStoreException(
                "Invalid arguments not allowed when encrypting key");
        }

        try {
            try {
                enc = Cipher.getInstance("AES/CBC/PKCS5Padding", "wolfJCE");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new KeyStoreException(
                    "AES/CBC/PKCS5Padding not available in wolfJCE Cipher", e);

            } catch (NoSuchProviderException e) {
                throw new KeyStoreException(
                    "WolfSSLKeyStore must currently use wolfJCE for AES", e);
            }

            keySpec = new SecretKeySpec(kek, "AES");
            ivSpec = new IvParameterSpec(iv);

            try {
                enc.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            } catch (InvalidKeyException e) {
                throw new KeyStoreException(
                    "Invalid AES key used for private key encryption", e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new KeyStoreException(
                    "Invalid params used for private key encryption", e);
            }

            try {
                encrypted = enc.doFinal(plainKey);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new KeyStoreException(
                    "Error encrypting private key with AES-CBC", e);
            }

        } finally {
            if (keySpec != null) {
                try {
                    keySpec.destroy();
                } catch (DestroyFailedException e) {
                    log("SecretKeySpec.destroy() failed in encryptKey()");
                }
            }
        }

        return encrypted;
    }

    /**
     * Decrypt protected key using AES-CBC, return original plaintext
     * key as byte array.
     *
     * @param encKey encrypted/protected key as byte array
     * @param kek key encryption key to decrypt with
     * @param iv initialization vector (IV) for decryption operation
     *
     * @return unprotected plaintext key as byte array
     *
     * @throws KeyStoreException on error unprotecting/decrypting key
     */
    private static byte[] decryptKey(byte[] encKey, byte[] kek, byte[] iv)
        throws KeyStoreException {

        Cipher dec = null;
        SecretKeySpec keySpec = null;
        IvParameterSpec ivSpec = null;
        byte[] plain = null;

        if (encKey == null || encKey.length == 0 || kek == null ||
            kek.length == 0 || iv == null || iv.length == 0 ||
            iv.length != Aes.BLOCK_SIZE) {
            throw new KeyStoreException(
                "Invalid arguments not allowed when decrypting key");
        }

        try {
            /* Decrypt protected key with AES-CBC and KEK */
            try {
                dec = Cipher.getInstance("AES/CBC/PKCS5Padding", "wolfJCE");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new KeyStoreException(
                    "AES/CBC/PKCS5Padding not available in wolfJCE Cipher", e);
            } catch (NoSuchProviderException e) {
                throw new KeyStoreException(
                    "WolfSSLKeyStore must currently use wolfJCE for AES", e);
            }

            keySpec = new SecretKeySpec(kek, "AES");
            ivSpec = new IvParameterSpec(iv);

            try {
                dec.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            } catch (InvalidKeyException e) {
                throw new KeyStoreException(
                    "Invalid AES key used for private key decryption");
            } catch (InvalidAlgorithmParameterException e) {
                throw new KeyStoreException(
                    "Invalid AES-CBC parameters for private key decryption", e);
            }

            try {
                /* Strips off padding internally, return is only plaintext */
                plain = dec.doFinal(encKey);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                if (plain != null) {
                    Arrays.fill(plain, (byte)0);
                }
                throw new KeyStoreException(
                    "Error decrypting private key with AES-CBC", e);
            }

        } finally {
            if (keySpec != null) {
                try {
                    keySpec.destroy();
                } catch (DestroyFailedException e) {
                    log("SecretKeySpec.destroy() failed in decryptKey()");
                }
            }
        }

        return plain;
    }

    /**
     * Return the key associated with the given alias, using the provided
     * password to decrypt it.
     *
     * In order for a key to be returned it must have been associated with
     * the alias through a call to setKeyEntry() with a PrivateKey or
     * SecretKey object.
     *
     * @param alias alias for which to return the associated key
     * @param password password used to decrypt key
     *
     * @return the requested Key, or null if the alias does not exist or does
     *         not match a key entry.
     *
     * @throws NoSuchAlgorithmException if the algorithm for recovering the
     *         key cannot be found
     * @throws UnrecoverableKeyException if the key cannot be recovered
     */
    @Override
    public synchronized Key engineGetKey(String alias, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException {

        int algoId = 0;
        byte[] plainKey = null;
        Object entry = null;

        PrivateKey pKey = null;
        PKCS8EncodedKeySpec p8Spec = null;
        KeyFactory keyFact = null;

        SecretKey sKey = null;
        SecretKeySpec skSpec = null;

        log("returning Key entry for alias: " + alias);

        entry = getEntryFromAlias(alias, EntryType.PRIVATE_KEY);
        if (entry == null) {
            entry = getEntryFromAlias(alias, EntryType.SECRET_KEY);
            if (entry == null) {
                return null;
            }
        }

        if (password == null || password.length == 0) {
            throw new UnrecoverableKeyException("Password cannot be null");
        }

        try {
            if (entry instanceof WKSPrivateKey) {
                plainKey = ((WKSPrivateKey)entry).getDecryptedKey(password);

                p8Spec = new PKCS8EncodedKeySpec(plainKey);

                algoId = Asn.getPkcs8AlgoID(plainKey);
                if (algoId == 0) {
                    throw new UnrecoverableKeyException(
                        "Unable to parse PKCS#8 algorithm ID from " +
                        "unprotected key");
                }

                switch (algoId) {
                    case Asn.RSAk:
                        keyFact = KeyFactory.getInstance("RSA");
                        break;
                    case Asn.ECDSAk:
                        keyFact = KeyFactory.getInstance("EC");
                        break;
                    default:
                        throw new NoSuchAlgorithmException(
                            "Only RSA and EC private key encoding supported");
                }

                try {
                    pKey = keyFact.generatePrivate(p8Spec);
                    if (pKey == null) {
                        throw new UnrecoverableKeyException(
                            "Error generating PrivateKey from " +
                            "PKCS8EncodedKeySpec");
                    }
                } catch (InvalidKeySpecException e) {
                    throw new UnrecoverableKeyException(
                        "Invalid key spec for KeyFactory");
                }
            }
            else if (entry instanceof WKSSecretKey) {
                WKSSecretKey sk = (WKSSecretKey)entry;

                plainKey = sk.getDecryptedKey(password);

                sKey = new SecretKeySpec(plainKey, sk.keyAlgo);
            }

        } finally {
            if (plainKey != null) {
                Arrays.fill(plainKey, (byte)0);
            }
        }

        if (entry instanceof WKSPrivateKey) {
            return (Key)pKey;
        }
        else if (entry instanceof WKSSecretKey) {
            return (Key)sKey;
        }
        else {
            return null;
        }
    }

    /**
     * Return the certificate chain associated with the provided alias.
     *
     * The certificate chain returned must have been associated with the
     * alias through a call to setKeyEntry() with a PrivateKey object.
     *
     * @param alias the alias for which to return the matching cert chain
     *
     * @return the certificate chain, ordered with the user/peer certificate
     *         first then going up to the root CA last. null if the alias
     *         does not exist or does not contain a certificate chain.
     */
    @Override
    public synchronized Certificate[] engineGetCertificateChain(String alias) {

        Object entry = null;

        log("returning Certificate[] for alias: " + alias);

        entry = entries.get(alias);
        if ((entry != null) && (entry instanceof WKSPrivateKey)) {
            return ((WKSPrivateKey)entry).chain.clone();
        }

        return null;
    }

    /**
     * Return the certificate associated with the provided alias.
     *
     * If the stored certificate was associated with the alias using a call
     * to setCertificateEntry() then the trusted certificate contained in
     * the entry is returned.
     *
     * If the given alias contains a private key entry which was created
     * with a call to setKeyEntry(), the first certificate in the chain
     * used to create that key entry is returned (if the chain exists).
     *
     * @param alias the alias for which to return the matching certificate
     *
     * @return the certificate, or null if the alias does not exist or
     *         does not match any entries.
     */
    @Override
    public synchronized Certificate engineGetCertificate(String alias) {

        Object entry = null;

        log("returning Certificate for alias: " + alias);

        entry = entries.get(alias);
        if (entry != null) {
            if (entry instanceof WKSCertificate) {
                return ((WKSCertificate)entry).cert;
            }
            else if (entry instanceof WKSPrivateKey) {
                WKSPrivateKey key = (WKSPrivateKey)entry;
                if (key.chain != null && key.chain.length > 0) {
                    return key.chain[0];
                }
            }
        }

        return null;
    }

    /**
     * Return the creation date of the entry matching the provided alias.
     *
     * @param alias the alias used to find matching entry
     *
     * @return the creation date of the entry matching alias, or null if the
     *         alias does not exist.
     */
    @Override
    public synchronized Date engineGetCreationDate(String alias) {

        Object entry = null;

        log("returning creation date for entry at alias: " + alias);

        entry = entries.get(alias);
        if (entry != null) {
            if (entry instanceof WKSCertificate) {
                return ((WKSCertificate)entry).creationDate;
            }
            else if (entry instanceof WKSPrivateKey) {
                return ((WKSPrivateKey)entry).creationDate;
            }
            else if (entry instanceof WKSSecretKey) {
                return ((WKSSecretKey)entry).creationDate;
            }
        }

        return null;
    }

    /**
     * Internal method to check if a Key object is supported by this KeyStore
     * for storing into an alias.
     *
     * 1. Key must be PrivateKey or SecretKey
     * 2. If PrivateKey object:
     *      a. Must be of format "PKCS#8"
     *      b. Must support encoding (.getEncoded())
     * 3. If SecretKey object:
     *      a. Must by of format "RAW"
     *      b. Must support encoding (.getEncoded())
     *
     * @param key Key object to check if supported
     *
     * @throws KeyStoreException if Key object is not supported
     */
    private void checkKeyIsSupported(Key key) throws KeyStoreException {

        if (key == null) {
            throw new KeyStoreException("Input key is null");
        }

        if (key instanceof PrivateKey) {
            if (!key.getFormat().equals("PKCS#8")) {
                throw new KeyStoreException("Only PKCS#8 format PrivateKeys " +
                    "are supported");
            }
            if (key.getEncoded() == null) {
                throw new KeyStoreException("Key does not support encoding");
            }
        }
        else if (key instanceof SecretKey) {
            if (!key.getFormat().equals("RAW")) {
                /* SecretKey should always be of format "RAW", double check */
                throw new KeyStoreException("Only RAW format SecretKeys " +
                    "are supported");
            }
            if (key.getEncoded() == null) {
                throw new KeyStoreException("Key does not support encoding");
            }
        }
        else {
            throw new KeyStoreException("Key must be of type PrivateKey " +
                "or SecretKey, unsupported type");
        }
    }

    /**
     * Internal method to check that this is a supported Certificate chain.
     *
     * Current checks include:
     *   1. Chain is not null or a zero length array
     *   2. Chain is made up of X509Certificate objects
     *   3. Chain cert signatures are correct as we walk up the chain
     *
     * The certificate chain should be ordered from leaf cert (entity) to
     * top-most intermedate certificate.
     *
     * @param chain Certificate chain to check
     *
     * @throws KeyStoreException if Certificate array is not supported
     */
    private void checkCertificateChain(Certificate[] chain)
        throws KeyStoreException {

        int i = 0;
        byte[] encodedCert = null;

        if (chain == null || chain.length == 0) {
            throw new KeyStoreException("Certificate chain must not " +
                "be null or empty when storing PrivateKey");
        }

        for (Certificate cert : chain) {
            if (!(cert instanceof X509Certificate)) {
                throw new KeyStoreException("Certificate chain objects must " +
                    "be of type X509Certificate");
            }
        }

        if (chain.length > 1) {
            /* Use wolfSSL CertManager to verify chain cert signatures match */
            WolfSSLCertManager cm = new WolfSSLCertManager();

            /* Load first chain cert as trusted (we don't have the
             * root CA available to verify full chain at this point */
            try {
                encodedCert = chain[chain.length-1].getEncoded();
                cm.CertManagerLoadCABuffer(encodedCert, encodedCert.length,
                    WolfCrypt.SSL_FILETYPE_ASN1);
            } catch (WolfCryptException | CertificateEncodingException e) {
                cm.free();
                throw new KeyStoreException(
                    "Error checking cert chain integrity, loading " +
                    "chain[" + chain.length + "]");
            }

            try {
                for (i = chain.length-2; i > 0; i--) {
                    encodedCert = chain[i].getEncoded();
                    /* Verify chain cert first against loaded CAs */
                    cm.CertManagerVerifyBuffer(encodedCert, encodedCert.length,
                        WolfCrypt.SSL_FILETYPE_ASN1);

                    if (i > 0) {
                        /* If verification passes, load as trusted */
                        cm.CertManagerLoadCABuffer(encodedCert,
                            encodedCert.length,
                            WolfCrypt.SSL_FILETYPE_ASN1);
                    }
                }
            } catch (WolfCryptException | CertificateEncodingException e) {
                cm.free();
                throw new KeyStoreException(
                    "Certificate chain invalid", e);
            }

            cm.free();
        }
    }

    /**
     * Internal method to check that an X509Certificate matches the provided
     * private key.
     *
     * @param cert X.509 certificate to check, which should match PrivateKey
     * @param key PrivateKey to check against certificate
     *
     * @throws KeyStoreException if leaf cert does not match private key
     */
    private void checkCertificateChainMatchesPrivateKey(
        X509Certificate cert, PrivateKey key) throws KeyStoreException {

        boolean match = false;
        byte[] derCert = null;
        byte[] pkcs8Key = null;

        if (cert == null || key == null) {
            throw new KeyStoreException("Certificate or PrivateKey is null");
        }

        try {
            derCert = cert.getEncoded();
            if (derCert == null || derCert.length == 0) {
                throw new KeyStoreException("Bad X509Certificate DER encoding");
            }
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException(e);
        }

        if (!key.getFormat().equals("PKCS#8") &&
            !key.getFormat().equals("PKCS8")) {
            throw new KeyStoreException("PrivateKey encoding not type PKCS#8");
        }

        pkcs8Key = key.getEncoded();
        if (pkcs8Key == null || pkcs8Key.length == 0) {
            throw new KeyStoreException("Bad PrivateKey PKCS#8 encoding");
        }

        match = X509CheckPrivateKey(derCert, pkcs8Key);
        if (!match) {
            throw new KeyStoreException("X509Certificate does not match " +
                "provided private key");
        }
    }

    /**
     * Assign the given key to an alias and protects it using the
     * provided password.
     *
     * If the key is of type java.security.PrivateKey, it must be accompanied
     * by a certificate chain which includes the corresponding public key.
     *
     * If the key is of type javax.crypto.SecretKey, no certificate chain
     * should be provided.
     *
     * If the alias already exists, the existing entry is overwritten
     * with the provided key (and cert chain if applicable).
     *
     * @param alias the alias name to associate and store
     * @param key the key to be associated with alias
     * @param password the password used to protect the key. Password cannot
     *        be null, but can be empty array. If wolfCrypt FIPS is used,
     *        this will cause an error since the minimum HMAC key length is
     *        14, meaning passwords must be at least 14 characters for use
     *        with this KeyStore and wolfCrypt FIPS.
     * @param chain the cert chain for the corresponding public key - only
     *        required if the key is of type java.security.PrivateKey
     *
     * @throws KeyStoreException if the key cannot be protected or the
     *         operation fails.
     */
    @Override
    public synchronized void engineSetKeyEntry(String alias, Key key,
        char[] password, Certificate[] chain) throws KeyStoreException {

        byte[] encodedKey = null;
        WKSPrivateKey privKey = null;
        WKSSecretKey secretKey = null;

        if (alias == null) {
            throw new KeyStoreException("Alias cannot be null");
        }

        if (key == null) {
            throw new KeyStoreException("Key cannot be null");
        }

        if (password == null) {
            throw new KeyStoreException("Password cannot be null");
        }

        checkKeyIsSupported(key);

        /* PKCS#8 private key (PrivateKey) or raw key bytes (SecretKey) */
        encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length == 0) {
            throw new KeyStoreException(
                "Error getting encoded key bytes from Key");
        }

        try {
            if (key instanceof PrivateKey) {
                log("inserting PrivateKey at alias: " + alias);

                /* Sanity check on cert chain, chain is required */
                checkCertificateChain(chain);

                /* Verify private key matches leaf cert */
                checkCertificateChainMatchesPrivateKey(
                    (X509Certificate)chain[0], (PrivateKey)key);

                /* Protect key and store inside new WKSPrivateKey object,
                 * throws KeyStoreException on error */
                privKey = new WKSPrivateKey(encodedKey, password,
                    chain, this.rand);

                /* Store entry into map */
                entries.put(alias, privKey);
            }
            else if (key instanceof SecretKey) {
                log("inserting SecretKey at alias: " + alias);

                /* Protect secret key inside WKSSecretKey object */
                secretKey = new WKSSecretKey(encodedKey, password,
                    key.getAlgorithm(), this.rand);

                /* Store entry into map */
                entries.put(alias, secretKey);
            }

        } finally {
            /* Zero out encoded key array */
            Arrays.fill(encodedKey, (byte)0);
        }

        return;
    }

    /**
     * Assign the given key to the provided alias, where the key has already
     * been protected.
     *
     * This method is not supported by this KeyStore implementation since
     * key protection method would not normally be known/used by external
     * parties without using this KeyStore.
     *
     * @param alias the alias name to associate and store
     * @param key the key to be associated with the alias, already in
     *        protected format.
     * @param chain the cert chain for the corresponding public key - only
     *        required if the key is of type java.security.PrivateKey
     *
     * @throws KeyStoreException if the operation fails
     */
    @Override
    public synchronized void engineSetKeyEntry(String alias, byte[] key,
        Certificate[] chain) throws KeyStoreException {

        throw new UnsupportedOperationException(
            "WolfSSLKeyStore does not support storing already protected keys");
    }

    /**
     * Assign a certificate to the provided alias.
     *
     * If the alias already holds an existing entry created by
     * setCertificateEntry() that trusted certificate is overwritten.
     *
     * If the alias already holds an existing entry which is a private key,
     * a KeyStoreException will be thrown since this method cannot overwrite
     * a private key entry.
     *
     * @param alias the alias name to map and store this certificate into
     * @param cert the certificate to store and associate with alias
     *
     * @throws KeyStoreException if the alias alreday exists and does not
     *         identify an entry containing a trusted certificate, or this
     *         method fails.
     */
    @Override
    public synchronized void engineSetCertificateEntry(String alias,
        Certificate cert) throws KeyStoreException {

        Object entry = entries.get(alias);
        if (entry instanceof WKSPrivateKey) {
            throw new KeyStoreException("Cannot overwrite private key entry");
        }

        log("inserting Certificate at alias: " + alias);

        WKSCertificate obj = new WKSCertificate();
        obj.cert = cert;
        obj.creationDate = new Date();

        entries.put(alias, obj);
    }

    /**
     * Delete the entry associated with the provided alias.
     *
     * @param alias the alias used to delete matching entry
     *
     * @throws KeyStoreException if the operation fails
     */
    @Override
    public synchronized void engineDeleteEntry(String alias)
        throws KeyStoreException {

        log("deleting entry at alias: " + alias);

        entries.remove(alias);
    }

    /**
     * Return enumeration of all alias names in this KeyStore.
     *
     * @return enumeration of all aliases
     */
    @Override
    public synchronized Enumeration<String> engineAliases() {

        log("returning all alias names in KeyStore");

        return entries.keys();
    }

    /**
     * Check if an alias is in this KeyStore.
     *
     * @param alias the alias name to check
     *
     * @return true if alias is in KeyStore, otherwise false
     */
    @Override
    public synchronized boolean engineContainsAlias(String alias) {

        log("checking if KeyStore contains alias: " + alias);

        return entries.containsKey(alias);
    }

    /**
     * Return the total number of entries in this KeyStore.
     *
     * @return number of entries
     */
    @Override
    public synchronized int engineSize() {

        log("returning size of KeyStore: " + entries.size());

        return entries.size();
    }

    /**
     * Check if entry associated with alias is a private key entry.
     *
     * Checks if the alias was created by a call to setKeyEntry() with
     * the key object of either PrivateKey or SecretKey.
     *
     * @param alias the alias to check
     *
     * @return true if entry is a key, otherwise false if not a
     *         private key entry or alias does not exist
     */
    @Override
    public synchronized boolean engineIsKeyEntry(String alias) {

        Object entry;
        boolean isKey = false;

        entry = entries.get(alias);
        if ((entry != null) &&
            (entry instanceof WKSPrivateKey ||
             entry instanceof WKSSecretKey)) {
            isKey = true;
        }
        else {
            isKey = false;
        }

        log("checking if alias (" + alias + ") is key: " + isKey);

        return isKey;
    }

    /**
     * Check if entry associated with alias is a certificate entry.
     *
     * Checks if the alias was created by a call to setCertificateEntry().
     *
     * @param alias the alias to check
     *
     * @return true if entry is a certificate, otherwise false if not a
     *         certificate entry or alias does not exist
     */
    @Override
    public synchronized boolean engineIsCertificateEntry(String alias) {

        Object entry = null;
        boolean isCert = false;

        entry = entries.get(alias);
        if ((entry != null) && (entry instanceof WKSCertificate)) {
            isCert = true;
        }
        else {
            isCert = false;
        }

        log("checking if alias (" + alias + ") is certificate: " + isCert);

        return isCert;
    }

    /**
     * Return the alias name of the first KeyStore entry that matches the
     * given certificate.
     *
     * If a KeyStore entry was created with setCertificateEntry(), the provided
     * certificate is compared to that entry's certificate.
     *
     * If a KeyStore entry was created with setKeyEntry(), then the certificate
     * provided is compared to the first element of the certificate chain
     * in the key entry's chain.
     *
     * @param cert the certificate to use for matching
     *
     * @return the alias name of the first entry that matches the provided
     *         certificate, or null if no entry is found.
     */
    @Override
    public synchronized String engineGetCertificateAlias(Certificate cert) {

        Certificate tmp = null;

        if (cert == null) {
            return null;
        }

        for (Map.Entry<String, Object> entry : entries.entrySet()) {
            if (entry.getValue() instanceof WKSCertificate) {
                tmp = ((WKSCertificate)entry.getValue()).cert;
            }
            else if ((entry.getValue() instanceof WKSPrivateKey) &&
                     (((WKSPrivateKey)entry.getValue()).chain != null)) {
                tmp = ((WKSPrivateKey)entry.getValue()).chain[0];
            }

            if ((tmp != null) && tmp.equals(cert)) {
                return entry.getKey();
            }
        }

        return null;
    }

    /**
     * Store this KeyStore into the provided OutputStream, protecting the
     * KeyStore integrity with the given password.
     *
     * KeyStore integrity is protected with PBKDF2-HMAC-SHA512 and HMAC-SHA512.
     *
     * @param stream OutputStream to write this KeyStore to
     * @param password password used to generate the keystore integrity check
     *
     * @throws IOException on I/O problem
     * @throws NoSuchAlgorithmException if integrity algorithm can't be
     *         found
     * @throws CertificateException if any of the certificates in this
     *         KeyStore could not be stored
     */
    @Override
    public synchronized void engineStore(OutputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {

        byte[] encoded = null;
        byte[] derivedKey = null;
        byte[] hmac = null;
        byte[] encodedEntry = null;
        byte[] salt = new byte[WKS_PBKDF2_SALT_SIZE];
        Mac mac = null;
        SecretKeySpec keySpec = null;
        ByteArrayOutputStream bos = null;
        DataOutputStream dos = null;
        WKSPrivateKey keyEntry = null;
        WKSSecretKey sKeyEntry = null;
        WKSCertificate certEntry = null;

        if (stream == null || password == null || password.length == 0) {
            throw new IllegalArgumentException(
                "OutputStream and password cannot be null");
        }

        log("storing KeyStore to OutputStream");

        try {
            bos = new ByteArrayOutputStream();
            dos = new DataOutputStream(bos);

            /* magic number */
            dos.writeInt(WKS_MAGIC_NUMBER);

            /* keystore version */
            log("KeyStore version: " + WKS_STORE_VERSION);
            dos.writeInt(WKS_STORE_VERSION);

            /* entry count */
            log("KeyStore entry count: " + entries.size());
            dos.writeInt(entries.size());

            /* write out entries */
            for (Map.Entry<String, Object> entry : entries.entrySet()) {
                if (entry.getValue() instanceof WKSPrivateKey) {
                    keyEntry = (WKSPrivateKey)entry.getValue();

                    log("storing PrivateKey: " + entry.getKey());

                    /* entry ID */
                    dos.writeInt(WKS_ENTRY_ID_PRIVATE_KEY);

                    /* alias */
                    dos.writeUTF(entry.getKey());

                    /* encoded WKSPrivateKey length and bytes */
                    encodedEntry = keyEntry.getEncoded(true);
                    dos.writeInt(encodedEntry.length);
                    dos.write(encodedEntry);
                    Arrays.fill(encodedEntry, (byte)0);
                }
                else if (entry.getValue() instanceof WKSCertificate) {
                    certEntry = (WKSCertificate)entry.getValue();

                    log("storing Certificate: " + entry.getKey());

                    /* entry ID */
                    dos.writeInt(WKS_ENTRY_ID_CERTIFICATE);

                    /* alias */
                    dos.writeUTF(entry.getKey());

                    /* encoded WKSCertificate length and bytes */
                    encodedEntry = certEntry.getEncoded();
                    dos.writeInt(encodedEntry.length);
                    dos.write(encodedEntry);
                    Arrays.fill(encodedEntry, (byte)0);
                }
                else if (entry.getValue() instanceof WKSSecretKey) {
                    sKeyEntry = (WKSSecretKey)entry.getValue();

                    log("storing SecretKey: " + entry.getKey());

                    /* entry ID */
                    dos.writeInt(WKS_ENTRY_ID_SECRET_KEY);

                    /* alias */
                    dos.writeUTF(entry.getKey());

                    /* encoded WKSSecretKey length and bytes */
                    encodedEntry = sKeyEntry.getEncoded(true);
                    dos.writeInt(encodedEntry.length);
                    dos.write(encodedEntry);
                    Arrays.fill(encodedEntry, (byte)0);
                }
                else {
                    throw new IOException(
                        "Encountered unsupported entry type when " +
                        "storing KeyStore");
                }
            }

            /* Generate random PBKDF2 salt */
            synchronized (randLock) {
                if (this.rand == null) {
                    this.rand = new SecureRandom();
                }
                rand.nextBytes(salt);
            }

            /* Write salt length and salt */
            dos.writeInt(salt.length);
            dos.write(salt);

            /* Write PBKDF2 iterations */
            dos.writeInt(WKS_PBKDF2_ITERATION_COUNT);

            /* Get encoded bytes up to this point */
            dos.flush();
            encoded = bos.toByteArray();

            /* Derive HMAC key from password with PBKDF2 */
            log("deriving HMAC-SHA512 key with PKCS#5 PBKDF2-HMAC-SHA512");
            derivedKey = Pwdbased.PBKDF2(
                WolfCryptSecretKeyFactory.passwordToByteArray(password),
                salt, WKS_PBKDF2_ITERATION_COUNT, WKS_HMAC_KEY_LENGTH,
                WKS_PBKDF2_TYPE);
            if (derivedKey == null) {
                throw new IOException("Error deriving key with PBKDF2");
            }

            /* Calculate HMAC-SHA512 of output array, hard coding use of
             * wolfJCE provider to guarantee use when using wolfCrypt FIPS */
            log("calculating HMAC-SHA512 for KeyStore integrity");
            try {
                keySpec = new SecretKeySpec(derivedKey, "SHA512");

                mac = Mac.getInstance("HmacSHA512", "wolfJCE");
                mac.init(keySpec);
                mac.update(encoded);
                hmac = mac.doFinal();

            } catch (NoSuchProviderException e) {
                throw new IOException("No Mac.HmacSHA512 found for wolfJCE");
            } catch (InvalidKeyException e) {
                throw new IOException("Invalid HmacSHA512 key");
            }

            /* Write HMAC to end of encoded store */
            dos.writeInt(hmac.length);
            dos.write(hmac);

            dos.flush();

            /* Write final array to provided OutputStream */
            stream.write(bos.toByteArray());

        } finally {
            dos.close();
            if (encoded != null) {
                Arrays.fill(encoded, (byte)0);
            }
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte)0);
            }
            if (hmac != null) {
                Arrays.fill(hmac, (byte)0);
            }
        }

        log("KeyStore successfully stored to OutputStream");

        return; 
    }

    /**
     * Internal InputStream class used to buffer input data and generate
     * an HMAC-SHA512 integrity check over that data.
     *
     * All data passing though this InputStream will be cached internally
     * for use in HMAC computation, unless data caching is disabled by
     * calling enableCaching(false). If caching is disabled, no future
     * data will be stored until caching is re-enabled.
     */
    private class BufferedPbkdf2HmacInputStream extends InputStream {

        /* InputStream from which data will be read */
        private InputStream is = null;

        /* Internal OutputStream where all bytes read will be written
         * to be cached for later HMAC operation */
        private ByteArrayOutputStream bos = null;

        /* Used to pause caching of data if needed, otherwise all bytes
         * read will be copied and stored into ByteArrayOutputStream */
        private boolean cacheData = true;

        public BufferedPbkdf2HmacInputStream(InputStream stream) {

            if (stream == null) {
                throw new IllegalArgumentException(
                    "InputStream and password cannot be null");
            }

            this.is = stream;
            this.bos = new ByteArrayOutputStream();

        }

        @Override
        public synchronized int read() throws IOException {

            int rByte = this.is.read();

            if (this.cacheData && rByte != -1) {
                bos.write(rByte);
            }
            return rByte;
        }

        @Override
        public synchronized void close() throws IOException {

            if (this.bos != null) {
                this.bos.reset();
                this.bos.close();
            }

            super.close();
        }

        /**
         * Enable or disable caching of data inside this InputStream.
         *
         * Caching is enabled by default, unless explicitly disabled.
         *
         * @param enabled boolean value to enable or disable input caching
         */
        public synchronized void enableCaching(boolean enabled) {
            this.cacheData = enabled;
        }

        /**
         * Generate HMAC-SHA512 over cached data, deriving HMAC key from
         * provided password using PBKDF2-HMAC-SHA512.
         *
         * @param password password to use for HMAC key generation
         * @param salt salt to use for PBKDF2 key derivation, cannot be null
         * @param iterations iterations to use for PBKDF2
         *
         * @return HMAC-SHA512 of data cached by this InputStream so far
         *
         * @throws IOException on error getting cached data internally
         */
        public synchronized byte[] generatePbkdf2Hmac(char[] password,
            byte[] salt, int iterations) throws IOException {

            Mac mac = null;
            SecretKeySpec keySpec = null;
            byte[] derivedKey = null;
            byte[] buffered = null;
            byte[] hmac = null;

            if (password == null || password.length == 0 ||
                salt == null || salt.length == 0 ||
                iterations < WKS_PBKDF2_MIN_ITERATIONS) {
                throw new IOException("Invalid password, salt, or iterations");
            }

            /* Derive HMAC key from password using PBKDF2 */
            derivedKey = Pwdbased.PBKDF2(
                WolfCryptSecretKeyFactory.passwordToByteArray(password),
                salt, iterations, WKS_HMAC_KEY_LENGTH, WKS_PBKDF2_TYPE);
            if (derivedKey == null) {
                throw new IOException("Error deriving key with PBKDF2");
            }

            /* Get full byte array to generate HMAC over */
            buffered = bos.toByteArray();

            /* Calculate HMAC-SHA512 of output array, hard coding use of
             * wolfJCE provider here to guarantee use when using FIPS */
            try {
                keySpec = new SecretKeySpec(derivedKey, "SHA512");

                mac = Mac.getInstance("HmacSHA512", "wolfJCE");
                mac.init(keySpec);
                mac.update(buffered);
                hmac = mac.doFinal();

            } catch (NoSuchProviderException e) {
                throw new IOException("No Mac.HmacSHA512 found for wolfJCE");

            } catch (NoSuchAlgorithmException e) {
                throw new IOException("No Mac.HmacSHA512 found in wolfJCE");

            } catch (InvalidKeyException e) {
                throw new IOException("Invalid HmacSHA512 key");

            } finally {
                if (buffered != null) {
                    Arrays.fill(buffered, (byte)0);
                }
            }

            return hmac;
        }
    }

    /**
     * Load the KeyStore from the provided InputStream.
     *
     * @param stream InputStream from which to load KeyStore
     * @param password password used to check KeyStore integrity, must not
     *        be null
     *
     * @throws IOException on I/O problem or issue with the
     *         KeyStore data format
     * @throws NoSuchAlgorithmException if algorithm used to check the
     *         KeyStore integrity cannot be found
     * @throws CertificateException if any of the certificates in the
     *         KeyStore could not be loaded
     */
    @Override
    public synchronized void engineLoad(InputStream stream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {

        int i;
        int tmp = 0;
        int entryCount = 0;
        int entryType = 0;
        int encodedLen = 0;
        int bytesRead = 0;
        int saltLen = 0;
        int hmacLen = 0;
        int iterations = 0;
        byte[] streamBytes = null;
        byte[] encodedEntry = null;
        byte[] salt = null;
        byte[] hmac = null;
        byte[] genHmac = null;
        boolean havePass = true;

        String alias = null;
        BufferedPbkdf2HmacInputStream his = null;
        DataInputStream dis = null;

        WKSPrivateKey keyEntry = null;
        WKSSecretKey sKeyEntry = null;
        WKSCertificate certEntry = null;

        log("loading KeyStore from InputStream");

        if (password == null || password.length == 0) {
            havePass = false;
            log("KeyStore password not provided, HMAC integrity check " +
                "will be skipped");
        }

        if (stream == null) {
            return;
        }

        try {
            if (havePass) {
                his = new BufferedPbkdf2HmacInputStream(stream);
                dis = new DataInputStream(his);
            }
            else {
                dis = new DataInputStream(stream);
            }

            /* magic number */
            tmp = dis.readInt();
            if (tmp != WKS_MAGIC_NUMBER) {
                throw new IOException(
                    "Invalid magic number ( " + tmp + "), " +
                    "KeyStore not of type WKS");

            }

            /* store version */
            tmp = dis.readInt();
            if (tmp != WKS_STORE_VERSION) {
                throw new IOException(
                    "Invalid WKS KeyStore version: " + tmp);
            }
            log("KeyStore version: " + tmp);

            /* total entry count */
            entryCount = dis.readInt();
            if (entryCount < 0) {
                throw new IOException("Invalid entry count, negative");
            }
            log("KeyStore entry count: " + entryCount);

            for (i = 0; i < entryCount; i++) {
                /* entry type */
                entryType = dis.readInt();
                if (entryType < 0) {
                    throw new IOException("Invalid entry type, negative");
                }

                /* alias */
                alias = dis.readUTF();

                /* encoded entry length */
                encodedLen = dis.readInt();
                if (encodedLen < 0) {
                    throw new IOException("Invalid encoded length, negative");
                }

                /* encoded entry */
                encodedEntry = new byte[encodedLen];
                bytesRead = dis.read(encodedEntry);
                if (bytesRead != encodedLen) {
                    throw new IOException(
                        "Unable to read total encoded entry byte array");
                }

                switch (entryType) {
                    case WKS_ENTRY_ID_PRIVATE_KEY:
                        log("loading PrivateKey: " + alias);
                        keyEntry = new WKSPrivateKey(encodedEntry);
                        entries.put(alias, keyEntry);
                        break;

                    case WKS_ENTRY_ID_SECRET_KEY:
                        log("loading SecretKey: " + alias);
                        sKeyEntry = new WKSSecretKey(encodedEntry);
                        entries.put(alias, sKeyEntry);
                        break;

                    case WKS_ENTRY_ID_CERTIFICATE:
                        log("loading Certificate: " + alias);
                        certEntry = new WKSCertificate(encodedEntry);
                        entries.put(alias, certEntry);
                        break;

                    default:
                        throw new IOException(
                            "Invalid entry type found: " + entryType);
                }
            }

            /* PBKDF2 salt len and salt */
            saltLen = dis.readInt();
            if (saltLen != WKS_PBKDF2_SALT_SIZE) {
                throw new IOException("Invalid salt size: " + saltLen);
            }

            salt = new byte[saltLen];
            saltLen = dis.read(salt);
            if (saltLen != WKS_PBKDF2_SALT_SIZE) {
                throw new IOException("Failed to read entire salt from WKS");
            }

            /* PBKDF2 iterations */
            iterations = dis.readInt();
            if (iterations < WKS_PBKDF2_MIN_ITERATIONS) {
                throw new IOException(
                    "PBKDF2 iterations too small: " + iterations);
            }

            /* Pause caching of input data, HMAC itself not included in HMAC */
            if (havePass) {
                his.enableCaching(false);
            }

            /* HMAC len and HMAC */
            hmacLen = dis.readInt();
            if (hmacLen < 0) {
                throw new IOException("Invalid HMAC length, negative");
            }
            hmac = new byte[hmacLen];
            hmacLen = dis.read(hmac);
            if (hmacLen != hmac.length) {
                throw new IOException(
                    "Failed to read entire HMAC from WKS stream");
            }

            /* Regenerate HMAC-SHA512 over bytes read so far */
            if (havePass) {
                genHmac = his.generatePbkdf2Hmac(password, salt, iterations);
                if (genHmac == null || genHmac.length == 0) {
                    throw new IOException(
                        "Unable to generate HMAC-SHA512 over input WKS stream");
                }

                if (!WolfCrypt.ConstantCompare(hmac, genHmac)) {
                    throw new IOException("Integrity check failed on WKS, " +
                        "KeyStore has been tampered with!");
                }

                log("HMAC-SHA512 integrity verification successful");
            }
            else {
                log("HMAC-SHA512 integrity verification skipped, " +
                    "no password provided");
            }

        } finally {
            if (dis != null) {
                dis.close();
            }
        }

        log("KeyStore successfully loaded from InputStream");

        return;
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private static synchronized void log(String msg) {
        if (debug.DEBUG) {
            debug.print("[WolfSSLKeyStore] " + msg);
        }
    }

    /**
     * Inner class representing a private key entry.
     *
     * When encoded to a byte[] for storage (getEncoded()), the following
     * format is used. Items are written out through DataOutputStream
     * backed by ByteArrayOutputStream, thus long values are stored
     * to 8 bytes big endian, int is 4 bytes big endian, etc.
     *
     * The HMAC-SHA512 at the end is calculated over all items above it along
     * with their lengths.
     *
     *   creationDate.getTime()          (long | 8 bytes)
     *   kdfSalt.length                  (int | 4 bytes)
     *   kdfSalt                         (byte[])
     *   kdfIterations                   (int | 4 bytes)
     *   iv.length                       (int | 4 bytes)
     *   iv                              (byte[])
     *   encryptedKey.length             (int | 4 bytes)
     *   encryptedKey                    (byte[])
     *   chain.length                    (int | 4 bytes)
     *   FOR EACH CERT:
     *     chain[i].getType()            (UTF String)
     *     chain[i].getEncoded().length  (int | 4 bytes)
     *     chain[i].getEncoced()         (byte[])
     *   hmac.length                     (int | 4 bytes)
     *   hmac                            (byte[])
     */
    private static class WKSPrivateKey {

        byte[] encryptedKey;    /* protected/encrypted key */
        byte[] iv;              /* AES-GCM IV */
        byte[] kdfSalt;         /* PBKDF2 salt */
        int kdfIterations;      /* PBKDF2 iterations */
        Certificate[] chain;    /* cert chain matching this private key */
        Date creationDate;      /* creation date for this object */
        byte[] hmacSha512;      /* HMAC calculated over members and lengths */

        protected WKSPrivateKey() {
        }

        /**
         * Create new WKSPrivateKey from plaintext key and certificate chain,
         * encrypt/protect plaintext key using provided password.
         *
         * @param plainKey unencrypted private key to protect/encrypt inside
         *        this object
         * @param password password to be used for key protection
         * @param chain Certificate array containing cert chain matching key
         *
         * @throws IllegalArgumentException if input arguments are null
         * @throws KeyStoreException if encrypting/protecting private key fails
         */
        protected WKSPrivateKey(byte[] plainKey, char[] password,
            Certificate[] chain, SecureRandom rand)
            throws IllegalArgumentException, KeyStoreException {

            byte[] derivedKey = null;
            byte[] protectedKey = null;
            byte[] hmac = null;
            byte[] kek = new byte[WKS_ENC_KEY_LENGTH];
            byte[] hmacKey = new byte[WKS_HMAC_KEY_LENGTH];
            byte[] encoded = null;
            SecureRandom rng = rand;

            if (plainKey == null || plainKey.length == 0 ||
                password == null || password.length == 0 ||
                chain == null || chain.length == 0) {
                throw new IllegalArgumentException(
                    "Invalid null arguments when creating WKSPrivateKey");
            }

            /* Generate random salt and IV */
            this.kdfSalt = new byte[WKS_PBKDF2_SALT_SIZE];
            this.iv = new byte[WKS_ENC_IV_LENGTH];

            synchronized (randLock) {
                if (rng == null) {
                    rng = new SecureRandom();
                }
                rng.nextBytes(this.kdfSalt);
                rng.nextBytes(this.iv);
            }

            try {
                /* Derive key encryption key from password using
                 * PBKDF2-HMAC-SHA512. Generate a 96 byte key in total, split
                 * between 32-byte AES-CBC-256 and 64-byte HMAC-SHA512 keys */
                derivedKey = deriveKeyFromPassword(password, this.kdfSalt,
                    WKS_PBKDF2_ITERATION_COUNT,
                    WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH);

                if (derivedKey == null) {
                    throw new KeyStoreException(
                        "Error deriving key encryption key, got null key");
                }
                if (derivedKey.length !=
                    (WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH)) {
                    throw new KeyStoreException(
                        "Error deriving key encryption key, wrong length. " +
                        " actual: " + derivedKey.length + ", needed: " +
                        (WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH));
                }

                /* Split key into encrypt + HMAC keys, erase derivedKey */
                System.arraycopy(derivedKey, 0, kek, 0, kek.length);
                System.arraycopy(derivedKey, kek.length, hmacKey, 0,
                    hmacKey.length);
                Arrays.fill(derivedKey, (byte)0);

                /* Encrypt plain key with KEK */
                protectedKey = encryptKey(plainKey, kek, this.iv);
                if (protectedKey == null) {
                    throw new KeyStoreException(
                        "Failed to encrypt plaintext key");
                }

                this.encryptedKey = protectedKey;
                this.kdfIterations = WKS_PBKDF2_ITERATION_COUNT;
                this.chain = chain.clone();
                this.creationDate = new Date();

                /* Get encoded byte[] of object class variables without HMAC */
                encoded = getEncoded(false);
                if (encoded == null) {
                    throw new KeyStoreException(
                        "Failed to get encoded WKSPrivateKey for HMAC gen");
                }

                /* Generate internal HMAC over object contents */
                hmac = generateHmac(hmacKey, encoded);
                if (hmac == null) {
                    throw new KeyStoreException(
                        "Failed to generate HMAC over WKSPrivateKey");
                }

                this.hmacSha512 = hmac;

            } catch (KeyStoreException | IOException |
                     CertificateEncodingException e) {
                /* Clear protected key and HMAC in case of error */
                if (protectedKey != null) {
                    Arrays.fill(protectedKey, (byte)0);
                }
                if (hmac != null) {
                    Arrays.fill(hmac, (byte)0);
                }
                throw new KeyStoreException(e);

            } finally {
                /* Clear local KEK, HMAC key, and encoded content */
                Arrays.fill(kek, (byte)0);
                Arrays.fill(hmacKey, (byte)0);
                if (encoded != null) {
                    Arrays.fill(encoded, (byte)0);
                }
            }
        }

        /**
         * Create new WKSPrivateKey object from encoded byte array.
         *
         * @param encoded encoded byte array which was created by
         *        calling WKSPrivateKey getEncoded() method.
         *
         * @throws IOException on error reading/parsing encoded array
         */
        protected WKSPrivateKey(byte[] encoded)
            throws IOException, CertificateException {

            int i;
            int tmp = 0;
            byte[] tmpArr = null;
            String tmpStr = null;
            ByteArrayInputStream bis = null;
            ByteArrayInputStream certStream = null;
            DataInputStream dis = null;
            CertificateFactory cf = null;
            Certificate tmpCert = null;

            if (encoded == null || encoded.length == 0) {
                throw new IllegalArgumentException(
                    "Input byte array cannot be null");
            }

            try {
                bis = new ByteArrayInputStream(encoded);
                dis = new DataInputStream(bis);

                /* creationDate */
                this.creationDate = new Date(dis.readLong());

                /* kdfSalt */
                tmp = dis.readInt();
                if (tmp != WKS_PBKDF2_SALT_SIZE) {
                    throw new IOException(
                        "Invalid PBKDF2 salt size: " + tmp);
                }
                this.kdfSalt = new byte[tmp];
                dis.read(this.kdfSalt);

                /* kdfIterations */
                tmp = dis.readInt();
                if (tmp < WKS_PBKDF2_MIN_ITERATIONS) {
                    throw new IOException(
                        "PBKDF2 iterations too small: " + tmp);
                }
                this.kdfIterations = tmp;

                /* iv */
                tmp = dis.readInt();
                if (tmp != WKS_ENC_IV_LENGTH) {
                    throw new IOException(
                        "Invalid IV size: " + tmp);
                }
                this.iv = new byte[tmp];
                dis.read(this.iv);

                /* encrypted key */
                tmp = dis.readInt();
                if (tmp < 0) {
                    throw new IOException(
                        "Bad encrypted key length, negative");
                }
                this.encryptedKey = new byte[tmp];
                dis.read(this.encryptedKey);

                /* chain */
                tmp = dis.readInt();
                if (tmp > WKS_MAX_CHAIN_COUNT) {
                    throw new IOException(
                        "Cert chain count (" + tmp + ") is larger than max " +
                        "allowed (" + WKS_MAX_CHAIN_COUNT + ")");
                }
                this.chain = new Certificate[tmp];

                /* chain certs */
                for (i = 0; i < chain.length; i++) {

                    /* type, get CertificateFactory */
                    tmpStr = dis.readUTF();
                    if ((cf == null) ||
                        ((cf != null) && !cf.getType().equals(tmpStr))) {
                        cf = CertificateFactory.getInstance(tmpStr);
                    }

                    /* encoding length */
                    tmp = dis.readInt();
                    if (tmp < 0) {
                        throw new IOException(
                            "Bad encoding length, negative");
                    }
                    tmpArr = new byte[tmp];

                    /* encoded cert */
                    dis.read(tmpArr);
                    certStream = new ByteArrayInputStream(tmpArr);
                    tmpCert = cf.generateCertificate(certStream);
                    certStream.close();

                    /* add to chain */
                    this.chain[i] = tmpCert;
                }

                /* HMAC-SHA512, not verifying since we don't have password */
                tmp = dis.readInt();
                if (tmp != WKS_HMAC_KEY_LENGTH) {
                    throw new IOException(
                        "HMAC length (" + tmp + ") is different than " +
                        "expected (" + WKS_HMAC_KEY_LENGTH + ")");
                }
                this.hmacSha512 = new byte[tmp];
                dis.read(this.hmacSha512);

            } catch (Exception e) {

                if (this.encryptedKey != null) {
                    Arrays.fill(this.encryptedKey, (byte)0);
                    this.encryptedKey = null;
                }
                if (this.iv != null) {
                    Arrays.fill(this.iv, (byte)0);
                    this.iv = null;
                }
                if (this.kdfSalt != null) {
                    Arrays.fill(this.kdfSalt, (byte)0);
                    this.kdfSalt = null;
                }
                if (this.hmacSha512 != null) {
                    Arrays.fill(this.hmacSha512, (byte)0);
                    this.hmacSha512 = null;
                }
                this.chain = null;
                this.creationDate = null;
                this.kdfIterations = 0;

                throw e;

            } finally {
                if (dis != null) {
                    dis.close();
                }
            }
        }

        /**
         * Get encoded byte array representation of this object, optionally
         * including HMAC over contents appended to end.
         *
         * @param withHMAC include HMAC on end of encoded array when true,
         *        otherwise return encoded object without HMAC. HMAC
         *        is included when writing out / storing, but not included
         *        when we are just using this as a helper function to
         *        check the HMAC value inside this object in memory.
         *
         * @return byte array representing this object or null on error
         * @throws IOException on error writing to output stream
         * @throws CertificateEncodingException on error getting
         *         Certificate encoding
         */
        protected synchronized byte[] getEncoded(boolean withHMAC)
            throws IOException, CertificateEncodingException {

            int i;
            byte[] out = null;
            ByteArrayOutputStream bos = null;
            DataOutputStream dos = null;

            if (this.creationDate == null || this.kdfSalt == null ||
                this.kdfSalt.length == 0 || this.kdfIterations <= 0 ||
                this.iv == null || this.iv.length == 0 ||
                this.encryptedKey == null || this.encryptedKey.length == 0 ||
                this.chain == null) {
                log("invalid WKSPrivateKey class variables, returning null " +
                    "from getEncoded()");
                return null;
            }

            if (withHMAC && (this.hmacSha512 == null ||
                             this.hmacSha512.length == 0)) {
                log("WKSPrivateKey HMAC null or zero length, returning null " +
                    "from getEncoded()");
                return null;
            }

            try {
                bos = new ByteArrayOutputStream();
                dos = new DataOutputStream(bos);

                dos.writeLong(this.creationDate.getTime());
                dos.writeInt(this.kdfSalt.length);
                dos.write(this.kdfSalt, 0, this.kdfSalt.length);
                dos.writeInt(this.kdfIterations);
                dos.writeInt(this.iv.length);
                dos.write(this.iv, 0, this.iv.length);
                dos.writeInt(this.encryptedKey.length);
                dos.write(this.encryptedKey, 0, this.encryptedKey.length);
                dos.writeInt(this.chain.length);
                if (this.chain.length > 0) {
                    for (i = 0; i < this.chain.length; i++) {
                        dos.writeUTF(this.chain[i].getType());
                        dos.writeInt(this.chain[i].getEncoded().length);
                        dos.write(this.chain[i].getEncoded(), 0,
                                  this.chain[i].getEncoded().length);
                    }
                }
                if (withHMAC) {
                    dos.writeInt(this.hmacSha512.length);
                    dos.write(this.hmacSha512);
                }

                dos.flush();
                out = bos.toByteArray();

            } finally {
                if (dos != null) {
                    dos.close();
                }
            }

            return out;
        }

        /**
         * Decrypt and return plaintext key encoded in this object,
         * using provided password.
         *
         * Verifies internally-generated HMAC over WKSPrivateKey object
         * contents using password before decrypting key.
         *
         * Other than password, all other information needed should already
         * be stored in this object.
         *
         * @param password password to use for decryption
         */
        protected synchronized byte[] getDecryptedKey(char[] password)
            throws UnrecoverableKeyException {

            byte[] plain = null;
            byte[] derivedKey = null;
            byte[] hmac = null;
            byte[] kek = new byte[WKS_ENC_KEY_LENGTH];
            byte[] hmacKey = new byte[WKS_HMAC_KEY_LENGTH];
            byte[] encoded = null;

            if (password == null || password.length == 0) {
                throw new UnrecoverableKeyException(
                    "Unable to decrypt key with null password");
            }

            try {
                /* Derive key encryption key from password using
                 * PBKDF2-HMAC-SHA512. Generate a 96 byte key in total, to
                 * split between 32-byte AES-CBC-256 key and 64-byte
                 * HMAC-SHA512 key. */
                derivedKey = deriveKeyFromPassword(password, this.kdfSalt,
                    WKS_PBKDF2_ITERATION_COUNT,
                    WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH);

                if (derivedKey == null) {
                    throw new KeyStoreException(
                        "Error deriving key decryption key, got null key");
                }

                /* Split key into decrypt + HMAC keys, erase derivedKey */
                System.arraycopy(derivedKey, 0, kek, 0, kek.length);
                System.arraycopy(derivedKey, kek.length, hmacKey, 0,
                    hmacKey.length);
                Arrays.fill(derivedKey, (byte)0);

                /* Get encoded byte[] of object class variables without HMAC */
                encoded = getEncoded(false);
                if (encoded == null) {
                    throw new KeyStoreException(
                        "Failed to get encoded WKSPrivateKey for HMAC");
                }

                /* Re-generate internal HMAC over object contents */
                hmac = generateHmac(hmacKey, encoded);
                if (hmac == null) {
                    throw new KeyStoreException(
                        "Failed to regenerate HMAC over WKSPrivateKey");
                }

                /* Verify HMAC first before decrypting key */
                if(!WolfCrypt.ConstantCompare(hmac, this.hmacSha512)) {
                    throw new KeyStoreException(
                        "HMAC verification failed on WKSPrivateKey, entry " +
                        "corrupted");
                } else {
                    log("HMAC verification successful on WKSPrivateKey");
                }

                /* Decrypt encrypted key with KEK */
                plain = decryptKey(this.encryptedKey, kek, this.iv);
                if (plain == null) {
                    throw new UnrecoverableKeyException(
                        "Unable to decrypt protected key");
                }

            } catch (KeyStoreException | IOException |
                     CertificateEncodingException e) {
                if (plain != null) {
                    Arrays.fill(plain, (byte)0);
                }
                throw new UnrecoverableKeyException(e.getMessage());

            } finally {
                Arrays.fill(kek, (byte)0);
                Arrays.fill(hmacKey, (byte)0);
                if (hmac != null) {
                    Arrays.fill(hmac, (byte)0);
                }
                if (encoded != null) {
                    Arrays.fill(encoded, (byte)0);
                }
            }

            return plain;
        }
    }

    /**
     * Inner class representing a single certificate-only entry.
     *
     * When encoded to a byte[] for storage (getEncoded()), the following
     * format is used:
     *
     *   creationDate.getTime()    (long)
     *   cert.getType()            (UTF String)
     *   cert.getEncoded().length  (int)
     *   cert.getEncoced()         (byte[])
     */
    private static class WKSCertificate {

        Certificate cert;
        Date creationDate;

        protected WKSCertificate() {
        }

        /**
         * Create new WKSCertificate object from encoded byte array.
         *
         * @param encoded encoded byte array obtained by calling WKSCertificate
         *        getEncoded() method.
         *
         * @throws IOException on error reading/parsing encoded array
         */
        protected WKSCertificate(byte[] encoded)
            throws IOException, CertificateException {

            int i;
            int tmp = 0;
            byte[] tmpArr = null;
            String tmpStr = null;
            ByteArrayInputStream bis = null;
            ByteArrayInputStream certStream = null;
            DataInputStream dis = null;
            CertificateFactory cf = null;
            Certificate tmpCert = null;

            if (encoded == null || encoded.length == 0) {
                throw new IllegalArgumentException(
                    "Input byte array cannot be null");
            }

            try {
                bis = new ByteArrayInputStream(encoded);
                dis = new DataInputStream(bis);

                /* creationDate */
                this.creationDate = new Date(dis.readLong());

                /* type, get CertificateFactory */
                tmpStr = dis.readUTF();
                if ((cf == null) ||
                    ((cf != null) && !cf.getType().equals(tmpStr))) {
                    cf = CertificateFactory.getInstance(tmpStr);
                }

                /* encoding length */
                tmp = dis.readInt();
                if (tmp < 0) {
                    throw new IOException("Bad encoding length, negative");
                }
                tmpArr = new byte[tmp];

                /* encoded cert */
                dis.read(tmpArr);
                certStream = new ByteArrayInputStream(tmpArr);
                this.cert = cf.generateCertificate(certStream);
                certStream.close();

            } catch (Exception e) {
                this.cert = null;
                this.creationDate = null;
                throw e;

            } finally {
                if (tmpArr != null) {
                    Arrays.fill(tmpArr, (byte)0);
                    tmpArr = null;
                }

                if (dis != null) {
                    dis.close();
                }
            }
        }

        /**
         * Get encoded byte array representation of this object.
         *
         * @return byte array representing this object or null on error
         * @throws IOException on error writing to output stream
         * @throws CertificateEncodingException on error getting
         *         Certificate encoding
         */
        protected synchronized byte[] getEncoded()
            throws IOException, CertificateEncodingException {

            int i;
            byte[] out = null;
            ByteArrayOutputStream bos = null;
            DataOutputStream dos = null;

            if (this.cert == null || this.creationDate == null ||
                this.cert.getEncoded() == null) {
                return null;
            }

            try {
                bos = new ByteArrayOutputStream();
                dos = new DataOutputStream(bos);

                dos.writeLong(this.creationDate.getTime());
                dos.writeUTF(this.cert.getType());
                dos.writeInt(this.cert.getEncoded().length);
                dos.write(this.cert.getEncoded(), 0,
                          this.cert.getEncoded().length);

                dos.flush();
                out = bos.toByteArray();

            } finally {
                if (dos != null) {
                    dos.close();
                }
            }

            return out;
        }
    }

    /**
     * Inner class representing a SecretKey entry.
     *
     * When encoded to a byte[] for storage (getEncoded()), the following
     * format is used. Items are written out through DataOutputStream
     * backed by ByteArrayOutputStream, thus long values are stored
     * to 8 bytes big endian, int is 4 bytes big endian, etc.
     *
     * The HMAC-SHA512 at the end is calculated over all items above it along
     * with their lengths.
     *
     *   creationDate.getTime()          (long | 8 bytes)
     *   key.getAlgorithm()              (UTF String)
     *   kdfSalt.length                  (int | 4 bytes)
     *   kdfSalt                         (byte[])
     *   kdfIterations                   (int | 4 bytes)
     *   iv.length                       (int | 4 bytes)
     *   iv                              (byte[])
     *   encryptedKey.length             (int | 4 bytes)
     *   encryptedKey                    (byte[])
     *   hmac.length                     (int | 4 bytes)
     *   hmac                            (byte[])
     */
    private static class WKSSecretKey {

        byte[] encryptedKey = null; /* protected/encrypted key */
        byte[] iv = null;           /* AES IV */
        byte[] kdfSalt = null;      /* PBKDF2 salt */
        int kdfIterations = 0;      /* PBKDF2 iterations */
        String keyAlgo = null;      /* SecretKey.getAlgorithm() */
        Date creationDate = null;   /* creation date for this object */
        byte[] hmacSha512 = null;   /* HMAC over members and lengths */

        protected WKSSecretKey() {
        }

        /**
         * Create new WKSSecretKey from plaintext key, encrypt/protect using
         * provided password.
         *
         * @param plainKey unencrypted private key to protect/encrypt inside
         *        this object
         * @param password password to be used for key protection
         *
         * @throws IllegalArgumentException if input arguments are null
         * @throws KeyStoreException if encrypting/protecting key fails
         */
        protected WKSSecretKey(byte[] plainKey, char[] password,
            String keyAlgo, SecureRandom rand) throws IllegalArgumentException,
            KeyStoreException {

            byte[] derivedKey = null;
            byte[] protectedKey = null;
            byte[] hmac = null;
            byte[] kek = new byte[WKS_ENC_KEY_LENGTH];
            byte[] hmacKey = new byte[WKS_HMAC_KEY_LENGTH];
            byte[] encoded = null;
            SecureRandom rng = rand;

            if (plainKey == null || plainKey.length == 0 ||
                password == null || password.length == 0 ||
                keyAlgo == null || keyAlgo.isEmpty()) {
                throw new IllegalArgumentException(
                    "Invalid null arguments when creating WKSSecretKey");
            }

            /* Generate random salt and IV */
            this.kdfSalt = new byte[WKS_PBKDF2_SALT_SIZE];
            this.iv = new byte[WKS_ENC_IV_LENGTH];

            synchronized (randLock) {
                if (rng == null) {
                    rng = new SecureRandom();
                }
                rng.nextBytes(this.kdfSalt);
                rng.nextBytes(this.iv);
            }

            try {
                /* Derive key encryption key from password using
                 * PBKDF2-HMAC-SHA512. Generate a 96 byte key in total, split
                 * between 32-byte AES-CBC-256 and 64-byte HMAC-SHA512 keys */
                derivedKey = deriveKeyFromPassword(password, this.kdfSalt,
                    WKS_PBKDF2_ITERATION_COUNT,
                    WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH);
                if (derivedKey == null) {
                    throw new KeyStoreException(
                        "Error deriving key encryption key, got null key");
                }

                /* Split key into encrypt + HMAC keys, erase derivedKey */
                System.arraycopy(derivedKey, 0, kek, 0, kek.length);
                System.arraycopy(derivedKey, kek.length, hmacKey, 0,
                    hmacKey.length);
                Arrays.fill(derivedKey, (byte)0);

                /* Encrypt plain key */
                protectedKey = encryptKey(plainKey, kek, this.iv);
                if (protectedKey == null) {
                    throw new KeyStoreException(
                        "Failed to encrypt plaintext key");
                }

                this.encryptedKey = protectedKey;
                this.kdfIterations = WKS_PBKDF2_ITERATION_COUNT;
                this.keyAlgo = keyAlgo;
                this.creationDate = new Date();

                /* Get encoded byte[] of object class variables without HMAC */
                encoded = getEncoded(false);
                if (encoded == null) {
                    throw new KeyStoreException(
                        "Failed to get encoded WKSSecretKey for HMAC");
                }

                /* Generate internal HMAC over object contents */
                hmac = generateHmac(hmacKey, encoded);
                if (hmac == null) {
                    throw new KeyStoreException(
                        "Failed to generate HMAC over WKSSecretKey");
                }

                this.hmacSha512 = hmac;

            } catch (KeyStoreException | IOException |
                     CertificateEncodingException e) {
                /* Clear protected key and HMAC in case of error */
                if (protectedKey != null) {
                    Arrays.fill(protectedKey, (byte)0);
                }
                if (hmac != null) {
                    Arrays.fill(hmac, (byte)0);
                }
                throw new KeyStoreException(e);

            } finally {
                /* Clear local KEK, HMAC key, and encoded content */
                Arrays.fill(kek, (byte)0);
                Arrays.fill(hmacKey, (byte)0);
                if (encoded != null) {
                    Arrays.fill(encoded, (byte)0);
                }
            }
        }

        /**
         * Create new WKSSecretKey object from encoded byte array.
         *
         * @param encoded encoded byte array obtained by calling WKSPrivateKey
         *        getEncoded() method.
         *
         * @throws IOException on error reading/parsing encoded array
         */
        protected WKSSecretKey(byte[] encoded)
            throws IOException, CertificateException {

            int i = 0;
            int tmp = 0;
            byte[] tmpArr = null;
            String tmpStr = null;
            ByteArrayInputStream bis = null;
            ByteArrayInputStream certStream = null;
            DataInputStream dis = null;

            if (encoded == null || encoded.length == 0) {
                throw new IllegalArgumentException(
                    "Input byte array cannot be null");
            }

            try {
                bis = new ByteArrayInputStream(encoded);
                dis = new DataInputStream(bis);

                /* creationDate */
                this.creationDate = new Date(dis.readLong());

                /* SecretKey algorithm */
                this.keyAlgo = dis.readUTF();

                /* kdfSalt */
                tmp = dis.readInt();
                if (tmp != WKS_PBKDF2_SALT_SIZE) {
                    throw new IOException(
                        "Invalid PBKDF2 salt size: " + tmp);
                }
                this.kdfSalt = new byte[tmp];
                dis.read(this.kdfSalt);

                /* kdfIterations */
                tmp = dis.readInt();
                if (tmp < WKS_PBKDF2_MIN_ITERATIONS) {
                    throw new IOException(
                        "PBKDF2 iterations too small ( " + tmp +
                        "), min size: " + WKS_PBKDF2_MIN_ITERATIONS);
                }
                this.kdfIterations = tmp;

                /* iv */
                tmp = dis.readInt();
                if (tmp != WKS_ENC_IV_LENGTH) {
                    throw new IOException(
                        "Invalid IV size: " + tmp);
                }
                this.iv = new byte[tmp];
                dis.read(this.iv);

                /* encrypted key */
                tmp = dis.readInt();
                if (tmp < 0) {
                    throw new IOException(
                        "Bad encrypted key length, negative");
                }
                this.encryptedKey = new byte[tmp];
                dis.read(this.encryptedKey);

                /* HMAC-SHA512 */
                tmp = dis.readInt();
                if (tmp != WKS_HMAC_KEY_LENGTH) {
                    throw new IOException(
                        "HMAC length (" + tmp + ") different length than " +
                        "expected (" + WKS_HMAC_KEY_LENGTH + ")");
                }
                this.hmacSha512 = new byte[tmp];
                dis.read(this.hmacSha512);

            } catch (Exception e) {

                if (this.encryptedKey != null) {
                    Arrays.fill(this.encryptedKey, (byte)0);
                    this.encryptedKey = null;
                }
                if (this.iv != null) {
                    Arrays.fill(this.iv, (byte)0);
                    this.iv = null;
                }
                if (this.kdfSalt != null) {
                    Arrays.fill(this.kdfSalt, (byte)0);
                    this.kdfSalt = null;
                }
                if (this.hmacSha512 != null) {
                    Arrays.fill(this.hmacSha512, (byte)0);
                    this.hmacSha512 = null;
                }
                this.creationDate = null;
                this.kdfIterations = 0;

                throw e;

            } finally {
                if (dis != null) {
                    dis.close();
                }
            }
        }

        /**
         * Get encoded byte array representation of this object.
         *
         * @param withHMAC include HMAC on end of encoded array when true,
         *        otherwise return encoded object without HMAC. HMAC is
         *        included when writing out / storing, but not included
         *        when we are just using this as a helper method to check
         *        the HMAC value inside this object in memory.
         *
         * @return byte array representing this object or null on error
         * @throws IOException on error writing to output stream
         * @throws CertificateEncodingException on error getting
         *         Certificate encoding
         */
        protected synchronized byte[] getEncoded(boolean withHMAC)
            throws IOException, CertificateEncodingException {

            int i;
            byte[] out = null;
            ByteArrayOutputStream bos = null;
            DataOutputStream dos = null;

            if (this.creationDate == null || this.keyAlgo == null ||
                this.kdfSalt == null || this.kdfSalt.length == 0 ||
                this.kdfIterations <= 0 || this.iv == null ||
                this.iv.length == 0 || this.encryptedKey == null ||
                this.encryptedKey.length == 0) {
                log("invalid WKSSecretKey class variables, returning null " +
                    "from getEncoded()");
                return null;
            }

            if (withHMAC && (this.hmacSha512 == null ||
                             this.hmacSha512.length == 0)) {
                log("WKSSecretKey HMAC null or zero length, returning null " +
                    "from getEncoded()");
                return null;
            }

            try {
                bos = new ByteArrayOutputStream();
                dos = new DataOutputStream(bos);

                dos.writeLong(this.creationDate.getTime());
                dos.writeUTF(this.keyAlgo);
                dos.writeInt(this.kdfSalt.length);
                dos.write(this.kdfSalt, 0, this.kdfSalt.length);
                dos.writeInt(this.kdfIterations);
                dos.writeInt(this.iv.length);
                dos.write(this.iv, 0, this.iv.length);
                dos.writeInt(this.encryptedKey.length);
                dos.write(this.encryptedKey, 0, this.encryptedKey.length);
                if (withHMAC) {
                    dos.writeInt(this.hmacSha512.length);
                    dos.write(this.hmacSha512);
                }

                dos.flush();
                out = bos.toByteArray();

            } finally {
                if (dos != null) {
                    dos.close();
                }
            }

            return out;
        }

        /**
         * Decrypt and return plaintext key using provided password.
         *
         * Verifies internally-generated HMAC over WKSSecretKey object
         * contents using password before decrypting key.
         *
         * Other than password, all other information needed should already
         * be stored in this object.
         *
         * @param password password to use for decryption
         */
        protected synchronized byte[] getDecryptedKey(char[] password)
            throws UnrecoverableKeyException {

            byte[] plain = null;
            byte[] derivedKey = null;
            byte[] hmac = null;
            byte[] kek = new byte[WKS_ENC_KEY_LENGTH];
            byte[] hmacKey = new byte[WKS_HMAC_KEY_LENGTH];
            byte[] encoded = null;

            if (password == null || password.length == 0) {
                throw new UnrecoverableKeyException(
                    "Unable to decrypt key with null password");
            }

            try {
                /* Derive key encryption key from password using
                 * PBKDF2-HMAC-SHA512. Generate a 96 byte key in total, split
                 * between 32-byte AES-CBC-256 and 64-byte HMAC-SHA512 key */
                derivedKey = deriveKeyFromPassword(password, this.kdfSalt,
                    WKS_PBKDF2_ITERATION_COUNT,
                    WKS_ENC_KEY_LENGTH + WKS_HMAC_KEY_LENGTH);

                if (derivedKey == null) {
                    throw new KeyStoreException(
                        "Error deriving key decryption key, got null key");
                }

                /* Split key into decrypt + HMAC keys, erase derivedKey */
                System.arraycopy(derivedKey, 0, kek, 0, kek.length);
                System.arraycopy(derivedKey, kek.length, hmacKey, 0,
                    hmacKey.length);
                Arrays.fill(derivedKey, (byte)0);

                /* Get encoded byte[] of object class variables without HMAC */
                encoded = getEncoded(false);
                if (encoded == null) {
                    throw new KeyStoreException(
                        "Failed to get encoded WKSSecretKey for HMAC");
                }

                /* Re-generate internal HMAC over object contents */
                hmac = generateHmac(hmacKey, encoded);
                if (hmac == null) {
                    throw new KeyStoreException(
                        "Failed to regenerate HMAC over WKSSecretKey");
                }

                /* Verify HMAC first before decrypting key */
                if (!WolfCrypt.ConstantCompare(hmac, this.hmacSha512)) {
                    throw new KeyStoreException(
                        "HMAC verification failed on WKSSecretKey, entry " +
                        "corrupted");
                } else {
                    log("HMAC verification successful on WKSSecretKey");
                }

                /* Decrypt encrypted key with KEK */
                plain = decryptKey(this.encryptedKey, kek, this.iv);
                if (plain == null) {
                    throw new UnrecoverableKeyException(
                        "Unable to decrypt protected key");
                }

            } catch (KeyStoreException | IOException |
                     CertificateEncodingException e) {
                if (plain != null) {
                    Arrays.fill(plain, (byte)0);
                }
                throw new UnrecoverableKeyException(e.getMessage());

            } finally {
                Arrays.fill(kek, (byte)0);
                Arrays.fill(hmacKey, (byte)0);
                if (hmac != null) {
                    Arrays.fill(hmac, (byte)0);
                }
                if (encoded != null) {
                    Arrays.fill(encoded, (byte)0);
                }
            }

            return plain;
        }
    }
}

