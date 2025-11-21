
# wolfSSL KeyStore (WKS) Design Notes

The WKS KeyStore format was designed to be compatible with wolfCrypt FIPS
140-2 and 140-3, meaning it utilizes FIPS validated cryptographic algorithms.
This document includes notes on the design and algorithm choices used by WKS.
For details on the wolfCrypt FIPS 140-2/3 cryptographic module and boundary,
please reference the appropriate Security Policy or contact fips@wolfssl.com.

## User Customizable Properties

| Security Property | Default | Min | Description |
| --- | --- | --- | --- |
| `wolfjce.wks.iterationCount` | 210,000 | 10,000 | PBKDF2 iteration count |
| `wolfjce.wks.maxCertChainLength` | 100 | N/A | Max cert chain length |
| `wolfjce.keystore.kekCacheEnabled` | false | N/A | Enable KEK caching |
| `wolfjce.keystore.kekCacheTtlSec` | 300 | 1 | Cache TTL in seconds |

## Notes on Algorithm and Security Properties

PBKDF2-HMAC-SHA512 was chosen over PBKDF2-HMAC-SHA256 for AES and HMAC key
generation to allow use of fewer iterations (210,000, as per current
[OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)) versus the recommended 600,000 for SHA-256.

PBKDF2 salt size of 128-bits (16 bytes) is used to follow recommendations
in [NIST SP 800-132, Page 6](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf).

AES-CBC (AES/CBC/PKCS5Padding) was chosen over AES-GCM since AES-GCM requires
that each {key,nonce} combination be unique. Simply generating a random nonce
via RNG does not guarantee uniqueness, and we have no way of maintaining an
accurate counter across KeyStore objects and store/load operations.

Different keys are used for PrivateKey/SecretKey encryption and HMAC, and
derived from one larger PBKDF2 operation (96 bytes) then split between
encryption (32-byte key) and HMAC (64-byte key) operations. A
random salt is generated for each PBKDF2 key generation operation.

HMAC values are calculated over content but also the PBKDF2 salt length,
salt, and iteration count, and all other key parameters (ex: IV and length) to
also include those in the integrity check.

## KeyStore Integrity

### HMAC Generation During KeyStore Storage

When WKS KeyStore objects are stored (`engineStore()`), the following format
is used. This is composed of a *HEADER* section, an *ENTRIES* section, followed
lastly by an HMAC generated over the *HEADER* and *ENTRIES*, including the
PBKDF2 salt, salt length, and iteration count.

The *HEADER* includes a magic number specific to the WKS KeyStore type (`7`), a
WKS KeyStore version (may be incremented in the future as features are added
or if the WKS type definition changes), and a count of the entries included in
the store.

The *ENTRIES* section is made up of one or more `WKSPrivateKey`,
`WKSSecretKey`, or `WKSCertificate` entries. These represent the storage of
a `PrivateKey`, `SecretKey`, and `Certificate` objects respectively.

Generation of the HMAC happens during a call to
`engineStore(OutputStream stream, char[] password)` and is generated in the
following manner:

- Input password must not be null or zero length
- Input password is converted from `char[]` into `byte[]` using password
conversion algorithm described below.
- Random salt of size `WKS_PBKDF2_SALT_SIZE` (128 bits) is generated
- HMAC-SHA512 key (64-bytes) is generated with PBKDF2-HMAC-SHA512 using:
    + Password byte array
    + Random 16-byte salt (`WKS_PBKDF2_SALT_SIZE`)
    + 210,000 iterations (`WKS_PBKDF2_ITERATION_COUNT`), but can be overriden
      by user by setting `wolfjce.wks.iterationCount` Security property.
      Minimum iteration count is 10,000.
- The final HMAC-SHA512 is calculated using the derived key over the bytes of
*HEADER*, *ENTRIES*, salt length, salt, and iteration count. It is then
written out to the OutputStream.

### HMAC Verification During KeyStore Load

When a WKS KeyStore is loaded with
`engineLoad(InputStream stream, char[] password)`, the input password is
optional. If a password is provided, the KeyStore integrity will be checked
using the included HMAC, otherwise the integrity check will be skipped.
This design is to maintain consistency with how the Java JKS format handles
integrity checks upon KeyStore load, and allows for easy conversion and use
of files such as `cacerts` to a WKS type where users do not normally provide
the password when loading the KeyStore file.

Since the HMAC is stored at the end of the KeyStore stream, `engineLoad()`
buffers KeyStore bytes as they are read in, up to and including the PBKDF2
salt size, salt, and PBKDF2 iteration count. Once all entries have been read,
the HMAC is read and verified:
- The salt length is read, sanitized against `WKS_PBKDF2_SALT_SIZE`
- The salt is read
- The PBKDF2 iteration count is read, and checked against min size of
`WKS_PBKDF2_MIN_ITERATIONS`
- Caching of data is paused while the HMAC is read in next
- The original HMAC length is read
- An HMAC-SHA512 is regenerated over the buffered header and entry bytes
    + Password is converted from char[] to byte[] as explained below
    + An HMAC-SHA512 key (64-bytes) is calculated as explained above, using
      salt that was read from input KeyStore stream
    + The generated HMAC value is calculated using this key
- The generated HMAC is compared in both size and contents against the stored
HMAC. If these are different, an IOException is thrown.

### Stored WKS format:

```
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
```

## PrivateKey Protection

A PrivateKey entry is stored into the KeyStore with the `engineSetKeyEntry()`
method, exposed publicly through `KeyStore` as `setKeyEntry()`, when
passing in a `Key` of type `PrivateKey`. The password argument is not allowed
to be null, otherwise a KeyStoreException is thrown.

```
void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
```

Process of storing a PrivateKey is as follows:
- Sanity check the certificate chain:
    + Chain is not null or zero length chain
    + Chain is made up of X509Certificate objects
    + Chain cert signatures are correct as we walk up the chain. The cert
      chain should be ordered from leaf cert (entity) to top-most intermedate
      certificate. The last cert is loaded as a trusted root, and used to
      verify the rest of the chain, since we don't have the root CA cert
      available at this point.
- Verify private key (`Key key`) matches the leaf certificate (`chain[0]`)
- Encrypt private key before storing into KeyStore map:
    + Generate random PBKDF2 salt, of size `WKS_PBKDF2_SALT_SIZE` bytes
    + Generate random IV, of size `WKS_ENC_IV_LENGTH` bytes
    + Convert password from char[] into byte[] using password conversion
      algorithm described below.
    + Encryption key is derived using PBKDF2-SHA256 using byte array, random
      salt, and `WKS_PBKDF2_ITERATION_COUNT` (or customized) iteration count.
        - 96-byte key is generated with PBKDF2 in total, split between 32-byte
          AES-CBC-256 and 64-byte HMAC-SHA512 keys.
    + Encrypt key bytes using AES-CBC-256
    + Generate HMAC-SHA512 over encrypted key and other WKSPrivateKey
      object members
    + Zeroize KEK and HMAC keys (generated from PBKDF2)

When importing a PrivateKey from a KeyStore stream, the process is reversed.
Initially during `engineLoad()`, parameters are read in as well as the encrypted
key:
- Read PBKDF2 salt length, sanity check against `WKS_PBKDF2_SALT_SIZE`
- Read PBKDF2 salt
- Read PBKDF2 iterations, sanity check against `WKS_PBKDF2_MIN_ITERATIONS`
- Read encryption IV, santiy check against `WKS_ENC_IV_LENGTH`
- Read encrypted key
- Read certificate chain if present, check length against `WKS_MAX_CHAIN_COUNT`
- Read HMAC value into object variable, will be checked when user gets key out

The PrivateKey is stored encrypted internal to the WolfSSLKeyStore until
a caller retrieves it with `getKey()`. At that point, WolfSSLKeyStore:
- Derives the decryption key using PBKDF2-SHA256
    + Converts password from `char[]` to `byte[]` using algorithm below
    + Uses salt and iteration count stored internally from encryption
      process or read from KeyStore stream after loading
    + Derives decryption key and HMAC key with PBKDF2-HMAC-SHA512
    + Regenerate and verify HMAC against stored value
    + Decrypts key using AES-CBC-256
    + Zeroizes KEK and HMAC keys (generated from PBKDF2)

## SecretKey Protection

A SecretKey entry is stored into the KeyStore with the `engineSetKeyEntry()`
method, exposed publicly through `KeyStore` as `setKeyEntry()`, when
passing in a `Key` of type `SecretKey`. The password argument is not allowed
to be null, otherwise a KeyStoreException is thrown.

```
void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
```

Process of storing a SecretKey is the same as PrivateKey above, except
there is no certificate so no certifiate or private key sanity checks are done.
The same encrypt/decrypt process is shared between PrivateKey and SecretKey
protection.

## KEK Caching for Performance

### Overview

Repeated calls to `getKey()` on the same KeyStore can be slow due to PBKDF2
happening on each call to derive the Key Encryption Key (KEK) from the user
password. PBKDF2 on each `getKey()` operation ensures that neither password
nor KEK are stored in memory for more time that is needed to derive the KEK and
decrypt the key entry. Although this is the most secure approach, PBKDF2 on
each `getKey()` can be too performance expensive for some use cases.

The WKS KeyStore includes an optional KEK (Key Encryption Key) cache that
stores derived keys in memory to avoid repeated PBKDF2 computations for the
same password/salt combination. With KEK caching enabled, follow up calls
to `getKey()` are much faster.

### Cache Design

The cache uses the following design:

- **Cache Key:** `SHA-256(passwordHash + kdfSalt + kdfIterations)`
  - `passwordHash` = `SHA-256(password)` - avoids storing plaintext passwords
  - Including `kdfSalt` and `kdfIterations` ensures different entries with
    the same password but different PBKDF2 parameters have separate cache keys
- **Cache Entry:** Stores the derived key (KEK + HMAC key), password hash for
  verification, and TTL expiry timestamp
- **Password Verification:** On cache hit, the provided password is hashed and
  compared against the stored hash.
- **HMAC Verification:** Caching only occurs after successful HMAC verification
  to ensure data integrity is maintained.

### Security Properties

| Property | Default | Description |
| --- | --- | --- |
| `wolfjce.keystore.kekCacheEnabled` | `false` | Set to `"true"` to enable caching |
| `wolfjce.keystore.kekCacheTtlSec` | `300` | Cache entry TTL in seconds (5 min) |

Example usage:

```java
/* Enable KEK caching with 10 minute TTL */
Security.setProperty("wolfjce.keystore.kekCacheEnabled", "true");
Security.setProperty("wolfjce.keystore.kekCacheTtlSec", "600");
```

### Cache Lifecycle

The cache is cleared in the following scenarios:
- **Entry deletion:** When `deleteEntry()` is called on an encrypted entry
- **Entry overwrite:** When `setKeyEntry()` overwrites an existing encrypted
  entry
- **KeyStore reload:** When `load()` is called to load a new KeyStore
- **TTL expiration:** Individual entries are removed when their TTL expires
- **Explicit clear:** When `clearCache()` is called on the KeyStore instance
- **Garbage collection:** Automatically when the KeyStore object is finalized

For deterministic cleanup of sensitive cached data, explicitly call
`clearCache()` when the KeyStore is no longer needed:

```java
KeyStore store = KeyStore.getInstance("WKS", "wolfJCE");
/* ... use the KeyStore ... */

/* Explicitly clear cached keys before discarding */
if (store instanceof com.wolfssl.provider.jce.WolfSSLKeyStore) {
    ((com.wolfssl.provider.jce.WolfSSLKeyStore) store).clearCache();
}
```

### Security Considerations

1. **Memory exposure:** Cached derived keys remain in memory for the TTL
   duration. Only enable in trusted environments where performance benefits
   outweigh the increased memory exposure window.

### Performance Characteristics

- **First call:** Full PBKDF2 derivation to generate KEK from password
- **Subsequent calls:** Cache lookup and verification
- **Cache overhead:** ~1-2 SHA-256 operations per call for cache key computation

## Certificate Protection

A Certificate entry is stored into the KeyStore with the
`engineSetCertificateEntry()` method. Certificate entries are not protected
and are stored directly into the KeyStore.

They are integrity protected by the KeyStore HMAC when a KeyStore is written
out to a stream with `engineStore()`, but otherwise have no internal
encryption or integrity protection since no password is provided when storing
certificates.

## Password Conversion Algorithm

The Java KeyStore class specifies that passwords are provided by the user as a
Java character array (`char[]`). Before using a password as input to PBKDF2,
wolfJCE is converts it into a byte array. In Java, one character (`char`) is
composed of two bytes (`byte`). RFC 2898 (PBKDF2) considers a password to be an
octet string and recommends for interop ASCII or UTF-8 encoding be used. SunJCE
uses UTF-8 for PBKDF2 SecretKeyFactory, so we do the same in WolfSSLKeyStore
using `WolfCryptSecretKeyFactory.passwordToByteArray(char[])`.

# Support

Please email support@wolfssl.com with any questions.

