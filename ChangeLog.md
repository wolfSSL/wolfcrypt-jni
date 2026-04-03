### wolfCrypt JNI Release 1.10.0 (04/15/2026)

Release 1.10.0 of wolfCrypt JNI and JCE has bug fixes and new features including:

**New JCE Functionality:**
- Add Cipher `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` support (PR 188)
- Add Cipher `RSA/ECB/OAEPWithSHA-1AndMGF1Padding` support (PR 191)
- Add Cipher `WRAP_MODE` and `UNWRAP_MODE` support for RSA-based key wrapping (PR 197)
- Add PKIX CertPathBuilder implementation using native wolfSSL `X509_STORE` (PR 190, 192, 198, 200)
- Add `jdk.certpath.disabledAlgorithms` enforcement to CertPathBuilder and CertPathValidator (PR 200)
- Register default FIPS error callback in `WolfCryptProvider` for FIPS error debugging (PR 207)
- Enrich `WolfCryptException` with FIPS module status for `FIPS_NOT_ALLOWED_E` errors (PR 207)

**New JNI Functionality:**
- Add hex string conversion via `WolfCrypt.toHexString()` and `WolfCrypt.hexStringToByteArray()` (PR 187)
- Add PEM to DER conversion support for keys and certificates (PR 186)
- Add `setFlags()` and `setVerificationTime()` methods to `WolfSSLX509StoreCtx` (PR 192)

**New Property Support:**
- Add `wolfssl.skipLibraryLoad` system property for custom native library loading (PR 189)
- Add `wolfjce.ioTimeout` system property for OCSP/CRL IO timeouts (PR 199)

**JNI and JCE Changes:**
- Fix FIPS error callback lifecycle, deregister native callback in `JNI_OnUnload` (PR 203)
- Fix Ed25519 signature verification passing message length instead of signature length (PR 205)
- Fix `jlong` to `word32` pointer cast in `RsaFlattenPublicKey` and `RsaExportCrtKey` (PR 205)
- Fix unsigned return value handling for `wc_RsaEncryptSize()` across RSA functions (PR 205, 206)
- Add HMAC offset/length bounds validation for byte array and ByteBuffer variants (PR 205)
- Improve NULL check handling in HMAC, Ed25519, Curve25519, and Pwdbased JNI wrappers (PR 205)
- Add missing `releaseByteArray()` calls across ECC, RSA, ChaCha, and AES-GCM JNI functions (PR 205, 206)
- Fix incorrect error code in `HmacFinal` hash size check (PR 205)
- Return defensive copy of IV array from `engineGetIV()` (PR 205)
- Fix `wc_ecc_import_private_raw()` not passing validated `curveId` to underlying import function (PR 206)
- Zeroize encoded key byte array in `WolfCryptPBEKey.destroy()` (PR 206)
- Use constant-time comparison for GMAC tag verification (PR 206)
- Add missing AES-CTR and AES-OFB cleanup in `WolfCryptCipher.finalize()` (PR 206)
- Fix signed integer overflow in JNI offset/length bounds checks (PR 206)
- Add ByteBuffer bounds validation in SHA, MD5, and RNG native functions (PR 206)
- Fix missing return after throw in SHA and MD5 copy NULL checks (PR 206)
- Remove unused `wc_RsaPSS_VerifyInline` JNI wrapper that skipped padding check (PR 206)
- Reduce `WC_RNG` struct allocations in `WolfCryptCipher` and `WolfCryptDhParameterGenerator` (PR 208)
- Expand FIPS-compliant SecureRandom sanitization in `WolfCryptKeyGenerator` (PR 209)
- Zero intermediate output buffers before free across JNI wrappers (PR 210)
- Fix DH key export return value reset in success paths (PR 210)
- Free internal AES struct in GMAC after use (PR 210)

**Example Changes:**
- Add `CertPathBuilder` and `CertPathValidator` example (PR 190)
- Update Android example project CMakeLists.txt file exclusion list (PR 198, 206)
- Add JKS to BKS KeyStore conversion script for Android testing (PR 209)
- Migrate Android example project from `jcenter()` to `mavenCentral()` and AndroidX (PR 209)
- Add Gradle wrapper `distributionSha256Sum` to Android example project (PR 210)

**Testing Changes:**
- Add Java 24 and 25 tests to GitHub Actions workflows (PR 193)
- Add GitHub Actions workflow for Linux 32-bit testing with Java 17 (PR 194)
- Add GitHub Actions workflow for UBSan undefined behavior testing (PR 195)
- Add `ant spotbugs` target and GitHub Actions SpotBugs static analysis workflow (PR 204)
- Add GitHub Actions workflow for Android FIPS Ready testing (PR 209)
- Add GitHub Actions workflow for Java 9+ module (JPMS) testing (PR 196)
- Fix threaded MessageDigest tests hanging on FIPS error (PR 207)
- Improve JUnit test reliability for FIPS mode and CI environments (PR 209)
- Pin Bouncy Castle dependency version with SHA-256 hash verification (PR 209)
- Update Apache Ant CI dependency to 1.10.16 (PR 209)

**Misc Changes:**
- Add Java 9+ module support (JPMS) for `jlink` compatibility (PR 196)
- Fix Javadoc warnings about default constructors in `WolfCryptUtil` and `Asn` (PR 201)
- Fix code issues and warnings found by SpotBugs static analysis (PR 204)
- Update copyright dates to 2026 (PR 185)

The wolfCrypt JNI/JCE Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfcryptjni/. For build
instructions and more details, please check the manual.

### wolfCrypt JNI Release 1.9.0 (12/31/2025)

Release 1.9.0 of wolfCrypt JNI and JCE has bug fixes and new features including:

**New JCE Functionality:**
- Add KeyGenerator implementation (AES, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512) (PR 98)
- Add SHA-224 support to MessageDigest, Mac, Signature, KeyGenerator (PR 104)
- Add SHA-3 support to MessageDigest, Mac, Signature (PR 103)
- Add utility method to convert JKS/PKCS12 KeyStore to WKS type (PR 108)
- Add more AES mode support to Cipher class (PR 129, 163, 173):
    - AES/CCM/NoPadding
    - AES/CTR/NoPadding
    - AES/ECB/NoPadding
    - AES/ECB/PKCS5Padding
    - AES/OFB/NoPadding
    - AES/CTS/NoPadding
- Add AESCMAC (AES-CMAC), AESGMAC (AES-GMAC) to Mac class (PR 129)
- Add RSA-PSS support to Signature class (PR 131):
    - RSASSA-PSS
    - SHA224withRSA/PSS
    - SHA256withRSA/PSS
    - SHA384withRSA/PSS
    - SHA512withRSA/PSS
- Add `Cipher.engineGetParameters()` support (PR 140)
- Add Cipher generic `AES` type support (PR 142)
- Add AES and GCM support to AlgorithmParameters class (PR 144)
- Add HmacSHA3 support to KeyGenerator class (PR 150):
    - HmacSHA3-224
    - HmacSHA3-256
    - HmacSHA3-384
    - HmacSHA3-512
- Add `toString()` to WolfCryptRandom, used when printing SecureRandom object (PR 154)
- Add additional ECC algorithm OIDs to Signature and KeyPairGenerator classes (PR 158)
- Add EC KeyFactory support (PR 159)
- Add P1363 ECDSA signature formats to Signature class (PR 160)
- Add DH support to AlgorithmParameter, AlgorithmParameterGenerator, and KeyFactory classes (PR 161)
- Add AES and 3DES support to SecretKeyFactory and SecretKey classes (PR 164)
- Add additional AES and Hmac algorithm aliases to Cipher and Mac classes (PR 166)
- Add Java ServiceLoader support for wolfJCE provider for Java Module System (JPMS) compatibility (PR 167)
- Add RSA KeyFactory support (PR 169)
- Add MessageDigest OID alias values for SHA-224/256/384/512 (PR 170)
- Add PSS parameter encoding support in WolfCryptPSSParameters class (PR 175)
- Add `engineProbe()` implementation to WolfSSLKeyStore (PR 178)
- Add optional KEK caching to WolfSSLKeyStore for performance (PR 176)
- Add RSASSA-PSS key support to WolfSSLKeyStore (PR 180)

**JNI and JCE Changes:**
- Fix `Cipher.getOutputSize()` for AES/GCM/NoPadding in DECRYPT mode (PR 107)
- Dynamically get algorithm and key ASN enum values from wolfSSL (PR 111)
- Dynamically get hash OID sums from wolfSSL (PR 124)
- Fix max secret size in DH agreement (PR 123)
- Fix potential JNI-level ECC issues (PR 117)
- Fix build issues with older wolfSSL and FIPS build variants (PR 133)
- Fix AES-CTR IV consistency across state resets (PR 136)
- Fix for using buffered data in `Cipher.engineGetOutputSize()` (PR 138)
- Throw `AEADBadTagException` on AES-GCM decrypt failure (PR 139)
- Fix `Cipher.engineInit()` with null parameters (PR 141)
- Throw correct `InvalidAlgorithmParameterException` from `Cipher.init()` on unsupported mode (PR 143)
- Fix for PKCS#7 pad/unpad operations in Cipher (PR 146)
- Fix expected output size for Cipher decrypt related to pad size (PR 147)
- Fix AES-GCM Cipher edge case to allow for null input or output arrays (PR 145)
- Improve Cipher input validation, output buffer sizing, update behavior (PR 148)
- Fix MessageDigest parameter validation (PR 149)
- Fix `ArrayIndexOutOfBoundsException` in Cipher AES-GCM/CCM with zero-length plaintext (PR 151)
- Throw exception if RSA `PrivateKey` does not include CRT parameters (PR 153)
- Throw `IllegalArgumentException` from `WolfCryptRandom.engineGenerateSeed()` on bad input values (PR 152)
- Set default key and parameter sizes in `KeyPairGenerator` if not explicitly set (PR 155)
- Fix ECC `KeyPairGenerator` bits to bytes conversion (PR 157)
- Check RSA key size used against min allowed in KeyPairGenerator (PR 162)
- Fix SecretKey decryption to use stored PBKDF2 iteration count in WKS (PR 168)
- Remove synchronization on some WolfSSLKeyStore methods (PR 165)
- Validate EC key sizes in `KeyPairGenerator.initialize()` (PR 174)
- Improvements to PKIXCertPathValidator with OCSP revocation checking, disabled algorithm validation, and more (PR 177, 178)

**Debugging Changes:**
- Switch to use Java logging (`java.util.logging`) framework for debug logs (PR 110)
- Refresh debug flags when WolfCryptProvider is loaded (PR 135)
- Switch debug log timestamp to use Java `Instant.ofEpochMilli()`, remove dependency on `java.sql.Timestamp` (PR 137)

**Example Changes:**
- Add RSA key generation to wolfJCE benchmark app (PR 95)
- Add ECC and ECDH to wolfJCE benchmark app (PR 99, 116)
- Add HMAC benchmark to wolfJCE benchmark app (PR 100)
- Add DH benchmarks to wolfJCE benchmark app (PR 102)
- Add PBKDF2 benchmark to wolfJCE benchmark app (PR 105)
- Add MessageDigest benchmark to wolfJCE benchmark app (PR 106)
- Add Signature benchmark to wolfJCE benchmark app (PR 109)
- Add SHA-3 ciphers to HMAC benchmark in wolfJCE benchmark app (PR 113)
- Add KeyGenerator benchmark to wolfJCE benchmark app (PR 115)
- Add SecureRandom benchmark to wolfJCE benchmark app (PR 120)
- Add KeyStore benchmark example app for WKS/JKS/PKCS12 (PR 118)
- Add individual algorithm category options to wolfJCE benchmark app (PR 121)

**Testing Changes:**
- Add GitHub Actions PRB test for AddressSanitizer (`-fsanitize=address`) builds (PR 119)
- Add GitHub Actions PRB tests for coding style (line length, comment style) (PR 126, 127)
- Add GitHub Actions PRB test for Clang scan-build static analysis (PR 128)
- Add GitHub Actions PRB test for Visual Studio builds on Windows (PR 130)
- Add GitHub Actions PRB test to build against last 5 stable wolfSSL releases (PR 181)
- Add GitHub Actions PRB test to run unit tests on Android emulator (PR 183)
- Output time taken in ms per JUnit test when ant test is run (PR 171)
- JUnit test performance improvements (PR 172)

**Misc Changes:**
- Clean up IDE warnings in Cursor and VSCode (PR 101)
- Add `CLAUDE.md` for consumption by Claude Code (PR 122)

The wolfCrypt JNI/JCE Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfcryptjni/. For build
instructions and more details, please check the manual.

### wolfCrypt JNI Release 1.8.0 (01/23/2025)

Release 1.8.0 of wolfCrypt JNI and JCE has bug fixes and new features including:

**New JCE Functionality:**
- Add Java security property support for mapping JKS/PKCS12 to WKS type (PR 83)

**JNI and JCE Changes:**
- Run FIPS CASTs once up front to prevent threaded app errors (PR 84, 91)

**Example Changes:**
- Define `WOLFSSL_CUSTOM_CONFIG` in Android Studio project builds (PR 85)
- Add basic JCE cryptography benchmark app (PR 88, 89, 93, 94)

**Testing Changes:**
- Add GitHub Action testing Maven (pom.xml) build on macOS and Linux (PR 82)

The wolfCrypt JNI/JCE Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfcryptjni/. For build
instructions and more details, please check the manual.

### wolfCrypt JNI Release 1.7.0 (11/11/2024)

Release 1.7.0 of wolfCrypt JNI and JCE has bug fixes and new features including:

**New JCE Functionality:**
- New WolfSSLKeyStore (WKS) KeyStore implementation for FIPS 140-2/3 compliance (PR 67)

**JNI and JCE Changes:**
- Remove call to BigInteger.longValueExact(), not available on some Java versions (PR 76)
- Detect `RSA_MIN_SIZE` in tests, add `Rsa.RSA_MIN_SIZE` helper (PR 77)
- Fix pointer use in native `X509CheckPrivateKey()` (PR 80)

**Example Changes:**
- Set keytool path correctly in `system-cacerts-to-wks.sh` (PR 78)
- Add example Android Studio project (IDE/Android) (PR 79)

**Testing Changes:**
- Run Facebook Infer on pull requests with GitHub Actions (PR 74)
- Add Android Gradle build with GitHub Actions to run on all pull requests (PR 79)

The wolfCrypt JNI/JCE Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfcryptjni/. For build
instructions and more details, please check the manual.

### wolfCrypt JNI Release 1.6.0 (4/17/2024)

Release 1.6.0 of wolfCrypt JNI and JCE has bug fixes and new features including:

**New JCE Functionality:**
- Add RSA support to `KeyPairGenerator` class (PR 49)
- Add `AES/CBC/PKCS5Padding` support to `Cipher` class (PR 51)
- Add `RSA` support to `Cipher` class (PR 51)
- Add `PKIX` implementation of `CertPathValidator` class (PR 60, 66)
- Add `SHA1` alias for `MessageDigest` `SHA-1` for interop compatibility (PR 61)
- Add `AES/GCM/NoPadding` support to `Cipher` class (PR 62)
- Add `SecretKeyFactory` implementation supporting `PBKDF2` (PR 70)
- Add `DEFAULT` support to `SecureRandom` class (PR 72)

**New JNI Wrapped APIs and Functionality:**
- Add `AES-GCM` support to `com.wolfssl.wolfcrypt.AesGcm` class (PR 62)

**JNI and JCE Changes:**
- Add synchronization to `com.wolfssl.wolfcrypt.Rng` class (PR 44)
- Correct preprocessor guards for 3DES with wolfCrypt FIPS (PR 47)
- Correct order of operations in `wc_CreatePKCS8Key()` JNI wrapper API (PR 50)
- Add synchronization around native structure pointer use (PR 53)
- Remove inclusion of CyaSSL header includes, switch to wolfSSL (PR 56)
- Call `PRIVATE_KEY_LOCK/UNLOCK()` for wolfCrypt FIPS 140-3 compatibility (PR 57)
- Improve native HMAC feature detection (PR 58)
- Prepend zero byte to DH shared secret if less than prime length (PR 69)
- Add synchronization to protected methods in `WolfCryptSignature` (PR 68)
- Add synchronization to public methods of `WolfCryptKeyPairGenerator` (PR 73)
- Only allocate one `Rng` object per `WolfCryptSignature`, not per sign operation (PR 73)
- Reduce extra `WolfCryptRng` object creation in `Signature` and `KeyPairGenerator` (PR 73)

**New Platform Support:**
- Add Windows support with Visual Studio, see IDE/WIN/README.md (PR 46)

**Build System Changes:**
- Support custom wolfSSL library prefix and name in `makefile.linux` (PR 45)
- Standardize JNI library name on OSX to .dylib (PR 54)
- Update Maven build support (PR 55)

**Example Changes:**
- Print provider of `SecureRandom` from `ProviderTest.java` (PR 43)
- Add Windows batch script to run `ProviderTest` example (PR 52)

**Testing Changes:**
- Add extended threading test for `WolfCryptRandom` class (PR 44)
- Add Facebook Infer test script, make fixes (PR 48, 63)
- Add GitHub Actions tests for Oracle/Zulu/Coretto/Temurin/Microsoft JDKs on Linux and OS X (PR 65)

**Documentation Changes:**
- Remove build instructions from `README.md` for FIPS historical cert #2425 (PR 56)
- Fix Javadoc warnings for Java 21 and 22 (PR 71)

The wolfCrypt JNI/JCE Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfcryptjni/. For build
instructions and more details, please check the manual.

### wolfCrypt JNI Release 1.5.0 (11/14/2022)

Release 1.5.0 of wolfCrypt JNI has bug fixes and new features including:

- Add build compatibility for Java 7 (PR 38)
- Add support for "SHA" algorithm string in wolfJCE (PR 39)
- Add rpm package support (PR 40)
- Add wolfJCE MessageDigest.clone() support (PR 41)
- Improve error checking of native Md5 API calls (PR 41)
- Add unit tests for com.wolfssl.wolfcrypt.Md5 (PR 41)

### wolfCrypt JNI Release 1.4.0 (08/11/2022)

Release 1.4.0 of wolfCrypt JNI has bug fixes and new features including:

- Add example directory with one simple ProviderTest example (PR 32)
- Fix double free of ChaCha pointer (PR 34)
- Add test cases for ChaCha.java (PR 34)
- Skip WolfCryptMacTest for HMAC-MD5 when using wolfCrypt FIPS 140-3 (PR 35)
- Use new hash struct names (wc\_Md5/wc\_Sha/etc) in native code (PR 35)
- Fix potential build error with non-ASCII apostrophes in Fips.java (PR 36)

### wolfCrypt JNI Release 1.3.0 (05/13/2022)

Release 1.3.0 of wolfCrypt JNI has bug fixes and new features including:

- Run FIPS tests on `ant test` when linked against a wolfCrypt FIPS library (PR 24)
- Wrap native AesGcmSetExtIV\_fips() API (PR 24)
- Fix releaseByteArray() usage in Fips.RsaSSL\_Sign() (PR 24)
- Fix AES-GCM FIPS test cases (PR 24)
- Keep existing JAVA\_HOME in makefiles if already set (PR 25)
- Add JCE support for MessageDigestSpi.engineGetDigestLength() (PR 27)
- Update junit to 4.13.2 (PR 28)
- Update missing Javadocs, fixes warnings on newer Java versions (PR 29)

### wolfCrypt JNI Release 1.2.0 (11/16/2021)

Release 1.2.0 of wolfCrypt JNI has bug fixes and new features including:

- Add **FIPS 140-3** compatibility when using wolfCrypt FIPS or FIPS Ready
- Increase junit version from 4.12 to 4.13 in pom.xml
- Add local `./lib` directory to `java.library.path` in pom.xml
- Fix builds with `WOLFCRYPT_JNI_DEBUG_ON` defined
- Fix compatibility with wolfCrypt `NO_OLD_*` defines
- Fix compatibility with wolfSSL `./configure --enable-all` and ECC tests

### wolfCrypt JNI Release 1.1.0 (08/26/2020)

Release 1.1.0 of wolfCrypt JNI has bug fixes and new features including:

- New JNI-level wrappers for ChaCha, Curve25519, and Ed25519
- Maven pom.xml build file
- Runtime detection of hash type enum values for broader wolfSSL support
- Updated wolfSSL error codes to match native wolfSSL updates
- Native HMAC wrapper fixes for building with wolfCrypt FIPSv2
- Native wrapper to return `HAVE_FIPS_VERSION` value to Java
- Remove Blake2b from HMAC types, to match native wolfSSL changes
- Better native wolfSSL feature detection
- Increase Junit version to 4.13
- Use nativeheaderdir on supported platforms instead of javah
- Use hamcrest-all-1.3.jar in build.xml
- Add call to `wc_ecc_set_rng()` when needed

### wolfCrypt JNI Release 1.0.0 (7/10/2017)

Release 1.0.0 of wolfCrypt JNI has bug fixes and new features including:

- Bug fixes to JCE classes: Cipher, KeyAgreement (DH), Signature
- JCE debug logging with wolfjce.debug system property
- Additional unit tests for JCE provider
- Conditional ant build for JNI and/or JCE
- New ant targets with choice of debug or release builds

### wolfCrypt JNI Release 0.3 BETA

Release 0.3 BETA of wolfCrypt JNI includes:

- Support for ECC and DH key generation
- Bug fixes regarding key import/export
- Better argument sanitization at JNI level

### wolfCrypt JNI Release 0.2 BETA

Release 0.2 BETA of wolfCrypt JNI includes:

- Support for Android
- Support for Oracle JDK/JVM
- Support for code signing wolfcrypt-jni.jar file
- Compatibility with non-FIPS wolfSSL and wolfCrypt builds
- Bug fixes regarding releasing native resources
- Test package changed to (com.wolfssl.provider.jce.test)

### wolfCrypt JNI Release 0.1 BETA

Release 0.1 BETA of wolfCrypt JNI includes:

- Initial JCE package
- Support for OpenJDK

