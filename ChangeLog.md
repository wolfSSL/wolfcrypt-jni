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
instructions and more details comments, please check the manual.

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
instructions and more details comments, please check the manual.

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
instructions and more details comments, please check the manual.

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

