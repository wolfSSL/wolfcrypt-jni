
## wolfCrypt JCE Provider and JNI Wrapper

This package provides a Java, JNI-based interface to the native wolfCrypt
(and wolfCrypt FIPS API, if using with a FIPS version of wolfCrypt). It also
includes a JCE provider for wolfCrypt.

For instructions and notes on the JNI wrapper, please reference this README.md,
or the wolfSSL online documentation.

For instructions and notes on the JCE provider, please reference the
[README_JCE.md](./README_JCE.md) file, or online instructions.

### Compiling
---------

To compile the wolfCrypt JNI wrapper:

1) Compile and install a wolfSSL (wolfssl-x.x.x), wolfSSL FIPS
release (wolfssl-x.x.x-commercial-fips), or wolfSSL FIPS Ready release:

In any of these cases, you will need the `--enable-keygen` ./configure option.

**wolfSSL Standard Build**:
```
$ cd wolfssl-x.x.x
$ ./configure --enable-keygen
$ make check
$ sudo make install
```

**wolfSSL FIPSv1 Build**:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips --enable-keygen
$ make check
$ sudo make install
```

**wolfSSL FIPSv2 Build**:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=v2 --enable-keygen
$ make check
$ sudo make install
```

**wolfSSL FIPS Ready Build**:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=ready --enable-keygen
$ make check
$ sudo make install
```

2) Compile the native wolfCrypt JNI object files. Two makefiles are distributed
for Linux (`makefile.linux`) and Mac OSX (`makefile.macosx`). First copy
the makefile for your platform to a file called `makefile`:

```
$ cd wolfcrypt-jni
$ cp makefile.linux makefile
```

Then compile the native wolfCrypt JNI object files:

```
$ cd wolfcrypt-jni
$ make
```

3) Compile the wolfCrypt JNI Java sources files, from the wolfcrypt-jni
   directory:

```
$ ant (shows possible build targets)
$ ant <build-jni-debug|build-jni-release|build-jce-debug|build-jce-release>
```

In order for the JUnit tests to be run correctly when executing "ant test",
please follow these steps (for Linux/Mac):

Running "ant test" will execute JUnit tests included in this package. These
tests require JUnit to be available on your system and for the correct JAR
files to be on your `JUNIT_HOME` path.

To install and set up JUnit:

a) Download "junit-4.13.2.jar" and "hamcrest-all-1.3.jar" from junit.org

b) Place these JAR files on your system and set `JUNIT_HOME` to point to
   that location:

```
$ export JUNIT_HOME=/path/to/jar/files
```

The JUnit tests can then be run with:

```
$ ant test
```

To clean the both Java JAR and native library:

```
$ ant clean
$ make clean
```

### API Javadocs
---------

Running `ant` will generate a set of Javadocs under the `wolfcrypt-jni/docs`
directory.  To view the root document, open the following file in a web browser:

`wolfcrypt-jni/docs/index.html`

### Example / Test Code
---------

The JUnit test code can act as a good usage example of the wolfCrypt JNI
API. This test code is run automatically when "ant test" is executed from
the root wolfcrypt-jni directory.  The test source code is located at:

`wolfcrypt-jni/src/test/com/wolfssl/wolfcrypt`

JCE-specific examples can be found in the `examples/provider` sub-directory.
These examples will only be compiled with either `ant build-jce-debug` or
`ant build-jce-release` are used. Since these are JCE/provider-only examples,
they are not built for JNI-only builds (`ant build-jni-debug/release`).

For more details, see the [README_JCE.md](./README_JCE.md).

### JAR Code Signing
---------

The wolfcrypt-jni.jar can be code signed by placing a "codeSigning.properties"
file in the "wolfcrypt-jni" root directory.  The ant build script (build.xml)
will detect the prescense of this properties file and use the provided
information to sign the generated JAR file.

"codeSigning.properties" should have the following properties set:

```
sign.alias=<signing alias in keystore>
sign.keystore=<path to signing keystore>
sign.storepass=<keystore password>
sign.tsaurl=<timestamp server url>
```

Signing the JAR is important especially if using the JCE Provider with a JDK
that requires JCE provider JAR's to be authenticated.  Please see
[README_JCE.md](./README_JCE.md) for more details.

### Revision History
---------

#### wolfCrypt JNI Release 1.5.0 (11/14/2022)

Release 1.5.0 of wolfCrypt JNI has bug fixes and new features including:

- Add build compatibility for Java 7 (PR 38)
- Add support for "SHA" algorithm string in wolfJCE (PR 39)
- Add rpm package support (PR 40)
- Add wolfJCE MessageDigest.clone() support (PR 41)
- Improve error checking of native Md5 API calls (PR 41)
- Add unit tests for com.wolfssl.wolfcrypt.Md5 (PR 41)

#### wolfCrypt JNI Release 1.4.0 (08/11/2022)

Release 1.4.0 of wolfCrypt JNI has bug fixes and new features including:

- Add example directory with one simple ProviderTest example (PR 32)
- Fix double free of ChaCha pointer (PR 34)
- Add test cases for ChaCha.java (PR 34)
- Skip WolfCryptMacTest for HMAC-MD5 when using wolfCrypt FIPS 140-3 (PR 35)
- Use new hash struct names (wc\_Md5/wc\_Sha/etc) in native code (PR 35)
- Fix potential build error with non-ASCII apostrophes in Fips.java (PR 36)

#### wolfCrypt JNI Release 1.3.0 (05/13/2022)

Release 1.3.0 of wolfCrypt JNI has bug fixes and new features including:

- Run FIPS tests on `ant test` when linked against a wolfCrypt FIPS library (PR 24)
- Wrap native AesGcmSetExtIV\_fips() API (PR 24)
- Fix releaseByteArray() usage in Fips.RsaSSL\_Sign() (PR 24)
- Fix AES-GCM FIPS test cases (PR 24)
- Keep existing JAVA\_HOME in makefiles if already set (PR 25)
- Add JCE support for MessageDigestSpi.engineGetDigestLength() (PR 27)
- Update junit to 4.13.2 (PR 28)
- Update missing Javadocs, fixes warnings on newer Java versions (PR 29)

#### wolfCrypt JNI Release 1.2.0 (11/16/2021)

Release 1.2.0 of wolfCrypt JNI has bug fixes and new features including:

- Add **FIPS 140-3** compatibility when using wolfCrypt FIPS or FIPS Ready
- Increase junit version from 4.12 to 4.13 in pom.xml
- Add local `./lib` directory to `java.library.path` in pom.xml
- Fix builds with `WOLFCRYPT_JNI_DEBUG_ON` defined
- Fix compatibility with wolfCrypt `NO_OLD_*` defines
- Fix compatibility with wolfSSL `./configure --enable-all` and ECC tests

#### wolfCrypt JNI Release 1.1.0 (08/26/2020)

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

#### wolfCrypt JNI Release 1.0.0 (7/10/2017)

Release 1.0.0 of wolfCrypt JNI has bug fixes and new features including:

- Bug fixes to JCE classes: Cipher, KeyAgreement (DH), Signature
- JCE debug logging with wolfjce.debug system property
- Additional unit tests for JCE provider
- Conditional ant build for JNI and/or JCE
- New ant targets with choice of debug or release builds

#### wolfCrypt JNI Release 0.3 BETA

Release 0.3 BETA of wolfCrypt JNI includes:

- Support for ECC and DH key generation
- Bug fixes regarding key import/export
- Better argument sanitization at JNI level

#### wolfCrypt JNI Release 0.2 BETA

Release 0.2 BETA of wolfCrypt JNI includes:

- Support for Android
- Support for Oracle JDK/JVM
- Support for code signing wolfcrypt-jni.jar file
- Compatibility with non-FIPS wolfSSL and wolfCrypt builds
- Bug fixes regarding releasing native resources
- Test package changed to (com.wolfssl.provider.jce.test)

#### wolfCrypt JNI Release 0.1 BETA

Release 0.1 BETA of wolfCrypt JNI includes:

- Initial JCE package
- Support for OpenJDK

