
## wolfCrypt JNI

This package provides a Java, JNI-based interface to the native wolfCrypt
(and wolfCrypt FIPS API, if using with a FIPS version of wolfCrypt). It also
includes a JCE provider for wolfCrypt.

For instructions and notes on the JNI wrapper, please reference this README.md,
or the wolfSSL online documentation.

For instructions and notes on the JCE provider, please reference the
README_JCE.md file, or online instructions.

### Compiling
---------

To compile the wolfCrypt JNI wrapper:

1) Compile and install a wolfSSL (wolfssl-x.x.x), wolfSSL FIPS
release (wolfssl-x.x.x-commercial-fips), or wolfSSL FIPS Ready release:

In any of these cases, you will need the "--enable-keygen" ./configure option.

wolfSSL Standard Build:
```
$ cd wolfssl-x.x.x
$ ./configure --enable-keygen
$ make check
$ sudo make install
```

wolfSSL FIPSv1 Build:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips --enable-keygen
$ make check
$ sudo make install
```

wolfSSL FIPSv2 Build:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=v2 --enable-keygen
$ make check
$ sudo make install
```

wolfSSL FIPS Ready Build:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=ready --enable-keygen
$ make check
$ sudo make install
```

2) Compile the native wolfCrypt JNI object files:

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
files to be on your JUNIT_HOME path.

To install and set up JUnit:

a) Download "junit-4.13.jar" and "hamcrest-all-1.3.jar" from junit.org

b) Place these JAR files on your system and set JUNIT_HOME to point to
   that location:

    $ export JUNIT_HOME=/path/to/jar/files

The JUnit tests can then be run with:

```
$ ant test
```

### API Javadocs
---------

After the "ant" command has been executed, this will generate a set of
Javadocs under the wolfcrypt-jni/docs directory.  To view the root document,
open the following file in a web browser:

wolfcrypt-jni/docs/index.html

### Example / Test Code
---------

The JUnit test code can act as a good usage example of the wolfCrypt JNI
API. This test code is run automatically when "ant test" is executed from
the root wolfcrypt-jni directory.  The test source code is located at:

wolfcrypt-jni/src/test/com/wolfssl/wolfcrypt

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
README_JCE.md for more details.

### Revision History
---------

********* wolfCrypt JNI Release 1.1.0 (08/26/2020)

Release 1.1.0 of wolfCrypt JNI has bug fixes and new features including:

- New JNI-level wrappers for ChaCha, Curve25519, and Ed25519
- Maven pom.xml build file
- Runtime detection of hash type enum values for broader wolfSSL support
- Updated wolfSSL error codes to match native wolfSSL updates
- Native HMAC wrapper fixes for building with wolfCrypt FIPSv2
- Native wrapper to return HAVE_FIPS_VERSION value to Java
- Remove Blake2b from HMAC types, to match native wolfSSL changes
- Better native wolfSSL feature detection
- Increase Junit version to 4.13
- Use nativeheaderdir on supported platforms instead of javah
- Use hamcrest-all-1.3.jar in build.xml
- Add call to wc_ecc_set_rng() when needed

********* wolfCrypt JNI Release 1.0.0 (7/10/2017)

Release 1.0.0 of wolfCrypt JNI has bug fixes and new features including:

- Bug fixes to JCE classes: Cipher, KeyAgreement (DH), Signature
- JCE debug logging with wolfjce.debug system property
- Additional unit tests for JCE provider
- Conditional ant build for JNI and/or JCE
- New ant targets with choice of debug or release builds

********* wolfCrypt JNI Release 0.3 BETA

Release 0.3 BETA of wolfCrypt JNI includes:

- Support for ECC and DH key generation
- Bug fixes regarding key import/export
- Better argument sanitization at JNI level

********* wolfCrypt JNI Release 0.2 BETA

Release 0.2 BETA of wolfCrypt JNI includes:

- Support for Android
- Support for Oracle JDK/JVM
- Support for code signing wolfcrypt-jni.jar file
- Compatibility with non-FIPS wolfSSL and wolfCrypt builds
- Bug fixes regarding releasing native resources
- Test package changed to (com.wolfssl.provider.jce.test)

********* wolfCrypt JNI Release 0.1 BETA

Release 0.1 BETA of wolfCrypt JNI includes:

- Initial JCE package
- Support for OpenJDK

