
## wolfCrypt JNI

This package provides a Java, JNI-based interface to the native wolfCrypt
(and wolfCrypt FIPS API, if using with a FIPS version of wolfCrypt). It also
includes a JCE provider for wolfCrypt.

For instructions and notes on the JNI wrapper, please referene this README,
or online documentation.

For instructinos and notes on the JCE provider, please reference the
README_JCE file, or online instructions.

### Compiling
---------

To compile the wolfCrypt JNI wrapper:

1) Compile and install a wolfSSL (wolfssl-x.x.x) or wolfSSL FIPS
release (wolfssl-x.x.x-commercial-fips):

In either case, you will need the "--enable-keygen" ./configure option.

wolfSSL Standard Build:
```
$ cd wolfssl-x.x.x
$ ./configure --enable-keygen
$ make check
$ sudo make install
```

wolfSSL FIPS Build:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips --enable-keygen
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

a) Download "junit-4.12.jar" and "hamcrest-core-1.3.jar" from junit.org

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
README_JCE for more details.

