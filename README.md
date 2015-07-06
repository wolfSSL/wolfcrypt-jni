
## wolfCrypt JNI

This package provides a Java, JNI-based interface to the native wolfCrypt
FIPS API.

### Compiling
---------

To compile the wolfcrypt-jni wrapper:

1) Compile and install a wolfSSL FIPS release (wolfssl-x.x.x-commercial-fips):
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
$ ant
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

