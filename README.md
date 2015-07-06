
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
