
## wolfCrypt JCE Provider and JNI Wrapper

This packages includes both a JNI wrapper and JCE provider around the native
wolfCrypt cryptography library. It supports both normal and FIPS validated
versions of wolfCrypt.

For instructions and notes on the **JNI wrapper**, please reference this
README.md, or the wolfSSL online user manual.

For instructions and notes on the **JCE provider**, please reference the
[README_JCE.md](./README_JCE.md) file, or online user manual.

### Compiling Native wolfSSL (Dependency)
---------

To compile the wolfCrypt JNI wrapper and JCE provider, first the native (C)
wolfSSL library must be compiled and installed.

Compile and install a wolfSSL (wolfssl-x.x.x), wolfSSL FIPS
release (wolfssl-x.x.x-commercial-fips), or wolfSSL FIPS Ready release.

In any of these cases, you will need the `--enable-jni` ./configure option.
The `--enable-jni` option includes all native wolfSSL features needed by
both wolfCrypt JNI/JCE (this package) as well as wolfSSL JNI/JSSE (a
separate package and repo). If you want the minimal set of requirements needed
for only wolfJCE, you can use `--enable-keygen --enable-crl`, where
CRL support is needed to support JCE `CertPathValidator(PKIX)` CRL support.

**wolfSSL Standard Build**:
```
$ cd wolfssl-x.x.x
$ ./configure --enable-jni
$ make check
$ sudo make install
```

**wolfSSL FIPSv2 Build**:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=v2 --enable-jni
$ make check
$ sudo make install
```

**wolfSSL FIPS Ready Build**:

```
$ cd wolfssl-x.x.x-commercial-fips
$ ./configure --enable-fips=ready --enable-jni
$ make check
$ sudo make install
```

### Compiling wolfSSL JNI/JCE with ant
---------

wolfCrypt JNI/JCE's ant build is the most stable and well-tested. Newer support
for building with Maven has also been added. See section below for instructions
on building with Maven. Continue reading here for instructions to build with
ant.

1) Compile the native wolfCrypt JNI object files. Two makefiles are distributed,
one for Linux (`makefile.linux`) and one for Mac OSX (`makefile.macosx`). First
copy the makefile for your platform to a file called `makefile`:

```
$ cd wolfcrypt-jni
$ cp makefile.linux makefile
```

Then compile the native wolfCrypt JNI object files into a native C shared
library:

```
$ cd wolfcrypt-jni
$ make
```

2) Compile the wolfCrypt JNI/JCE Java sources files, from the wolfcrypt-jni
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

#### API Javadocs
---------

Running `ant` will generate a set of Javadocs under the `wolfcrypt-jni/docs`
directory.  To view the root document, open the following file in a web browser:

`wolfcrypt-jni/docs/index.html`

### Compiling wolfSSL JNI/JCE with Maven
---------

wolfSSL JNI/JCE supports building and packaging with Maven, for those projects
that are already set up to use and consume Maven packages.

wolfSSL JNI/JCE's Maven build configuration is defined in the included
`pom.xml` file.

First, compile the native JNI shared library (libwolfcryptjni.so/dylib) same
as above. This will create the native JNI shared library under the `./lib`
directory:

```
$ cd wolfcrypt-jni
$ cp makefile.linux makefile
$ make
```

Compile the Java sources, where Maven will place the compiled `.class` files
under the `./target/classes` directory:

```
$ mvn compile
```

Compile and run JUnit tests using:

```
$ mvn test
```

Package up the wolfCrypt JNI/JCE JAR file using the following command. This will
run the JUnit tests then create a `.jar` file located under the `./target`
directory, similar to `target/wolfcrypt-jni-X.X.X-SNAPSHOT.jar`:

```
$ mvn package
```

To build the Javadoc API reference for wolfCrypt JNI/JCE run the following. This
will generate Javadoc HTML under the `./docs/apidocs` directory:

```
$ mvn javadoc:javadoc
```

To install the wolfSSL JNI/JCE JAR file, run the following. This will install
the JAR into the local Maven repository:

```
$ mvn install
```

The local Maven repository installation location will be similar to:

```
~/.m2/repository/com/wolfssl/wolfcrypt-jni/X.X.X-SNAPSHOT/wolfcrypt-jni-X.X.X-SNAPSHOT.jar
```

The wolfCrypt JNI shared library (`libwolfcryptjni.so/dylib`) created with
`make` will need to be "installed" by being placed on your native
library search path. For example, copied into `/usr/local/lib`, `/usr/lib`,
or other location. Alternatively, append the `./libs` directory to your native
library search path by exporting `LD_LIBRARY_PATH` (Linux) or
`DYLD_LIBRARY_PATH` (OSX):

```
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/wolfcryptjni/lib
```

After wolfCrypt JNI/JCE has been installed into the local Maven repository,
an application can include this as a dependency in the application's
`pom.xml` file, similar to (where the version number will change depending
on the current release):

```
<project ...>
    ...
    <dependencies>
        <dependency>
            <groupId>com.wolfssl</groupId>
            <artifactId>wolfcrypt-jni</artifactId>
            <version>1.6.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
    ...
</project>
```


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

### Release Notes
---------

Release notes can be found in [ChangeLog.md](./ChangeLog.md).

