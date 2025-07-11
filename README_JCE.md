
## wolfCrypt JCE Provider

The wolfCrypt JCE Provider is currently set up to be compiled together into
the same JAR file as the normal wolfcrypt-jni classes.

The wolfCrypt JCE Provider is located in the following package:

    com.wolfssl.wolfcrypt.jce.provider

Compiling the JCE provider is done using the same instructions as
wolfcrypt-jni. Follow direction in the README.md for compiling the package,
but make sure to use one of the following "ant" build targets:

    build-jce-debug
    build-jce-release

This JCE provider has been tested on OSX (Oracle JVM), Linux (OpenJDK),
and Android platforms.

Pre-compiled and signed wolfCrypt JNI/JCE JAR's are included with the stable
releases of the JCE provider. See below for more details.

### System and Security Property Support
---------

wolfJCE supports the following System and Security properties for behavior
customization and debugging.

#### Security Property Support

The following Java Security properties can be set in the `java.security`
file for JCE provider customization:

| Security Property | Default | To Enable | Description |
| --- | --- | --- | --- |
| wolfjce.wks.iterationCount | 210,000 | Numeric | PBKDF2 iteration count (10,000 minimum) |
| wolfjce.wks.maxCertChainLength | 100 | Integer | Max cert chain length |
| wolfjce.mapJKStoWKS | UNSET | true | Register fake JKS KeyStore service mapped to WKS |
| wolfjce.mapPKCS12toWKS | UNSET | true | Register fake PKCS12 KeyStore service mapped to WKS |

**wolfjce.mapJKStoWKS** - this Security property should be used with caution.
When enabled, this will register a "JKS" KeyStore type in wolfJCE, which means
calling applications using `KeyStore.getInstance("JKS")` will get a KeyStore
implementation from wolfJCE. BUT, this KeyStore type will actually be a
WolfSSLKeyStore (WKS) type internally. Loading actual JKS files will fail.
This can be helpful when FIPS compliance is required, but existing code gets
a JKS KeyStore instance - and this assumes the caller has the flexibility to
actually load a real WKS KeyStore file into this KeyStore object. If this
property is being set at runtime programatically, the wolfJCE provider services
will need to be refreshed / reloaded, by doing:

```
WolfCryptProvider prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
prov.refreshServices();
```

**wolfjce.mapPKCS12toWKS** - this Security property should be used with caution.
When enabled, this will register a "PKCS12" KeyStore type in wolfJCE, which
means calling applications using `KeyStore.getInstance("PKCS12")` will get a
KeyStore implementation from wolfJCE. BUT, this KeyStore type will actually be a
WolfSSLKeyStore (WKS) type internally. Loading actual PKCS12 files will fail.
This can be helpful when FIPS compliance is required, but existing code gets
a PKCS12 KeyStore instance - and this assumes the caller has the flexibility to
actually load a real WKS KeyStore file into this KeyStore object. If this
property is being set at runtime programatically, the wolfJCE provider services
will need to be refreshed / reloaded, by doing:

```
WolfCryptProvider prov = (WolfCryptProvider)Security.getProvider("wolfJCE");
prov.refreshServices();
```

#### System Property Support

The following Java System properties can be set on the command line or
programatically for JCE provider customization:

| System Property | Default | To Enable | Description |
| --- | --- | --- | --- |
| wolfjce.debug | "false" | "true" | Enable wolfJCE debug logging |

### Algorithm Support:
---------

The JCE provider currently supports the following algorithms:

    MessageDigest Class
        MD5
        SHA-1
        SHA-224
        SHA-256
        SHA-384
        SHA-512
        SHA3-224
        SHA3-256
        SHA3-384
        SHA3-512

    SecureRandom Class
        DEFAULT (maps to HashDRBG)
        HashDRBG

    Cipher Class
        AES/CBC/NoPadding
        AES/CBC/PKCS5Padding
        AES/ECB/NoPadding
        AES/ECB/PKCS5Padding
        AES/GCM/NoPadding
        DESede/CBC/NoPadding
        RSA
        RSA/ECB/PKCS1Padding

    Mac Class
        HmacMD5
        HmacSHA1
        HmacSHA224
        HmacSHA256
        HmacSHA384
        HmacSHA512
        HmacSHA3-224
        HmacSHA3-256
        HmacSHA3-384
        HmacSHA3-512

    Signature Class
        MD5withRSA
        SHA1withRSA
        SHA224withRSA
        SHA256withRSA
        SHA384withRSA
        SHA512withRSA
        SHA3-224withRSA
        SHA3-256withRSA
        SHA3-384withRSA
        SHA3-512withRSA
        SHA1withECDSA
        SHA224withECDSA
        SHA256withECDSA
        SHA384withECDSA
        SHA512withECDSA
        SHA3-224withECDSA
        SHA3-256withECDSA
        SHA3-384withECDSA
        SHA3-512withECDSA

    KeyAgreement Class
        DiffieHellman
        DH
        ECDH

    KeyGenerator
        AES
        HmacSHA1
        HmacSHA224
        HmacSHA256
        HmacSHA384
        HmacSHA512

    KeyPairGenerator Class
        RSA
        EC
        DH

    CertPathValidator Class
        PKIX

    SecretKeyFactory
        PBKDF2WithHmacSHA1
        PBKDF2WithHmacSHA224
        PBKDF2WithHmacSHA256
        PBKDF2WithHmacSHA384
        PBKDF2WithHmacSHA512
        PBKDF2WithHmacSHA3-224
        PBKDF2WithHmacSHA3-256
        PBKDF2WithHmacSHA3-384
        PBKDF2WithHmacSHA3-512

    KeyStore
        WKS

### SecureRandom.getInstanceStrong()

When registered as the highest priority security provider, wolfJCE will provide
`SecureRandom` with the underlying `HashDRBG` algorithm.

Java applications can alternatively call the `SecureRandom.getInstanceStrong()`
API to get a "known strong SecureRandom implementation". To provide this
with wolfJCE, the `java.security` file needs to be modified by setting the
`securerandom.strongAlgorithms` property to:

```
securerandom.strongAlgorithms=HashDRBG:wolfJCE
```

Note that the `securerandom.source` property in `java.security` has no affect
on the wolfJCE provider.

### WolfSSLKeyStore (WKS) Implementation Details and Usage

wolfJCE implements one custom KeyStore class named WolfSSLKeyStore, represented
as "WKS". If wolfJCE has been installed as a Security provider, this KeyStore
can be used with:

```
KeyStore store = KeyStore.getInstance("WKS");
```

#### Algorithm Use and FIPS 140-2 / 140-3 Compatibility

The WKS KeyStore has been designed to be compatible with wolfCrypt
FIPS 140-2 and 140-3.

PrivateKey and SecretKey objects stored are protected inside the KeyStore
using AES-CBC-256 with HMAC-SHA512 in an Encrypt-then-MAC manner. PKCS#5
PBKDF2-HMAC-SHA512 is used to generate 96 bytes of key material which is split
between a 32-byte AES-CBC-256 key and 64-byte HMAC-SHA512 key.

PBKDF2 salt is 16 bytes, randomly generated for each key storage operation
PBKDF2 iteration count defaults to 210,000 (current OWASP recommendation), but
is user overridable with wolfjce.wks.iterationCount Security property in
java.security file. User password is converted from char[] to byte[] using
UTF-8, consistent with how SunJCE uses UTF-8 for PBKDF2 SecretKeyFactory.
AES-CBC IV is randomly generated for each key storage operation

This KeyStore uses a different format that is not directly compatible with
existing formats (ex: JKS, PKCS12, etc). Other KeyStore types will need to be
converted over to WKS KeyStore objects for FIPS compliant use with wolfCrypt
FIPS 140-2/3.

#### Stored Object Compatibility

The WKS KeyStore supports storage of PrivateKey, Certificate, and
SecretKey objects.

#### Converting Other KeyStore Formats to WKS

The Java `keytool` application can be used to convert between KeyStore formats.
This can be easily used to convert a JKS KeyStore into a WKS format KeyStore.

The following example command would convert a KeyStore in JKS format named
`server.jks` to a KeyStore in WKS format named `server.wks`:

```
keytool -importkeystore -srckeystore server.jks -destkeystore server.wks \
    -srcstoretype JKS -deststoretype WKS \
    -srcstorepass "pass" -deststorepass "pass" \
    -provider com.wolfssl.provider.jce.WolfCryptProvider \
    --providerpath /path/to/wolfcrypt-jni.jar
```

Additionally, wolfJCE provides a utility method `WolfCryptUtil.convertKeyStoreToWKS()` 
that can be used programmatically to convert KeyStore formats. This method
supports converting from JKS, PKCS12, and WKS formats to WKS format. When
converting from WKS to WKS, the method efficiently returns the same input
stream without performing any conversion.

The method automatically detects the input KeyStore format and handles the
conversion appropriately. It supports the following features:

- Automatic format detection (WKS, JKS, PKCS12)
- Preservation of all certificates and keys from the source KeyStore
- Support for both key entries (with certificate chains) and certificate-only entries
- Efficient handling of WKS input (returns same stream)
- Proper stream handling with mark/reset support for large KeyStores

**FIPS NOTE:** This utility method will call Sun provider code for JKS
and PKCS12. This means that if using wolfCrypt FIPS, these calls will make
calls into non-FIPS compliant cryptography for the conversion. Please take
this into consideration when being used in a FIPS compliant environment.

Example usage:

```java
import com.wolfssl.provider.jce.WolfCryptUtil;
import java.io.InputStream;
import java.security.KeyStore;

/* Load your source KeyStore (JKS, PKCS12, or WKS) */
InputStream sourceStream = ...;
char[] password = "your_password".toCharArray();

/* Convert to WKS format, fail on insert errors */
InputStream wksStream = WolfCryptUtil.convertKeyStoreToWKS(sourceStream, password, true);

/* Load the converted WKS KeyStore */
KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
wksStore.load(wksStream, password);
```

The method respects the Security properties `wolfjce.mapJKStoWKS` and 
`wolfjce.mapPKCS12toWKS` when performing conversions. If these properties are
set to "true", the method will use reflection to find the Sun provider
implementations for JKS and PKCS12 to use for conversion.

To list entries inside a WKS keystore using the `keytool`, a command
similar to the following can be used (with the `-list` option):

```
keytool -list -provider com.wolfssl.provider.jce.WolfCryptProvider \
    --providerpath /path/to/wolfcrypt-jni.jar \
    -storetype WKS -storepass "pass" -keystore server.wks
```

If running the above commands gives an error about the native wolfcryptjni
shared library not being found, you may need to add the library location
to `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (Mac OSX), ie:

```
export LD_LIBRARY_PATH=/path/to/libwolfcryptjni.so:$LD_LIBRARY_PATH
```

#### Converting System cacerts to WKS Format KeyStore

For FIPS compatibility, users who do not want to use non-wolfSSL KeyStore
implementations (ex: JKS) may need to convert the system cacerts or
jssecacerts KeyStore to WKS format. This can be done using the keytool
command as described above (default password for cacerts is 'changeit'), or
the helper script located in this package at:

```
examples/certs/systemcerts/system-cacerts-to-wks.sh
```

This is a shell script that takes no arguments. It tries to detect the
location of the active Java installation and converts `cacerts` and/or
`jssecacerts` to WKS format if they are found. Converted KeyStores are placed
under the same directory as the script, specifically:

```
examples/certs/systemcerts/cacerts.wks
examples/certs/systemcerts/jssecacerts.wks
```

#### Design Notes

More complete design documentation can be found in
[docs/WolfSSLKeyStore.md](./docs/design/WolfSSLKeyStore.md).

### Example / Test Code
---------

JUnit test code can act as a good usage reference, and is located under the
`./src/test/java/com/wolfssl/provider/jce/test/` directory for each wolfJCE
engine class.

There are some JCE examples located under the `examples/provider` directory,
including:

**ProviderTest**

This is an example that prints out all Security providers that are registered
in the system. It then programatically registers wolfJCE as the highest-level
provider and prints out the list again.

This example will be built when using the following ant targets:

```
$ ant build-jce-debug
$ ant build-jce-release
```

The example can then be run using:

```
$ ./examples/provider/ProviderTest.sh
```

**CryptoBenchmark**

This example benchmarks the performance of cryptographic operations using the
wolfJCE provider. It tests AES-CBC with 256-bit key encryption/decryption
operations.

Build and run:

```
# From wolfcrypt-jni root directory
make                      # Build native library
ant build-jce-release     # Build JCE JAR

# Run benchmark
./examples/provider/CryptoBenchmark.sh
```

This script requires for `JAVA_HOME` to be set.

For Bouncy Castle comparison testing:

CryptoBenchmark.sh will prompt with the following:

```
Would you like to download Bouncy Castle JARs? (y/n)
```

If you respond with 'y', the script will download the Bouncy Castle JARs and
run the benchmark with Bouncy Castle. At the end of the benchmark, the script
will prompt whether or not to remove the Bouncy Castle JAR files.

If you prefer to download the JARs manually, follow the instructions below:

Visit [bouncy-castle-java](https://www.bouncycastle.org/download/bouncy-castle-java/)

Download:

```
bcprov-jdk18on-1.79.jar # Bouncy Castle Provider
bctls-jdk18on-1.79.jar  # Bouncy Castle DTLS/TLS API/JSSE Provider
```

Copy jar files to wolfcrypt-jni/lib/:

```
cp bcprov-jdk18on-1.79.jar wolfcrypt-jni/lib
cp bctls-jdk18on-1.79.jar wolfcrypt-jni/lib
```

### JAR Code Signing
---------

The Oracle JDK/JVM requires that JCE providers who implement several of the
classes above be signed by a code signing certificate issued by Oracle.

Full details on obtaining a JCE Code Signing Certifciate can be found here:

http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html

For instructions on signing the "wolfcrypt-jni.jar" file generated by the
ant build system, please see the main README.md included in this package.

### Using a Pre-Signed JAR File

wolfSSL (company) has it's own set of code signing certificates from Oracle
that allow wolfJCE to be authenticated in the Oracle JDK.  With each release
of wolfJCE, wolfSSL ships a couple pre-signed versions of the
'wolfcrypt-jni.jar", located at:

wolfcrypt-jni-X.X.X/lib/signed/debug/wolfcrypt-jni.jar
wolfcrypt-jni-X.X.X/lib/signed/release/wolfcrypt-jni.jar

This pre-signed JAR can be used with the JUnit tests, without having to
re-compile the Java source files.  To run the JUnit tests against this
JAR file:
 
$ cd wolfcrypt-jni-X.X.X
$ cp ./lib/signed/release/wolfcrypt-jni.jar ./lib
$ ant test


### Support
---------

Please email support@wolfssl.com with any questions or feedback.

The wolfJCE User Manual (PDF), available from the wolfSSL website contains
additional details on using the wolfCrypt JCE provider.

