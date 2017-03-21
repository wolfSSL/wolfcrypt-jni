
## wolfCrypt JCE Provider

The wolfCrypt JCE Provider is currently set up to be compiled together into
the same JAR file as the normal wolfcrypt-jni classes.

The wolfCrypt JCE Provider is located in the following class:

    com.wolfssl.wolfcrypt.jce.provider

Compiling the JCE provider is done using the same instructions as
wolfcrypt-jni. Follow direction in the README.md for compiling the package.

### Algorithm Support:
---------

The JCE provider currently supports the following algorithms:

    MessageDigest Class
        MD5
        SHA-1
        SHA-256
        SHA-384
        SHA-512

    SecureRandom Class
        HashDRBG

    Cipher Class
        AES/CBC/NoPadding
        DESede/CBC/NoPadding
        RSA/ECB/PKCS1Padding

    Mac Class
        HmacMD5
        HmacSHA1
        HmacSHA256
        HmacSHA384
        HmacSHA512

    Signature Class
        MD5withRSA
        SHA1withRSA
        SHA256withRSA
        SHA384withRSA
        SHA512withRSA
        SHA1withECDSA
        SHA256withECDSA
        SHA384withECDSA
        SHA512withECDSA

    KeyAgreement Class
        DiffieHellman
        DH
        ECDH

### Example / Test Code
---------

Example code will be added in the near future. JUnit test code is located
under the "./src/test/com/wolfssl/provider/jce/" directory for each wolfJCE
engine class.

### Support
---------

Please email support@wolfssl.com with any questions or feedback.

