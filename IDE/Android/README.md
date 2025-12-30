# Android Studio Example Project

This is an example Android Studio project file for wolfcrypt-jni / wolfJCE.
This project should be used for reference only.

Tool and version information used when testing this project:

- Ubuntu 20.04.3 LTS
- Android Studio Chipmunk 2021.2.1
- Android Gradle Plugin Version: 4.2.2
- Gradle Version: 7.1.3
- API 30: Android 11
- Emulator: Pixel 5 API 31

The following sections outline steps required to run this example on an
Android device or emulator.

## 1. Add Native wolfSSL Library Source Code to Project

This example project is already set up to compile and build the native
wolfSSL library source files, but the wolfSSL files themselves have not been
included in this package. You must download or link an appropriate version
of wolfSSL to this project using one of the options below.

The project looks for the directory
`wolfcrypt-jni/IDE/Android/app/src/main/cpp/wolfssl` for wolfSSL source code.
This can added in multiple ways:

- OPTION A: Download the latest wolfSSL library release from www.wolfssl.com,
unzip it, rename it to `wolfssl`, and place it in the direcotry
`wolfcrypt-jni/IDE/Android/app/src/main/cpp/`.

```
$ unzip wolfssl-X.X.X.zip
$ mv wolfssl-X.X.X wolfcrypt-jni/IDE/Android/app/src/main/cpp/wolfssl
```

- OPTION B: Alternatively GitHub can be used to clone wolfSSL:

```
$ cd /IDE/Android/app/src/main/cpp/
$ git clone https://github.com/wolfssl/wolfssl
$ cp wolfssl/options.h.in wolfssl/options.h
```

- OPTION C: A symbolic link to a wolfssl directory on the system by using:

```
$ cd /IDE/Android/app/src/main/cpp/
$ ln -s /path/to/local/wolfssl ./wolfssl
```

## 2. Update Java Symbolic Links (Only applies to Windows Users)

The following Java source directory is a Unix/Linux symlink:

```
wolfcrypt-jni/IDE/Android/app/src/main/java/com/wolfssl
```

This will not work correctly on Windows, and a new Windows symbolic link needs
to be created in this location. To do so:

1) Open Windows Command Prompt (Right click, and "Run as Administrator")
2) Navigate to `wolfcrypt-jni\IDE\Android\app\src\main\java\com`
3) Delete the existing symlink file (it shows up as a file called "wolfssl")

```
del wolfssl
```

4) Create a new relative symbolic link with `mklink`:

```
mklink /D wolfssl ..\..\..\..\..\..\..\src\java\com\wolfssl\
```

## 3. Push Certificate and KeyStore Files to Android Device

Several JUnit tests require access to certificate and KeyStore files. These
files are located in the `examples/certs` directory and must be pushed to
the Android device or emulator before running tests.

Start the emulator or connect your device, then use `adb push` from the root
wolfcrypt-jni directory. This step can be done after starting Android Studio
and compiling the project, but must be done before running the test cases.

```
adb shell mkdir -p /data/local/tmp/examples/certs/intermediate
adb shell mkdir -p /data/local/tmp/examples/certs/rsapss
adb shell mkdir -p /data/local/tmp/examples/certs/crl
adb push ./examples/certs/ /data/local/tmp/examples/
```

This will push all certificate files, KeyStore files (.jks, .wks, .p12),
and subdirectories (intermediate, rsapss, crl) needed by the JUnit tests.

If this step is skipped, tests in the following classes will be skipped due
to missing certificate files:

- `WolfSSLKeyStoreTest`
- `WolfCryptPKIXCertPathValidatorTest`
- `WolfCryptPKIXRevocationCheckerTest`
- `WolfSSLCertManagerOCSPTest`

## 4. Import and Build the Example Project with Android Studio

1) Open the Android Studio project by double clicking on the `Android` folder
in wolfcrypt-jni/IDE/. Or, from inside Android Studio, open the `Android`
project located in the wolfcrypt-jni/IDE directory.

2) Build the project and run MainActivity from app -> java/com/example.wolfssl.
This will ask for permissions to access the certificates in the /sdcard/
directory and then print out the server certificate information on success.

## Support

Please contact wolfSSL support at support@wolfssl.com with any questions or
feedback.

