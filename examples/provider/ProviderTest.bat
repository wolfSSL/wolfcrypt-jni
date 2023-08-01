
cd %~dp0\..\build >NUL 2>NUL
SETLOCAL

:: Populate correct config for build
call ..\WindowsConfig.bat

:: Set PATH to include DLL for native wolfSSL and wolfSSL JNI (native library)
SET PATH="%WOLFCRYPTJNI_DLL_DIR%;%WOLFSSL_DLL_DIR%";%PATH%

java -cp ".;.\provider;..\..\lib\wolfcrypt-jni.jar" -Djava.library.path="%WOLFCRYPTJNI_DLL_DIR%;%WOLFSSL_DLL_DIR%" ProviderTest

ENDLOCAL
cd %~dp0\..\..
