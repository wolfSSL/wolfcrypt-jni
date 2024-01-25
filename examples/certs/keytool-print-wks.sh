
# Script to print out WKS keystores using keytool -list
#
# Primarily used as a sanity check that keytool can successfully process
# WKS KeyStore files using the -list command
#
# Export library paths for Linux and Mac to find shared JNI library
export LD_LIBRARY_PATH=../../lib:$LD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=../../lib:$DYLD_LIBRARY_PATH

# ARGS: <keystore file> <password>
print_wks() {
    printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    printf "KEYSTORE: $1\n"
    keytool -list -provider com.wolfssl.provider.jce.WolfCryptProvider --providerpath ../../lib/wolfcrypt-jni.jar -storetype WKS -storepass "$2" -keystore ${1}
    if [ $? -ne 0 ]; then
        printf "fail"
        exit 1
    fi
}

print_wks "client.wks" "wolfSSL test"
print_wks "client-rsa-1024.wks" "wolfSSL test"
print_wks "client-rsa.wks" "wolfSSL test"
print_wks "client-ecc.wks" "wolfSSL test"
print_wks "server.wks" "wolfSSL test"
print_wks "server-rsa-1024.wks" "wolfSSL test"
print_wks "server-rsa.wks" "wolfSSL test"
print_wks "server-ecc.wks" "wolfSSL test"
print_wks "cacerts.wks" "wolfSSL test"
print_wks "ca-client.wks" "wolfSSL test"
print_wks "ca-server.wks" "wolfSSL test"
print_wks "ca-server-rsa-2048.wks" "wolfSSL test"
print_wks "ca-server-ecc-256.wks" "wolfSSL test"

printf "\nSUCCESS printing all KeyStore files\n"
