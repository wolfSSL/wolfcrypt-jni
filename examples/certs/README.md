
# Example and Test Certificates, Keys, and KeyStore Files

This directory contains example certificates, keys, and Java KeyStore
files used for testing and examples.

These certificates and keys have been copied over from the wolfSSL proper
example certs directory.

If new certs/keys are needed or added here, consider if they should also be
added to wolfSSL proper.

## Updating Example Certificates and Keys

To update the example certificates and keys, use the provided
`update-certs.sh` bash script. This script requires one argument on the
command line which is the location of the wolfSSL proper certs directory.

```
$ cd wolfcryptjni/examples/certs
$ ./update-certs.sh /path/to/wolfssl/certs
```

This script only updates the .pem and .der certificate and key files. To update
the example Java KeyStore files, see the next section.

## Updating Example Java KeyStore Files

To update the example Java KeyStore files, use the provided `update-jks-wks.sh`
bash script. This script requires one argument on the command line which is
the location of the wolfSSL proper certs directory.

This script will create new KeyStore files from original certificates. It will
first create JKS KeyStore files, then convert those to WKS (WolfSSLKeyStore)
format.

```
$ cd wolfcryptjni/examples/certs
$ ./update-jks-wks.sh /path/to/wolfssl/certs
```

This script only updates the example .jks and .wks files and not the individual
.pem or .der files in this directory. For that, please see the above section.

## Testing that Java keytool can read/parse WKS files

To confirm that Java keytool can parse WolfSSLKeyStore (WKS) format stores OK,
the `keytool-print-wks.sh` script can be used. This will call `keytool -list`
on each WKS KeyStore which is expected to pass successfully.

## Support

Please contact the wolfSSL support team at support@wolfssl.com with any
questions or feedback.

