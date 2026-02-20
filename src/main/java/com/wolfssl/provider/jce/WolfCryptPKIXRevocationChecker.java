/* WolfCryptPKIXRevocationChecker.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jce;

import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.Extension;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptException;

import java.security.cert.TrustAnchor;
import javax.security.auth.x500.X500Principal;

/**
 * wolfJCE implementation of PKIXRevocationChecker.
 *
 * This implementation supports:
 *   - OCSP checking via native wolfSSL OCSP implementation
 *   - CRL checking (when PREFER_CRLS option is set)
 *   - Standard PKIXRevocationChecker.Option values
 *   - OCSP responder URL override
 *   - Pre-loaded OCSP responses (OCSP stapling)
 *   - Soft-fail exception collection
 *
 * Note: This checker must be used with WolfCryptPKIXCertPathValidator.
 */
public class WolfCryptPKIXRevocationChecker extends PKIXRevocationChecker {

    /* Configuration */
    private URI ocspResponder;
    private X509Certificate ocspResponderCert;
    private List<Extension> ocspExtensions;
    private Map<X509Certificate, byte[]> ocspResponses;
    private Set<Option> options;
    private List<CertPathValidatorException> softFailExceptions;

    /* Reference to WolfSSLCertManager for OCSP operations */
    private WolfSSLCertManager certManager;

    /* State Tracking */
    private boolean initialized;

    /* Full certificate chain for finding issuers */
    private List<X509Certificate> certChain;

    /* Trust anchors for determining if issuer is a trust anchor */
    private Set<TrustAnchor> trustAnchors;

    /* Last applied I/O timeout value from wolfjce.ioTimeout property.
     * Used to skip redundant JNI calls when multiple checkers or
     * repeated init() calls read the same property value. wolfIO_SetTimeout()
     * sets a global value, so all checkers in the JVM share the same timeout.
     * Integer.MIN_VALUE indicates no timeout has been applied yet. */
    private static volatile int lastAppliedIOTimeout =
        Integer.MIN_VALUE;

    /**
     * Create new WolfCryptPKIXRevocationChecker.
     */
    public WolfCryptPKIXRevocationChecker() {

        this.ocspResponder = null;
        this.ocspResponderCert = null;
        this.ocspExtensions = null;
        this.ocspResponses = new HashMap<X509Certificate, byte[]>();
        this.options = EnumSet.noneOf(Option.class);
        this.certManager = null;
        this.initialized = false;
        this.certChain = null;
        this.trustAnchors = null;
        this.softFailExceptions =
            new ArrayList<CertPathValidatorException>();
    }

    /**
     * Set CertManager for OCSP operations.
     *
     * @param cm WolfSSLCertManager to use for OCSP checking
     */
    public void setCertManager(WolfSSLCertManager cm) {
        this.certManager = cm;
    }

    /**
     * Set certificate chain for finding issuers during OCSP validation.
     *
     * The chain should be ordered from end-entity (index 0) toward root.
     * This allows the revocation checker to find the issuer certificate
     * for any certificate being checked.
     *
     * @param chain List of certificates in the chain
     */
    public void setCertChain(List<X509Certificate> chain) {
        this.certChain = chain;
    }

    /**
     * Set trust anchors for OCSP validation.
     *
     * Trust anchors are used to determine if a certificate's issuer is a
     * trust anchor. If the issuer is a trust anchor with an actual
     * certificate, that certificate is loaded so OCSP response verification
     * can succeed.
     *
     * @param anchors Set of trust anchors
     */
    public void setTrustAnchors(Set<TrustAnchor> anchors) {
        this.trustAnchors = anchors;
    }

    /**
     * Initialize the checker for certificate path validation.
     *
     * @param forward true if checking in forward direction,
     *                false for reverse
     * @throws CertPathValidatorException if initialization fails
     */
    @Override
    public void init(boolean forward) throws CertPathValidatorException {

        this.initialized = true;
        this.softFailExceptions.clear();

        /* Set wolfSSL I/O timeout for HTTP-based operations (OCSP lookups,
         * CRL fetching) if 'wolfjce.ioTimeout' System property is set. */
        setIOTimeoutFromProperty();

        /* Verify we have OCSP support if needed */
        if (!options.contains(Option.PREFER_CRLS)) {
            if (!WolfCrypt.OcspEnabled()) {
                String msg = "OCSP not compiled into native wolfSSL";
                if (options.contains(Option.SOFT_FAIL)) {
                    softFailExceptions.add(
                        new CertPathValidatorException(msg,
                            null, null, -1,
                            BasicReason.UNDETERMINED_REVOCATION_STATUS));
                    return;

                } else {
                    throw new CertPathValidatorException(msg);
                }
            }
        }

        /* Configure CertManager if present */
        if (certManager != null) {
            try {
                /* Enable OCSP if not preferring CRLs */
                if (!options.contains(Option.PREFER_CRLS)) {
                    int ocspOptions = 0;

                    /* Check all certs unless ONLY_END_ENTITY specified */
                    if (!options.contains(Option.ONLY_END_ENTITY)) {
                        ocspOptions |= WolfCrypt.WOLFSSL_OCSP_CHECKALL;
                    }

                    certManager.CertManagerEnableOCSP(ocspOptions);

                    /* Set override URL if specified */
                    if (ocspResponder != null) {
                        certManager.CertManagerSetOCSPOverrideURL(
                            ocspResponder.toString());
                    }
                }

            } catch (WolfCryptException e) {
                if (options.contains(Option.SOFT_FAIL)) {
                    softFailExceptions.add(
                        new CertPathValidatorException(
                            "Failed to initialize OCSP: " + e.getMessage(),
                            e, null, -1,
                            BasicReason.UNDETERMINED_REVOCATION_STATUS));
                } else {
                    throw new CertPathValidatorException(
                        "Failed to initialize OCSP", e);
                }
            }
        }
    }

    /**
     * Check if forward checking is supported.
     *
     * @return false - wolfSSL validates in reverse order
     */
    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    /**
     * Get set of supported extensions.
     *
     * @return empty set - no critical extensions are processed
     */
    @Override
    public Set<String> getSupportedExtensions() {
        return Collections.<String>emptySet();
    }

    /**
     * Check the revocation status of a certificate.
     *
     * @param cert Certificate to check
     * @param unresolvedCritExts Collection of unresolved critical extensions
     * @throws CertPathValidatorException if certificate is revoked or
     *         check fails
     */
    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts)
        throws CertPathValidatorException {

        boolean preferCrls, noFallback;

        if (!initialized) {
            throw new CertPathValidatorException(
                "RevocationChecker not initialized");
        }

        if (!(cert instanceof X509Certificate)) {
            throw new CertPathValidatorException(
                "Certificate is not an X509Certificate");
        }

        X509Certificate x509Cert = (X509Certificate)cert;

        /* Check for pre-loaded OCSP response first (OCSP stapling) */
        if (ocspResponses.containsKey(x509Cert)) {
            checkPreloadedOcspResponse(x509Cert);
            return;
        }

        preferCrls = options.contains(Option.PREFER_CRLS);
        noFallback = options.contains(Option.NO_FALLBACK);

        if (preferCrls) {
            /* PREFER_CRLS set: Skip OCSP here, rely on CRL checking done by
             * WolfCryptPKIXCertPathValidator. CRLs are loaded into the
             * CertManager via checkRevocationEnabledAndLoadCRLs() and
             * checked automatically during CertManagerVerify() which
             * happens after this check() method returns.
             *
             * If NO_FALLBACK is not set, also try OCSP as secondary check. */
            if (!noFallback) {
                try {
                    checkOcsp(x509Cert);
                } catch (CertPathValidatorException e) {
                    /* OCSP failed, but CRL is primary - let CRL checking
                     * in CertManagerVerify() handle revocation status */
                    handleException(e);
                }
            }
            /* CRL checking happens in CertManagerVerify() after this */
        }
        else {
            /* OCSP is primary revocation check method */
            try {
                checkOcsp(x509Cert);
                return; /* OCSP succeeded */

            } catch (CertPathValidatorException e) {
                /* OCSP failed. If NO_FALLBACK, fail now. Otherwise, CRL
                 * checking in CertManagerVerify() serves as implicit
                 * fallback (if CRL is enabled in PKIXParameters). */
                handleException(e);
            }
        }
    }

    /**
     * Check certificate via OCSP.
     *
     * @param cert Certificate to check
     * @throws CertPathValidatorException if check fails or cert is revoked
     */
    private void checkOcsp(X509Certificate cert)
        throws CertPathValidatorException {

        byte[] certDer;

        if (certManager == null) {
            throw new CertPathValidatorException(
                "CertManager not available for OCSP checking");
        }

        /* Load issuer cert so OCSP response signature can be verified */
        loadIssuerForOcspVerification(cert);

        try {
            certDer = cert.getEncoded();
            certManager.CertManagerCheckOCSP(certDer, certDer.length);

        } catch (CertificateEncodingException e) {
            throw new CertPathValidatorException(
                "Failed to encode certificate", e);

        } catch (WolfCryptException e) {
            throw new CertPathValidatorException(
                "OCSP check failed: " + e.getMessage(), e,
                null, -1, BasicReason.UNDETERMINED_REVOCATION_STATUS);
        }
    }

    /**
     * Find and load the issuer certificate for OCSP response verification.
     *
     * OCSP responses are typically signed by the issuer of the certificate
     * being checked. This method finds the issuer in the certificate chain
     * or trust anchors and loads it into the CertManager so the OCSP
     * response signature can be verified.
     *
     * For the last certificate in the chain, the issuer is typically a
     * trust anchor. If the trust anchor has an actual certificate, it is
     * loaded for OCSP verification.
     *
     * @param cert Certificate whose issuer should be loaded
     */
    private void loadIssuerForOcspVerification(X509Certificate cert) {

        if (certManager == null) {
            return;
        }

        /* Find cert's position in the chain */
        int certIndex = -1;
        if (certChain != null) {
            for (int i = 0; i < certChain.size(); i++) {
                if (certChain.get(i).equals(cert)) {
                    certIndex = i;
                    break;
                }
            }
        }

        /* Issuer is the next cert in the chain (if it exists) */
        if (certChain != null && certIndex >= 0 &&
            certIndex + 1 < certChain.size()) {

            X509Certificate issuer = certChain.get(certIndex + 1);

            /* Only load if this is a CA certificate */
            if (issuer.getBasicConstraints() >= 0) {
                try {
                    certManager.CertManagerLoadCA(issuer);
                } catch (WolfCryptException e) {
                    /* Ignore - may already be loaded or not needed */
                }
            }
        }
        else if (certIndex >= 0 && trustAnchors != null) {
            /* Last cert in chain - issuer may be a trust anchor.
             * Look for a trust anchor with a certificate that matches
             * this cert's issuer. */
            X500Principal issuerPrincipal = cert.getIssuerX500Principal();

            for (TrustAnchor anchor : trustAnchors) {
                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null) {
                    /* Trust anchor has a certificate - check if it's
                     * the issuer of our cert */
                    if (anchorCert.getSubjectX500Principal().equals(
                            issuerPrincipal)) {
                        try {
                            certManager.CertManagerLoadCA(anchorCert);
                        } catch (WolfCryptException e) {
                            /* Ignore - may already be loaded */
                        }
                        break;
                    }
                }
            }
        }
    }

    /**
     * Get human readable name for OCSPResponseStatus value.
     *
     * Per RFC 6960, OCSPResponseStatus ::= ENUMERATED {
     *     successful (0), malformedRequest (1), internalError (2),
     *     tryLater (3), sigRequired (5), unauthorized (6) }
     *
     * @param status OCSPResponseStatus value
     * @return status name string
     */
    private String getOcspResponseStatusName(int status) {

        switch (status) {
            case 0:
                return "SUCCESSFUL";
            case 1:
                return "MALFORMED_REQUEST";
            case 2:
                return "INTERNAL_ERROR";
            case 3:
                return "TRY_LATER";
            case 5:
                return "SIG_REQUIRED";
            case 6:
                return "UNAUTHORIZED";
            default:
                return "UNKNOWN(" + status + ")";
        }
    }

    /**
     * Check pre-loaded OCSP response.
     *
     * Note: PKIXParameters.setDate() does not affect OCSP response validation.
     * OCSP responses are always validated against current system time by
     * wolfSSL. Date override only applies to certificate validity checking.
     *
     * @param cert Certificate to check
     * @throws CertPathValidatorException if response is invalid or
     *         cert is revoked
     */
    private void checkPreloadedOcspResponse(X509Certificate cert)
        throws CertPathValidatorException {

        int ocspStatus;
        byte[] response;
        byte[] certDer;

        response = ocspResponses.get(cert);
        if (response == null || response.length == 0) {
            throw new CertPathValidatorException(
                "Empty OCSP response for certificate: " +
                cert.getSubjectX500Principal());
        }

        if (certManager == null) {
            throw new CertPathValidatorException(
                "CertManager not available for OCSP response checking");
        }

        /* Check OCSP response status before native verification.
         * Non-successful OCSP responses (e.g. UNAUTHORIZED, TRY_LATER) should
         * be reported as errors per RFC 6960. Use native wolfSSL to parse the
         * response status from raw DER bytes. */
        ocspStatus = WolfSSLCertManager.getOcspResponseStatus(response,
            response.length);
        if (ocspStatus > 0) {
            throw new CertPathValidatorException("OCSP response error: " +
                getOcspResponseStatusName(ocspStatus));
        }
        else if (ocspStatus < 0) {
            throw new CertPathValidatorException(
                "Failed to parse OCSP response status: " + ocspStatus);
        }

        /* Load issuer cert so OCSP response signature can be verified */
        loadIssuerForOcspVerification(cert);

        try {
            certDer = cert.getEncoded();

            certManager.CertManagerCheckOCSPResponse(response, response.length,
                certDer, certDer.length);

        } catch (CertificateEncodingException e) {
            throw new CertPathValidatorException(
                "Failed to encode certificate", e);

        } catch (WolfCryptException e) {
            throw new CertPathValidatorException(
                "OCSP response check failed: " + e.getMessage(), e,
                null, -1, BasicReason.UNDETERMINED_REVOCATION_STATUS);
        }
    }

    /**
     * Handle exception based on SOFT_FAIL option.
     *
     * @param e Exception to handle
     * @throws CertPathValidatorException if not in soft-fail mode
     */
    private void handleException(CertPathValidatorException e)
        throws CertPathValidatorException {

        if (options.contains(Option.SOFT_FAIL)) {
            softFailExceptions.add(e);
        } else {
            throw e;
        }
    }

    /**
     * Set OCSP responder URI override.
     *
     * @param uri OCSP responder URI
     */
    @Override
    public void setOcspResponder(URI uri) {
        this.ocspResponder = uri;
    }

    /**
     * Get OCSP responder URI override.
     *
     * @return OCSP responder URI or null if not set
     */
    @Override
    public URI getOcspResponder() {
        return this.ocspResponder;
    }

    /**
     * Set OCSP responder certificate.
     *
     * @param cert OCSP responder certificate
     */
    @Override
    public void setOcspResponderCert(X509Certificate cert) {
        this.ocspResponderCert = cert;
    }

    /**
     * Get OCSP responder certificate.
     *
     * @return OCSP responder certificate or null if not set
     */
    @Override
    public X509Certificate getOcspResponderCert() {
        return this.ocspResponderCert;
    }

    /**
     * Set OCSP extensions.
     *
     * @param extensions List of OCSP extensions
     */
    @Override
    public void setOcspExtensions(List<Extension> extensions) {
        if (extensions == null) {
            this.ocspExtensions = null;
        } else {
            this.ocspExtensions =
                new ArrayList<Extension>(extensions);
        }
    }

    /**
     * Get OCSP extensions.
     *
     * @return List of OCSP extensions, empty list if not set
     */
    @Override
    public List<Extension> getOcspExtensions() {
        if (this.ocspExtensions == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(this.ocspExtensions);
    }

    /**
     * Set pre-loaded OCSP responses (for OCSP stapling).
     *
     * @param responses Map of certificates to OCSP response bytes
     */
    @Override
    public void setOcspResponses(Map<X509Certificate, byte[]> responses) {
        if (responses == null) {
            this.ocspResponses = new HashMap<X509Certificate, byte[]>();
        } else {
            this.ocspResponses =
                new HashMap<X509Certificate, byte[]>(responses);
        }
    }

    /**
     * Get pre-loaded OCSP responses.
     *
     * Returns the internal mutable map, not an unmodifiable copy.
     * JDK sun.security.validator.PKIXValidator.addResponses() expects
     * to be able to add OCSP responses to this map when using the internal
     * Validator API.
     *
     * @return Map of certificates to OCSP response bytes
     */
    @Override
    public Map<X509Certificate, byte[]> getOcspResponses() {
        return this.ocspResponses;
    }

    /**
     * Set revocation checker options.
     *
     * @param options Set of Option values
     */
    @Override
    public void setOptions(Set<Option> options) {
        if (options == null) {
            this.options = EnumSet.noneOf(Option.class);
        } else {
            this.options = EnumSet.copyOf(options);
        }
    }

    /**
     * Get revocation checker options.
     *
     * @return Set of Option values
     */
    @Override
    public Set<Option> getOptions() {
        return Collections.unmodifiableSet(this.options);
    }

    /**
     * Get list of exceptions encountered in soft-fail mode.
     *
     * @return List of CertPathValidatorException from soft-fail checks
     */
    @Override
    public List<CertPathValidatorException> getSoftFailExceptions() {
        return Collections.unmodifiableList(this.softFailExceptions);
    }

    /**
     * Read and apply wolfjce.ioTimeout system property.
     *
     * Sets the native wolfSSL I/O timeout via wolfIO_SetTimeout()
     * if the property is set and valid. If the property is set but
     * contains an invalid value, throws CertPathValidatorException
     * to fail revocation checker initialization.
     *
     * Note: The native timeout is a global (process-wide) setting
     * shared by all threads and validations in the JVM. To reduce
     * redundant JNI calls, the parsed value is compared against
     * the last applied value and the native call is skipped if
     * unchanged.
     *
     * @throws CertPathValidatorException if property value is
     *         invalid (not a number, negative, exceeds max, or
     *         HAVE_IO_TIMEOUT not compiled in)
     */
    private void setIOTimeoutFromProperty() throws CertPathValidatorException {

        int timeoutSec;
        String ioTimeout;

        try {
            ioTimeout = System.getProperty("wolfjce.ioTimeout");
        } catch (SecurityException e) {
            /* SecurityManager blocked property access, treat as
             * property not set and continue without timeout */
            return;
        }

        if (ioTimeout == null) {
            return;
        }
        final String trimmed = ioTimeout.trim();
        if (trimmed.isEmpty()) {
            return;
        }

        try {
            timeoutSec = Integer.parseInt(trimmed);

            /* Skip JNI call if value unchanged from last apply */
            if (timeoutSec != lastAppliedIOTimeout) {
                WolfCrypt.setIOTimeout(timeoutSec);
                lastAppliedIOTimeout = timeoutSec;

                WolfCryptDebug.log(
                    WolfCryptPKIXRevocationChecker.class,
                    WolfCryptDebug.INFO,
                    () -> "wolfjce.ioTimeout set to " +
                    trimmed + " seconds");
            }

        } catch (NumberFormatException e) {
            throw new CertPathValidatorException(
                "Invalid wolfjce.ioTimeout value: " + trimmed +
                ", must be integer seconds: " + e.getMessage(), e);

        } catch (IllegalArgumentException e) {
            throw new CertPathValidatorException(
                "Invalid wolfjce.ioTimeout value: " + trimmed +
                ": " + e.getMessage(), e);

        } catch (WolfCryptException e) {
            throw new CertPathValidatorException(
                "wolfjce.ioTimeout set but native wolfSSL not " +
                "compiled with HAVE_IO_TIMEOUT: " + e.getMessage(), e);
        }
    }

    /**
     * Clone this revocation checker.
     *
     * Clones configuration state (OCSP responder, options, responses, etc.)
     * but not validation state (certManager, certChain, trustAnchors) which
     * is set fresh by the CertPathValidator before each validation.
     *
     * @return Cloned WolfCryptPKIXRevocationChecker
     */
    @Override
    public WolfCryptPKIXRevocationChecker clone() {

        WolfCryptPKIXRevocationChecker cloned =
            new WolfCryptPKIXRevocationChecker();

        /* Clone configuration state */
        cloned.ocspResponder = this.ocspResponder;
        cloned.ocspResponderCert = this.ocspResponderCert;

        if (this.ocspExtensions != null) {
            cloned.ocspExtensions = new ArrayList<Extension>(
                this.ocspExtensions);
        }

        cloned.ocspResponses = new HashMap<X509Certificate, byte[]>(
            this.ocspResponses);
        cloned.options = EnumSet.copyOf(this.options);

        /* Note: certManager, certChain, and trustAnchors are not cloned.
         * These are set by WolfCryptPKIXCertPathValidator before each
         * validation call, so cloning them is unnecessary. */

        return cloned;
    }
}

