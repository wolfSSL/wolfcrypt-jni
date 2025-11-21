/* WolfCryptPKIXCertPathValidator.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Collection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Date;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPath;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CertSelector;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.CRL;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import javax.security.auth.x500.X500Principal;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfSSLCertManagerVerifyCallback;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE implementation of CertPathValidator for PKIX (X.509)
 *
 * This implementation supports most of CertPathValidator, but not the
 * following items. If needed, please contact support@wolfssl.com
 * with details of required support.
 *
 *     A. Certificate policies, and this related setters/getters. As such,
 *        validation will not return PolicyNode in CertPathValidatorResult
 *     B. getRevocationChecker() throws UnsupportedOperationException.
 *        Internal revocation is done with CRL if
 *        PKIXParameters.isRevocationEnabled() is true and appropriate CRLs
 *        have been loaded into CertStore Set
 */
public class WolfCryptPKIXCertPathValidator extends CertPathValidatorSpi {

    /**
     * Inner class implementing verification callback for date override.
     *
     * This callback is registered with WolfSSLCertManager when
     * PKIXParameters.getDate() returns a non-null override date. It
     * intercepts certificate date validation errors and re-validates
     * the certificate dates against the override date instead of the
     * current system time.
     *
     * For thread safety, each CertPathValidator creates its own callback
     * instance with its own certificate map and override date.
     */
    private class DateOverrideVerifyCallback
        implements WolfSSLCertManagerVerifyCallback {

        private final Date overrideDate;
        private final Map<Integer, X509Certificate> certsByDepth;

        /**
         * Create new DateOverrideVerifyCallback.
         *
         * @param date Override date to use for validation
         * @param certs List of certificates in chain, ordered from
         *              end-entity (index 0) to root
         */
        public DateOverrideVerifyCallback(
            Date date, List<X509Certificate> certs) {

            this.overrideDate = date;
            this.certsByDepth = new HashMap<>();

            /* Map certificates by depth for lookup in callback.
             * Depth 0 = end entity cert, increasing depth toward root. */
            for (int i = 0; i < certs.size(); i++) {
                certsByDepth.put(i, certs.get(i));
            }
        }

        /**
         * Verify callback implementation that overrides date validation.
         *
         * When a date validation error occurs (ASN_BEFORE_DATE_E or
         * ASN_AFTER_DATE_E), this checks if the override date falls
         * within the certificate's validity period. If so, the error is
         * overridden and verification continues. For all other errors,
         * the original preverify result is used.
         *
         * This callback is called from native JNI.
         *
         * @param preverify  1 if pre-verification passed, 0 if failed
         * @param error      Error code from verification (0 = no error)
         * @param errorDepth Certificate depth in chain (0 = end entity)
         *
         * @return 1 to accept certificate, 0 to reject
         */
        @Override
        public int verify(int preverify, int error, int errorDepth) {

            Date notBefore;
            Date notAfter;
            X509Certificate cert;

            /* Get the certificate at this depth */
            cert = certsByDepth.get(errorDepth);
            if (cert == null) {
                /* Reject if cert not found */
                log("Date override: cert not found at depth " + errorDepth +
                    ", rejecting");
                return 0;
            }

            /* Get certificate validity dates */
            notBefore = cert.getNotBefore();
            notAfter = cert.getNotAfter();

            /* When date override is active, always validate against the
             * override date, ignoring system time. This handles both:
             * - Accepting expired certs if override date is within validity
             * - Rejecting valid certs if override date is outside validity */

            /* If date error exists but override date is valid, accept */
            if (error == WolfCryptError.ASN_BEFORE_DATE_E.getCode() ||
                error == WolfCryptError.ASN_AFTER_DATE_E.getCode()) {

                /* Override date must be within cert validity */
                if (overrideDate.before(notBefore) ||
                    overrideDate.after(notAfter)) {
                    log("Date override: override date " + overrideDate +
                        " outside validity window (notBefore: " + notBefore +
                        ", notAfter: " + notAfter + "), rejecting");
                    return 0;
                }

                log("Date override: override date " + overrideDate +
                    " within validity, accepting despite date error");

                return 1;
            }

            /* No date error, but still need to validate override date.
             * If override date is outside cert validity, reject even though
             * current system time might be valid. */
            if (overrideDate.before(notBefore)) {
                log("Date override: override date " + overrideDate +
                    " before cert validity (notBefore: " + notBefore +
                    "), rejecting");
                return 0;
            }

            if (overrideDate.after(notAfter)) {
                log("Date override: override date " + overrideDate +
                    " after cert validity (notAfter: " + notAfter +
                    "), rejecting");
                return 0;
            }

            /* Override date is valid, accept */
            log("Date override: override date " + overrideDate +
                " within validity, accepting");

            return 1;
        }
    }

    /**
     * Create new WolfCryptPKIXCertPathValidator object.
     */
    public WolfCryptPKIXCertPathValidator() {
        log("created new WolfCryptPKIXCertPathValidator");
    }

    /**
     * Check CertPathParameters matches our requirements.
     *    1. Not null
     *    2. Is an instance of PKIXParameters
     *
     * @throws InvalidAlgorithmParameterException if null or not an instance
     *         of PKIXParameters
     */
    private void sanitizeCertPathParameters(CertPathParameters params)
        throws InvalidAlgorithmParameterException {

        log("sanitizing CertPathParameters");

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "CertPathParameters is null");
        }

        /* Check params is of type PKIXParameters */
        if (!(params instanceof PKIXParameters)) {
            throw new InvalidAlgorithmParameterException(
                "params not of type PKIXParameters");
        }
    }

    /**
     * Check CertPath matches our requirements.
     *   1. CertPath.getType() is "X.509"
     *   2. CertPath.getEncoding() contains "PkiPath"
     *
     * @throws InvalidAlgorithmParametersException if type is not X.509
     * @throws CertPathValidatorException if PkiPath encoding is not supported
     */
    private void sanitizeCertPath(CertPath path)
        throws InvalidAlgorithmParameterException, CertPathValidatorException {

        boolean pkiPathEncodingSupported = false;
        Iterator<String> supportedCertEncodings = null;

        log("sanitizing CertPath");

        /* Verify CertPath type is X.509 */
        if (!path.getType().equals("X.509")) {
            throw new InvalidAlgorithmParameterException(
                "PKIX CertPathValidator only supports X.509");
        }

        /* Check that PkiPath encoding is supported, which is an
         * ASN.1 DER encoded sequence of the cert */
        supportedCertEncodings = path.getEncodings();
        while (supportedCertEncodings.hasNext()) {
            if (supportedCertEncodings.next().equals("PkiPath")) {
                pkiPathEncodingSupported = true;
            }
        }
        if (!pkiPathEncodingSupported) {
            throw new CertPathValidatorException(
                "PkiPath CertPath encoding not supported but required");
        }
    }

    private void checkTargetCertConstraints(X509Certificate cert,
        int certIdx, CertPath path, PKIXParameters params)
        throws CertPathValidatorException {

        CertSelector selector = null;
        X509CertSelector x509Selector = null;

        if (cert == null || params == null) {
            throw new CertPathValidatorException(
                "X509Certificate in chain or PKIXParameters is null");
        }

        /* Only check leaf/peer certificate against constraints */
        if (certIdx != 0) {
            return;
        }

        /* Use CertSelector to check target cert */
        selector = params.getTargetCertConstraints();
        if (selector != null) {
            log("checking target cert constraints against CertSelector");

            if (!(selector instanceof X509CertSelector)) {
                throw new CertPathValidatorException(
                    "CertSelector not of type X509CertSelector");
            }
            x509Selector = (X509CertSelector)selector;

            if (!x509Selector.match(cert)) {
                throw new CertPathValidatorException(
                    "Target certificate did not pass CertConstraints check");
            }
        }
        else {
            log("no cert constraints in params, not checking CertSelector");
        }
    }

    private void disallowCertPolicyUse(PKIXParameters params)
        throws CertPathValidatorException {

        if (params == null) {
            throw new CertPathValidatorException(
                "PKIXParameters is null when checking for cert policies");
        }

        if (!params.getInitialPolicies().isEmpty()) {
            throw new CertPathValidatorException(
                "Certificate policies not supported by wolfJCE " +
                "CertPathValidator, PKIXParameters.getInitialPolicies() is " +
                "not empty");
        }

        /* Ignored, but log for debugging */
        log("PKIXParameters.getPolicyQualifiersRejected(): " +
            params.getPolicyQualifiersRejected());
        log("PKIXParameters.isPolicyMappingInhibited(): " +
            params.isPolicyMappingInhibited());

        /* Should the any policy OID be processed if it is included in
         * a certificate? Default is false, don't allow enablement since
         * not supported here yet */
        if (params.isAnyPolicyInhibited()) {
            throw new CertPathValidatorException(
                "Certificate policies not supported by wolfJCE " +
                "CertPathValidator. PKIXParameters.setAnyPolicyInhibited() " +
                "must be set to false (default)");
        }

        /* If true an acceptable policy needs to be explicitly identified in
         * every certificate. Default is false, don't allow enablement since
         * not supported here yet */
        if (params.isExplicitPolicyRequired()) {
            throw new CertPathValidatorException(
                "Certificate policies not supported by wolfJCE " +
                "CertPathValidator. PKIXParameters.setExplicitPolicy" +
                "Required() must be set to false (default)");
        }
    }

    /**
     * Check certificate against disabled algorithms constraints from
     * security property jdk.certpath.disabledAlgorithms.
     *
     * Validates both the signature algorithm and public key algorithm/size
     * against the disabled algorithms list.
     *
     * @param cert certificate to check
     * @param certIdx index of certificate, used when throwing exception
     * @param path CertPath used when throwing exception
     *
     * @throws CertPathValidatorException if algorithm is disabled or key
     *         size is too small, with BasicReason.ALGORITHM_CONSTRAINED
     */
    private void checkAlgorithmConstraints(X509Certificate cert,
        int certIdx, CertPath path) throws CertPathValidatorException {

        String sigAlg = null;
        PublicKey pubKey = null;
        String propertyName = "jdk.certpath.disabledAlgorithms";

        if (cert == null) {
            throw new CertPathValidatorException(
                "X509Certificate is null when checking algorithm constraints");
        }

        /* Check signature algorithm against disabled list */
        sigAlg = cert.getSigAlgName();
        if (WolfCryptUtil.isAlgorithmDisabled(sigAlg, propertyName)) {
            log("Algorithm constraints check failed on signature " +
                "algorithm: " + sigAlg);
            throw new CertPathValidatorException(
                "Algorithm constraints check failed on signature " +
                "algorithm: " + sigAlg, null, path, certIdx,
                BasicReason.ALGORITHM_CONSTRAINED);
        }

        /* Check public key algorithm and size against constraints */
        pubKey = cert.getPublicKey();
        if (!WolfCryptUtil.isKeyAllowed(pubKey, propertyName)) {
            log("Algorithm constraints check failed on public key: " +
                pubKey.getAlgorithm());
            throw new CertPathValidatorException(
                "Algorithm constraints check failed on public key",
                null, path, certIdx, BasicReason.ALGORITHM_CONSTRAINED);
        }
    }

    /**
     * Check X509Certificate against constraints or settings inside
     * PKIXParameters.
     *
     * @param cert certificate to check
     * @param certIdx index of certificate, used when throwing exception
     * @param path CertPath used when throwing exception
     * @param params parameters used to get constraints from
     *
     * @throws CertPathValidatorException if checks on certificate fail
     */
    private void sanitizeX509Certificate(X509Certificate cert,
        int certIdx, CertPath path, PKIXParameters params)
        throws CertPathValidatorException {

        if (cert == null || params == null) {
            throw new CertPathValidatorException(
                "X509Certificate in chain or PKIXParameters is null");
        }

        /* Check algorithm constraints from jdk.certpath.disabledAlgorithms */
        checkAlgorithmConstraints(cert, certIdx, path);

        /* Check target cert constraints, if set in parameters */
        checkTargetCertConstraints(cert, certIdx, path, params);

        /* Certificate policies are not currently supported by this
         * CertPathValidator implementation, throw exceptions when
         * user tries to use them. */
        disallowCertPolicyUse(params);
    }

    /**
     * Call all PKIXCertPathCheckers that have been registered into
     * PKIXParameters. This allows users to do additional verification
     * steps on certificates if needed.
     *
     * @param cert certificate to be checked
     * @param params parameters from which to get PKIXCertPathChecker list
     *
     * @throws CertPathValidatorException if a checker fails validation on
     *         the given Certificate
     */
    private void callCertPathCheckers(X509Certificate cert,
        PKIXParameters params) throws CertPathValidatorException {

        int i = 0;
        List<PKIXCertPathChecker> pathCheckers = null;

        if (cert == null || params == null) {
            throw new CertPathValidatorException(
                "X509Certificate in chain or PKIXParameters is null");
        }

        pathCheckers = params.getCertPathCheckers();
        if (pathCheckers == null) {
            /* Spec says this cannot be null */
            throw new CertPathValidatorException(
                "PKIXParameters.getCertPathCheckers() should not return null");
        }
        if (pathCheckers.isEmpty()) {
            return;
        }

        for (i = 0; i < pathCheckers.size(); i++) {
            log("calling CertPathChecker: " + pathCheckers.get(i));

            /* Throws CertPathValidatorException on error */
            pathCheckers.get(i).check((Certificate)cert);
        }
    }

    /**
     * Load TrustAnchors from PKIXParameters into WolfSSLCertManager as
     * trusted CA certificates.
     *
     * @param params PKIXParameters from which to get TrustAnchor Set
     * @param cm WolfSSLCertManager to load TrustAnchors into as trusted roots
     *
     * @throws CertPathValidatorException on failure to load trust anchors
     */
    private void loadTrustAnchorsIntoCertManager(
        PKIXParameters params, WolfSSLCertManager cm)
        throws CertPathValidatorException {

        Set<TrustAnchor> trustAnchors = null;
        Iterator<TrustAnchor> trustIterator = null;

        log("loading TrustAnchors into native WolfSSLCertManager");

        if (params == null || cm == null) {
            throw new CertPathValidatorException(
                "PKIXParameters or WolfSSLCertManager are null when loading " +
                "TrustAnchors");
        }

        /* Load trust anchors into CertManager from PKIXParameters */
        trustAnchors = params.getTrustAnchors();
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new CertPathValidatorException(
                "No TrustAnchors in PKIXParameters");
        }

        /* Iterate through TrustAnchors, load as CAs into CertManager */
        trustIterator = trustAnchors.iterator();
        while (trustIterator.hasNext()) {
            TrustAnchor anchor = trustIterator.next();
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert != null) {
                try {
                    cm.CertManagerLoadCA(anchorCert);

                    log("loaded TrustAnchor: " +
                        anchorCert.getSubjectX500Principal().getName());

                } catch (WolfCryptException e) {
                    throw new CertPathValidatorException(e);
                }
            }
        }
    }

    /**
     * Verify X509Certificate chain from top down, ending with peer/leaf
     * cert last.
     *
     */
    private void verifyCertChain(CertPath path, PKIXParameters params,
        List<X509Certificate> certs, WolfSSLCertManager cm)
        throws CertPathValidatorException {

        int i = 0;
        X509Certificate cert = null;

        if (path == null || params == null || certs == null || cm == null) {
            throw new CertPathValidatorException(
                "Input args to verifyCertChain are null");
        }

        log("verifying certificate chain (chain size: " + certs.size() + ")");

        /* Process certs from List in reverse order (top to peer) */
        for (i = certs.size()-1; i >= 0; i--) {
            cert = certs.get(i);

            try {
                /* Try to verify cert */
                cm.CertManagerVerify(cert);

                log("verified chain [" + i + "]: " +
                    cert.getSubjectX500Principal().getName());

            } catch (WolfCryptException e) {
                log("failed verification chain [" + i + "]: " +
                    cert.getSubjectX500Principal().getName());

                throw new CertPathValidatorException(
                    "Failed verification on certificate", e, path, i);
            }

            /* Verified successfully. If this is a CA and we have more
             * certs, load this as trusted (intermediate) */
            if (i > 0 && cert.getBasicConstraints() >= 0) {
                try {
                    cm.CertManagerLoadCA(cert);

                    log("chain [" + i + "] is intermediate, loading as root");

                } catch (WolfCryptException e) {

                    log("chain [" + i + "] is CA, but failed to load as " +
                        "trusted root, not loading");
                }
            }
        }
    }

    /**
     * Search TrustAnchors in PKIXParameters for one that verifies the provided
     * X509Certificate.
     *
     * @param params PKIXParameters to get TrustAnchors from
     * @param cert X509Certificate for which to find signer cert
     *
     * @return TrustAnchor that signs provided cert
     *
     * @throws CertPathValidatorException if the search for TrustAnchor fails
     */
    public TrustAnchor findTrustAnchor(PKIXParameters params,
        X509Certificate cert) throws CertPathValidatorException {

        Set<TrustAnchor> trustAnchors = null;
        Iterator<TrustAnchor> trustIterator = null;
        TrustAnchor anchorFound = null;
        X500Principal issuer = null;
        WolfSSLCertManager cm = null;
        Date overrideDate = null;

        if (params == null || cert == null) {
            throw new CertPathValidatorException(
                "Input parameters are null to findTrustAnchor");
        }

        /* Issuer name we need to match */
        issuer = cert.getIssuerX500Principal();
        if (issuer == null) {
            throw new CertPathValidatorException(
                "Unable to get expected issuer name");
        }

        /* Get all TrustAnchors in PKIXParameters */
        trustAnchors = params.getTrustAnchors();
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new CertPathValidatorException(
                "No TrustAnchors in PKIXParameters");
        }

        try {
            cm = new WolfSSLCertManager();
        } catch (WolfCryptException e) {
            throw new CertPathValidatorException(
                "Failed to create native WolfSSLCertManager");
        }

        /* If date override is set, register callback on this CertManager */
        overrideDate = params.getDate();
        if (overrideDate != null) {
            try {
                /* Create simple single-cert callback for this verification */
                List<X509Certificate> singleCert = new ArrayList<>();
                singleCert.add(cert);
                DateOverrideVerifyCallback callback =
                    new DateOverrideVerifyCallback(overrideDate, singleCert);
                cm.setVerifyCallback(callback);
            } catch (WolfCryptException e) {
                cm.free();
                throw new CertPathValidatorException(
                    "Failed to set date override callback in findTrustAnchor");
            }
        }

        /* Iterate through TrustAnchors and check for match */
        trustIterator = trustAnchors.iterator();
        while (trustIterator.hasNext()) {
            TrustAnchor anchor = trustIterator.next();
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert == null) {
                /* Skip to next */
                continue;
            }

            if (!anchorCert.getSubjectX500Principal().equals(issuer)) {
                /* Isser name doesn't match, skip to next */
                continue;
            }

            try {
                /* Unload any CAs in CertManager */
                cm.CertManagerUnloadCAs();
            } catch (WolfCryptException e) {
                cm.free();
                throw new CertPathValidatorException(
                    "Unable to unload CAs from native WolfSSLCertManager");
            }

            try {
                /* Load anchor as CA */
                cm.CertManagerLoadCA(anchorCert);
            } catch (WolfCryptException e) {
                /* error loading CA, skip to next */
                continue;
            }

            try {
                /* Try to verify cert, mark found if successful */
                cm.CertManagerVerify(cert);
                anchorFound = anchor;
            } catch (WolfCryptException e) {
                /* Does not verify, skip to next */
                continue;
            }
        }

        /* Free native WolfSSLCertManager resources */
        cm.free();

        return anchorFound;
    }

    /**
     * Check if revocation has been enabled in PKIXParameters, and if so
     * find and load any CRLs in params.getCertStores().
     *
     * @param params parameters used to check if revocation is enabled
     *        and if so load any CRLs available
     * @param cm WolfSSLCertManager to load CRLs into
     * @param targetCert peer/leaf cert used to find matching CRL
     *
     * @throws CertPathValidatorException if error is encountered during
     *        revocation checking or CRL loading
     */
    private void checkRevocationEnabledAndLoadCRLs(
        PKIXParameters params, WolfSSLCertManager cm,
        X509Certificate targetCert)
        throws CertPathValidatorException {

        int i = 0;
        int loadedCount = 0;
        List<CertStore> stores = null;
        Collection<? extends CRL> crls = null;

        if (params == null || cm == null) {
            throw new CertPathValidatorException(
                "PKIXParameters or WolfSSLCertManager is null");
        }

        if (params.isRevocationEnabled()) {
            log("revocation enabled in PKIXParameters, checking " +
                "for CRLs to load");

            if (!WolfCrypt.CrlEnabled()) {
                throw new CertPathValidatorException(
                    "Revocation enabled in PKIXParameters but native " +
                    "wolfCrypt CRL not compiled in");
            }

            /* Enable CRL in native WolfSSLCertManager */
            cm.CertManagerEnableCRL(WolfCrypt.WOLFSSL_CRL_CHECK);

            log("CRL support enabled in native WolfSSLCertManager");

            stores = params.getCertStores();
            if (stores == null || stores.isEmpty()) {
                log("no CertStores in PKIXParameters to load CRLs");
                return;
            }

            /* Create CRL selector to help match target X509Certificate */
            X509CRLSelector selector = new X509CRLSelector();
            selector.setCertificateChecking(targetCert);

            try {
                /* Find and load any matching CRLs */
                for (i = 0; i < stores.size(); i++) {
                    crls = stores.get(i).getCRLs(selector);
                    for (CRL crl: crls) {
                        if (crl instanceof X509CRL) {
                            cm.CertManagerLoadCRL((X509CRL)crl);
                            loadedCount++;
                        }
                    }
                }
            } catch (CertStoreException e) {
                throw new CertPathValidatorException(e);
            }

            log("loaded " + loadedCount + " CRLs into WolfSSLCertManager");
        }
        else {
            log("revocation not enabled in PKIXParameters");
        }
    }

    /**
     * Validates the specified certification path using the provided
     * algorithm parameter set.
     *
     * General validation process follows:
     *   1. Sanitize CertPathParameters
     *       a. Verify not null and instanceof PKIXParameters
     *   2. Sanitize CertPath
     *       a. CertPath.getType() is "X.509"
     *       b. CertPath.getEncoding() contains "PkiPath"
     *   3. If wolfCrypt FIPS, verify params.getSigProvider() is wolfJCE
     *   4. Sanitize Certificate objects in CertPath chain
     *       a. Check target certificate constraints meet target cert
     *       b. Check cert policies are not used (not supported)
     *   5. Call any registered CertPathCheckers
     *   6. Load TrustAnchors into WolfSSLCertManager
     *   7. Enable CRL if requested, load CRLs from getCertStores()
     *   8. Verify X.509 certificate chain
     *   9. Find top-most TrustAnchor for return object
     *
     * @param certPath the CertPath to be validated. CertPath entries are
     *                 ordered from leaf/peer up the chain to CA/root last.
     *                 The certificate representing the last/final TrustAnchor
     *                 should not be part of the CertPath.
     * @param params the algorithm parameters to be used for validation
     *
     * @return the result of the validation
     *
     * @throws CertPathValidatorException if the CertPath does not validate
     * @throws InvalidAlgorithmParameterException if the parameters or type
     *         specified are unsupported or inappropriate for this
     *         CertPathValidator implementation.
     */
    @Override
    public CertPathValidatorResult engineValidate(
        CertPath certPath, CertPathParameters params)
        throws CertPathValidatorException, InvalidAlgorithmParameterException {

        int i = 0;
        PKIXParameters pkixParams = null;
        List<X509Certificate> certs = null;
        WolfSSLCertManager cm = null;
        TrustAnchor trustAnchor = null;

        log("entered engineValidate(), FIPS enabled: " + Fips.enabled);

        sanitizeCertPathParameters(params);
        sanitizeCertPath(certPath);

        pkixParams = (PKIXParameters)params;

        /* If we are in FIPS mode, verify wolfJCE is the Signature provider
         * to help maintain FIPS compliance */
        if (Fips.enabled && pkixParams.getSigProvider() != "wolfJCE") {
            if (pkixParams.getSigProvider() == null) {
                /* Preferred Signature provider not set, set to wolfJCE */
                pkixParams.setSigProvider("wolfJCE");
            }
            else {
                throw new CertPathValidatorException(
                    "CertPathParameters Signature Provider must be wolfJCE " +
                    "when using wolfCrypt FIPS: " +
                    pkixParams.getSigProvider());
            }
        }

        /* Use wolfSSL CertManager to facilitate chain verification */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfCryptException e) {
            throw new CertPathValidatorException(
                "Failed to create native WolfSSLCertManager");
        }

        try {
            /* Get List of Certificate objects in CertPath, sanity check
             * that they are X509Certificate instances. This needs to be
             * done before date override callback registration since
             * callback needs access to certificate list. */
            certs = new ArrayList<>();
            for (Certificate cert : certPath.getCertificates()) {
                if (cert instanceof X509Certificate) {
                    certs.add((X509Certificate) cert);
                }
            }
            if (certs.size() == 0) {
                throw new CertPathValidatorException(
                    "No Certificate objects in CertPath");
            }

            /* Register verify callback to override date validation if
             * PKIXParameters specifies an override date */
            if (pkixParams.getDate() != null) {
                try {
                    DateOverrideVerifyCallback callback =
                        new DateOverrideVerifyCallback(
                            pkixParams.getDate(), certs);
                    cm.setVerifyCallback(callback);

                    log("Registered date override callback for " +
                        "validation date: " + pkixParams.getDate());

                } catch (WolfCryptException e) {
                    throw new CertPathValidatorException(
                        "Failed to register date override callback: " +
                        e.getMessage());
                }
            }

            /* Sanity checks on certs from PKIXParameters constraints */
            for (i = 0; i < certs.size(); i++) {
                sanitizeX509Certificate(certs.get(i), i, certPath, pkixParams);
                callCertPathCheckers(certs.get(i), pkixParams);
            }

            /* Load trust anchors into CertManager from PKIXParameters */
            loadTrustAnchorsIntoCertManager(pkixParams, cm);

            /* Enable CRL if PKIXParameters.isRevocationEnabled(), load
             * any CRLs found in PKIXParameters.getCertStores(). Needs to
             * happen after trust anchors are loaded, since native wolfSSL
             * will try to find/verify CRL against trusted roots on load */
            checkRevocationEnabledAndLoadCRLs(pkixParams, cm, certs.get(0));

            /* Verify cert chain */
            verifyCertChain(certPath, pkixParams, certs, cm);

            /* Cert chain has been verified, find TrustAnchor to return
             * in PKIXCertPathValidatorResult */
            trustAnchor = findTrustAnchor(
                pkixParams, certs.get(certs.size() - 1));

        } finally {
            /* Free native WolfSSLCertManager resources */
            cm.free();
        }

        /* PolicyNode not returned, since certificate policies are not
         * yet supported */
        return new PKIXCertPathValidatorResult(trustAnchor, null,
            certs.get(0).getPublicKey());
    }

    /**
     * Returns a CertPathChecker that this implementation uses to check the
     * revocation status of certificates.
     *
     * Not currently implemented in wolfJCE.
     *
     * @return a CertPathChecker object that this implementation uses to
     *         check the revocation status of certificates.
     * @throws UnsupportedOperationException if this method is not implemented
     */
    @Override
    public CertPathChecker engineGetRevocationChecker()
        throws UnsupportedOperationException {

        throw new UnsupportedOperationException(
            "getRevocationChecker() not supported by wolfJCE");
    }

    /**
     * Internal log function, called when debug is enabled.
     *
     * @param msg Log message to be printed
     */
    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO, () -> msg);
    }
}

