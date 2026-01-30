/* WolfCryptPKIXCertPathBuilder.java
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

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Collection;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Date;
import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXRevocationChecker;
import javax.security.auth.x500.X500Principal;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfSSLX509StoreCtx;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE implementation of CertPathBuilder for PKIX (X.509)
 *
 * This implementation builds a certification path from a target certificate
 * to a trust anchor using the PKIX algorithm. It searches for certificates
 * in the provided CertStores to build the chain.
 *
 * This implementation supports most of CertPathBuilder, but not the
 * following items. If needed, please contact support@wolfssl.com
 * with details of required support.
 *
 *     1. Certificate policies, and the related setters/getters. As such,
 *        validation will not return PolicyNode in CertPathBuilderResult
 *
 * Revocation checking is supported via:
 *     - CRL: If PKIXParameters.isRevocationEnabled() is true and appropriate
 *       CRLs have been loaded into CertStore Set
 *     - OCSP: via getRevocationChecker() which returns a
 *       WolfCryptPKIXRevocationChecker supporting OCSP and options
 */
public class WolfCryptPKIXCertPathBuilder extends CertPathBuilderSpi {

    /**
     * Create new WolfCryptPKIXCertPathBuilder object.
     */
    public WolfCryptPKIXCertPathBuilder() {
        log("created new WolfCryptPKIXCertPathBuilder");
    }

    /**
     * Sanitize CertPathParameters, not null and instance of
     * PKIXBuilderParameters.
     *
     * @throws InvalidAlgorithmParameterException if null or not an instance
     *         of PKIXBuilderParameters
     */
    private void sanitizeCertPathParameters(CertPathParameters params)
        throws InvalidAlgorithmParameterException {

        log("sanitizing CertPathParameters");

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "CertPathParameters is null");
        }

        /* Check params is of type PKIXBuilderParameters */
        if (!(params instanceof PKIXBuilderParameters)) {
            throw new InvalidAlgorithmParameterException(
                "params not of type PKIXBuilderParameters");
        }
    }

    /**
     * Find the target certificate based on the X509CertSelector in params.
     *
     * Searches through all CertStores for a certificate matching the
     * target constraints.
     *
     * @param params PKIXBuilderParameters containing target selector
     *
     * @return X509Certificate matching the target constraints
     *
     * @throws CertPathBuilderException if target certificate cannot be found
     */
    private X509Certificate findTargetCertificate(PKIXBuilderParameters params)
        throws CertPathBuilderException {

        CertSelector selector = null;
        X509CertSelector x509Selector = null;
        X509Certificate targetCert = null;
        List<CertStore> certStores = null;

        if (params == null) {
            throw new CertPathBuilderException(
                "PKIXBuilderParameters is null");
        }

        selector = params.getTargetCertConstraints();
        if (selector == null) {
            throw new CertPathBuilderException(
                "Target certificate constraints (X509CertSelector) not set " +
                "in PKIXBuilderParameters");
        }

        if (!(selector instanceof X509CertSelector)) {
            throw new CertPathBuilderException(
                "Target certificate constraints must be X509CertSelector");
        }

        x509Selector = (X509CertSelector)selector;
        log("searching for target certificate with selector: " + x509Selector);

        /* Check if target cert is directly set in selector */
        targetCert = x509Selector.getCertificate();
        if (targetCert != null) {
            log("target certificate directly set in selector");
            return targetCert;
        }

        /* Search through CertStores for matching certificate */
        certStores = params.getCertStores();
        if (certStores == null || certStores.isEmpty()) {
            throw new CertPathBuilderException(
                "No CertStores provided in PKIXBuilderParameters");
        }

        for (CertStore store : certStores) {
            try {
                Collection<? extends Certificate> certs =
                    store.getCertificates(x509Selector);

                if (certs != null && !certs.isEmpty()) {
                    /* Return first matching certificate */
                    targetCert = (X509Certificate) certs.iterator().next();
                    log("found target certificate: " +
                        targetCert.getSubjectX500Principal().getName());
                    return targetCert;
                }

            } catch (CertStoreException e) {
                log("error searching CertStore: " + e.getMessage());
                /* Continue to next store */
            }
        }

        throw new CertPathBuilderException(
            "Target certificate not found in CertStores");
    }

    /**
     * Check if given certificate is issued by a trust anchor.
     *
     * @param cert certificate to check
     * @param anchors set of trust anchors
     *
     * @return TrustAnchor that issued the certificate, or null if none
     */
    private TrustAnchor isIssuedByTrustAnchor(X509Certificate cert,
        Set<TrustAnchor> anchors) {

        if (cert == null || anchors == null || anchors.isEmpty()) {
            return null;
        }

        X500Principal issuer = cert.getIssuerX500Principal();

        for (TrustAnchor anchor : anchors) {
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert == null) {
                /* Skip anchors without certificates */
                continue;
            }

            X500Principal anchorSubject = anchorCert.getSubjectX500Principal();
            if (issuer.equals(anchorSubject)) {
                try {
                    /* Issuer name matches, verify signature */
                    cert.verify(anchorCert.getPublicKey());
                    log("certificate issued by trust anchor: " +
                        anchorSubject.getName());

                    return anchor;

                } catch (CertificateException | NoSuchAlgorithmException |
                         InvalidKeyException | NoSuchProviderException |
                         SignatureException e) {

                    /* Signature doesn't match, continue */
                    log("signature verification failed for anchor: " +
                        anchorSubject.getName() + " (" +
                        e.getClass().getSimpleName() + ": " +
                        e.getMessage() + ")");
                }
            }
        }

        return null;
    }

    /**
     * Check if given certificate is self-signed.
     *
     * @param cert certificate to check
     *
     * @return true if certificate is self-signed, false otherwise
     */
    private boolean isSelfSigned(X509Certificate cert) {

        if (cert == null) {
            return false;
        }

        if (!cert.getSubjectX500Principal().equals(
             cert.getIssuerX500Principal())) {
            return false;
        }

        try {
            cert.verify(cert.getPublicKey());
            return true;

        } catch (CertificateException | NoSuchAlgorithmException |
                 InvalidKeyException | NoSuchProviderException |
                 SignatureException e) {
            return false;
        }
    }

    /**
     * Find potential issuer certificates for a given certificate.
     *
     * Searches through CertStores for certificates where the subject
     * matches the issuer of the given certificate.
     *
     * @param cert certificate for which to find issuers
     * @param certStores list of CertStores to search
     * @param anchors set of trust anchors (also potential issuers)
     *
     * @return list of potential issuer certificates
     */
    private List<X509Certificate> findIssuers(X509Certificate cert,
        List<CertStore> certStores, Set<TrustAnchor> anchors) {

        if (cert == null) {
            return new ArrayList<>();
        }

        List<X509Certificate> issuers = new ArrayList<>();
        X500Principal issuerPrincipal = cert.getIssuerX500Principal();

        log("searching for issuers of: " +
            cert.getSubjectX500Principal().getName());

        /* Create selector to find certificates by subject name */
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(issuerPrincipal);

        /* Search CertStores */
        if (certStores != null) {
            for (CertStore store : certStores) {
                try {
                    Collection<? extends Certificate> certs =
                        store.getCertificates(selector);

                    for (Certificate c : certs) {
                        if (c instanceof X509Certificate) {
                            X509Certificate x509Cert = (X509Certificate) c;
                            /* Must be a CA certificate */
                            if (x509Cert.getBasicConstraints() >= 0) {
                                issuers.add(x509Cert);
                            }
                        }
                    }

                } catch (CertStoreException e) {
                    /* Continue to next store */
                }
            }
        }

        /* Also check trust anchors as potential issuers.
         * Trust anchors should be CA certificates (basicConstraints >= 0)
         * to be valid issuers in the chain. */
        for (TrustAnchor anchor : anchors) {
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert != null &&
                anchorCert.getSubjectX500Principal().equals(issuerPrincipal) &&
                anchorCert.getBasicConstraints() >= 0) {
                /* Avoid duplicates */
                if (!issuers.contains(anchorCert)) {
                    issuers.add(anchorCert);
                }
            }
        }

        log("found " + issuers.size() + " potential issuer(s)");

        return issuers;
    }

    /**
     * Build certificate path from target to trust anchor.
     *
     * @param targetCert the target (end-entity) certificate
     * @param params the PKIX builder parameters
     *
     * @return list of certificates from target to issuer (not including
     *         the trust anchor)
     *
     * @throws CertPathBuilderException if path cannot be built
     */
    private List<X509Certificate> buildPath(X509Certificate targetCert,
        PKIXBuilderParameters params) throws CertPathBuilderException {

        List<X509Certificate> path = new ArrayList<>();
        Set<X509Certificate> visited = new HashSet<>();
        Set<TrustAnchor> anchors = null;
        List<CertStore> certStores = null;
        int maxPathLength = 0;

        if (params == null) {
            throw new CertPathBuilderException(
                "PKIXBuilderParameters is null");
        }

        anchors = params.getTrustAnchors();
        certStores = params.getCertStores();
        maxPathLength = params.getMaxPathLength();

        /* maxPathLength of -1 means unlimited (no constraint) */
        if (maxPathLength < 0) {
            log("building path with unlimited max length");
        } else {
            log("building path with max length: " + maxPathLength);
        }

        /* Start with target certificate */
        X509Certificate current = targetCert;
        path.add(current);
        visited.add(current);

        /* Build path from target to trust anchor */
        while (true) {
            /* Check if current cert is issued by a trust anchor */
            TrustAnchor anchor = isIssuedByTrustAnchor(current, anchors);
            if (anchor != null) {
                log("path complete, reached trust anchor: " +
                    anchor.getTrustedCert()
                        .getSubjectX500Principal().getName());
                break;
            }

            /* Check if current cert is self-signed (root without anchor) */
            if (isSelfSigned(current)) {
                throw new CertPathBuilderException(
                    "Certificate is self-signed but not in trust anchors: " +
                    current.getSubjectX500Principal().getName());
            }

            /* Find potential issuers */
            List<X509Certificate> issuers =
                findIssuers(current, certStores, anchors);

            if (issuers.isEmpty()) {
                throw new CertPathBuilderException(
                    "Unable to find issuer for certificate: " +
                    current.getSubjectX500Principal().getName());
            }

            /* Try each potential issuer */
            boolean foundIssuer = false;
            for (X509Certificate issuer : issuers) {
                /* Check for loops */
                if (visited.contains(issuer)) {
                    log("skipping already-visited certificate: " +
                        issuer.getSubjectX500Principal().getName());
                    continue;
                }

                /* Verify signature */
                try {
                    current.verify(issuer.getPublicKey());

                } catch (CertificateException | NoSuchAlgorithmException |
                         InvalidKeyException | NoSuchProviderException |
                         SignatureException e) {
                    log("signature verification failed for issuer: " +
                        issuer.getSubjectX500Principal().getName() + " (" +
                        e.getClass().getSimpleName() + ": " +
                        e.getMessage() + ")");
                    continue;
                }

                /* Check if this issuer is a trust anchor */
                TrustAnchor issuerAnchor = null;
                for (TrustAnchor a : anchors) {
                    X509Certificate ac = a.getTrustedCert();
                    if (ac != null && ac.equals(issuer)) {
                        issuerAnchor = a;
                        break;
                    }
                }

                if (issuerAnchor != null) {
                    /* Reached trust anchor, path complete */
                    log("path complete, issuer is trust anchor: " +
                        issuer.getSubjectX500Principal().getName());
                    foundIssuer = true;
                    break;
                }

                /* Add issuer to path and continue */
                path.add(issuer);
                visited.add(issuer);
                current = issuer;
                foundIssuer = true;

                log("added to path: " +
                    issuer.getSubjectX500Principal().getName());
                break;
            }

            if (!foundIssuer) {
                throw new CertPathBuilderException(
                    "No valid issuer found for certificate: " +
                    current.getSubjectX500Principal().getName());
            }
        }

        /* Check path length constraint after path is complete.
         * maxPathLength is maximum number of intermediate CA certificates
         * allowed between end entity and trust anchor. maxPathLength of
         * -1 means unlimited (no constraints). */
        if (maxPathLength >= 0) {
            int numCACerts = path.size() - 1; /* exclude target cert */
            if (numCACerts > maxPathLength) {
                throw new CertPathBuilderException(
                    "Certificate path exceeds maximum length: " +
                    maxPathLength + " (found " + numCACerts +
                    " intermediate CA certificate(s))");
            }
        }

        return path;
    }

    /**
     * Find trust anchor that issued the last certificate in the path.
     *
     * @param path the certificate path
     * @param anchors set of trust anchors
     *
     * @return the trust anchor that issued the last certificate
     *
     * @throws CertPathBuilderException if no matching anchor found
     */
    private TrustAnchor findPathTrustAnchor(List<X509Certificate> path,
        Set<TrustAnchor> anchors) throws CertPathBuilderException {

        if (path == null) {
            throw new CertPathBuilderException(
                "Certificate path is null");
        }

        if (path.isEmpty()) {
            throw new CertPathBuilderException(
                "Cannot find trust anchor for empty path");
        }

        X509Certificate lastCert = path.get(path.size() - 1);
        TrustAnchor anchor = isIssuedByTrustAnchor(lastCert, anchors);

        if (anchor == null) {
            throw new CertPathBuilderException(
                "Path does not end at a trust anchor");
        }

        return anchor;
    }

    /**
     * Validate the built certificate path.
     *
     * @param path the certificate path to validate
     * @param params the PKIX builder parameters
     * @param anchor the trust anchor
     *
     * @throws CertPathBuilderException if validation fails
     */
    private void validatePath(List<X509Certificate> path,
        PKIXBuilderParameters params, TrustAnchor anchor)
        throws CertPathBuilderException {

        WolfSSLCertManager cm = null;

        log("validating built path (" + path.size() + " certificates)");

        if (path == null || anchor == null) {
            throw new CertPathBuilderException(
                "Path or TrustAnchor is null");
        }

        try {
            cm = new WolfSSLCertManager();

            /* Load trust anchor as CA */
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert != null) {
                cm.CertManagerLoadCA(anchorCert);
                log("loaded trust anchor: " +
                    anchorCert.getSubjectX500Principal().getName());
            }

            /* Verify certificates from top (closest to anchor) to target */
            for (int i = path.size() - 1; i >= 0; i--) {
                X509Certificate cert = path.get(i);

                try {
                    cm.CertManagerVerify(cert);
                    log("verified: " +
                        cert.getSubjectX500Principal().getName());

                } catch (WolfCryptException e) {
                    throw new CertPathBuilderException(
                        "Certificate verification failed: " +
                        cert.getSubjectX500Principal().getName(), e);
                }

                /* Load verified cert as CA for next verification */
                if (i > 0 && cert.getBasicConstraints() >= 0) {
                    try {
                        cm.CertManagerLoadCA(cert);

                    } catch (WolfCryptException e) {
                        /* continue */
                        log("Warning: failed to load verified cert as CA");
                    }
                }
            }

        } catch (WolfCryptException e) {
            throw new CertPathBuilderException(
                "Failed to create or use WolfSSLCertManager", e);

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    /**
     * Helper class to hold chain building result with trust anchor.
     */
    private static class NativeChainResult {
        final List<X509Certificate> path;
        final TrustAnchor trustAnchor;

        NativeChainResult(List<X509Certificate> path, TrustAnchor trustAnchor) {
            if (path == null || trustAnchor == null) {
                throw new IllegalArgumentException(
                    "Path and trustAnchor must not be null");
            }
            this.path = path;
            this.trustAnchor = trustAnchor;
        }
    }

    /**
     * Collect all intermediate CA certificates from CertStores.
     *
     * Searches through provided CertStores for CA certificates
     * (basicConstraints >= 0) and returns them as DER-encoded byte arrays.
     * Trust anchor certificates are excluded from the results.
     *
     * @param certStores list of CertStores to search
     * @param anchors set of trust anchors to exclude
     *
     * @return list of DER-encoded intermediate certificates
     */
    private List<byte[]> collectIntermediateCertificates(
        List<CertStore> certStores, Set<TrustAnchor> anchors) {

        List<byte[]> intermediatesDer = new ArrayList<>();

        if (certStores == null) {
            return intermediatesDer;
        }

        for (CertStore store : certStores) {
            try {
                /* Get all CA certificates from store */
                X509CertSelector caSelector = new X509CertSelector();
                caSelector.setBasicConstraints(0);
                Collection<? extends Certificate> certs =
                    store.getCertificates(caSelector);

                for (Certificate c : certs) {
                    if (c instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) c;
                        /* Skip if it's a trust anchor */
                        boolean isTrustAnchor = false;
                        for (TrustAnchor anchor : anchors) {
                            X509Certificate ac = anchor.getTrustedCert();
                            if (ac != null && ac.equals(x509)) {
                                isTrustAnchor = true;
                                break;
                            }
                        }
                        if (!isTrustAnchor) {
                            intermediatesDer.add(x509.getEncoded());
                            log("collected intermediate: " +
                                x509.getSubjectX500Principal().getName());
                        }
                    }
                }

            } catch (CertStoreException | CertificateException e) {
                /* Continue to next store on error */
                log("error collecting intermediates: " + e.getMessage());
            }
        }

        return intermediatesDer;
    }

    /**
     * Build and verify a certificate path using native wolfSSL X509_STORE
     * and wolfSSL_X509_verify_cert().
     *
     * @param targetCert target (end entity) certificate
     * @param params the PKIX builder parameters
     *
     * @return NativeChainResult containing the path (target to issuer,
     *         not including trust anchor) and the trust anchor
     *
     * @throws CertPathBuilderException if path cannot be built or verified
     */
    private NativeChainResult buildAndVerifyPathNative(
        X509Certificate targetCert, PKIXBuilderParameters params)
        throws CertPathBuilderException {

        Set<TrustAnchor> anchors = null;
        List<CertStore> certStores = null;
        int maxPathLength = 0;

        log("building and verifying path using native wolfSSL X509_STORE");


        if (targetCert == null || params == null) {
            throw new CertPathBuilderException(
                "Target certificate or PKIXBuilderParameters is null");
        }

        anchors = params.getTrustAnchors();
        certStores = params.getCertStores();
        maxPathLength = params.getMaxPathLength();

        WolfSSLX509StoreCtx storeCtx = null;
        try {
            storeCtx = new WolfSSLX509StoreCtx();

            /* Add trust anchors to the store */
            for (TrustAnchor anchor : anchors) {

                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null) {
                    byte[] anchorDer;
                    try {
                        anchorDer = anchorCert.getEncoded();

                    } catch (CertificateException e) {
                        throw new CertPathBuilderException(
                            "Failed to encode trust anchor certificate: " +
                            anchorCert.getSubjectX500Principal().getName(), e);
                    }
                    storeCtx.addCertificate(anchorDer);
                    log("added trust anchor to store: " +
                        anchorCert.getSubjectX500Principal().getName());
                }
            }

            /* Collect all intermediate certificates from CertStores */
            List<byte[]> intermediatesDer =
                collectIntermediateCertificates(certStores, anchors);

            /* Convert target cert to DER */
            byte[] targetDer;
            try {
                targetDer = targetCert.getEncoded();
            } catch (CertificateException e) {
                throw new CertPathBuilderException(
                    "Failed to encode target certificate: " +
                    targetCert.getSubjectX500Principal().getName(), e);
            }

            /* Prepare intermediates array (can be null if empty) */
            byte[][] intermediatesArray = null;
            if (!intermediatesDer.isEmpty()) {
                int size = intermediatesDer.size();
                intermediatesArray =
                    intermediatesDer.toArray(new byte[size][]);
            }

            /* Build and verify the chain */
            byte[][] chainDer = storeCtx.buildAndVerifyChain(
                targetDer, intermediatesArray, maxPathLength);

            /* Convert DER chain back to X509Certificates */
            CertificateFactory cf;
            try {
                cf = CertificateFactory.getInstance("X.509");

            } catch (CertificateException e) {
                throw new CertPathBuilderException(
                    "Failed to get X.509 CertificateFactory", e);
            }
            List<X509Certificate> fullChain = new ArrayList<>();

            for (int i = 0; i < chainDer.length; i++) {
                try {
                    X509Certificate cert = (X509Certificate)
                        cf.generateCertificate(
                            new ByteArrayInputStream(chainDer[i]));
                    fullChain.add(cert);

                } catch (CertificateException e) {
                    throw new CertPathBuilderException(
                        "Failed to parse certificate at position " + i +
                        " in chain returned by native verification", e);
                }
            }

            log("native chain building returned " + fullChain.size() +
                " certificate(s)");

            /* Chain includes target->intermediates->trust anchor.
             * We need to separate the trust anchor from the path.
             * The last cert in the chain should match a trust anchor. */
            if (fullChain.isEmpty()) {
                throw new CertPathBuilderException(
                    "Native chain building returned empty chain");
            }

            /* Find trust anchor, last certificate in chain */
            X509Certificate lastCert = fullChain.get(fullChain.size() - 1);
            TrustAnchor foundAnchor = null;

            for (TrustAnchor anchor : anchors) {
                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null &&
                    anchorCert.getSubjectX500Principal().equals(
                        lastCert.getSubjectX500Principal())) {

                    /* Verify it's the same cert (compare encoded) */
                    try {
                        if (Arrays.equals(anchorCert.getEncoded(),
                            lastCert.getEncoded())) {
                            foundAnchor = anchor;
                            break;
                        }
                    } catch (CertificateException e) {
                        /* Continue checking other anchors */
                    }
                }
            }

            if (foundAnchor == null) {
                /* Last cert wasn't in trust anchors directly. Can happen
                 * when wolfSSL_X509_verify_cert() verifies up to the trust
                 * anchor but doesn't include it in the returned chain.
                 * Check if any trust anchor issued the last cert. */
                foundAnchor = isIssuedByTrustAnchor(lastCert, anchors);
                if (foundAnchor != null) {

                    /* Check if lastCert is actually the trust anchor itself
                     * (self-signed) but with different encoding. */
                    X509Certificate anchorCert = foundAnchor.getTrustedCert();
                    if (anchorCert != null &&
                        isSelfSigned(lastCert) &&
                        lastCert.getSubjectX500Principal().equals(
                            anchorCert.getSubjectX500Principal())) {

                        /* Last cert is the trust anchor (self-signed with
                         * same subject), remove it from the path */
                        log("last cert is self-signed trust anchor " +
                            ", removing from path");
                    } else {
                        /* Last cert is issued by trust anchor but not the
                         * anchor itself, so keep it in the path. */
                        if (maxPathLength >= 0) {
                            int numIntermediates = fullChain.size() - 1;
                            if (numIntermediates > maxPathLength) {
                                log("path length " + numIntermediates +
                                    " exceeds max " + maxPathLength);

                                throw new CertPathBuilderException(
                                    "Certificate path exceeds maximum " +
                                    "length: " + maxPathLength + " (found " +
                                    numIntermediates +
                                    " intermediate CA certificate(s))");
                            }
                        }

                        log("path ends at certificate issued by " +
                            "trust anchor: " + (anchorCert != null ?
                                anchorCert.getSubjectX500Principal().getName() :
                                "unknown"));

                        return new NativeChainResult(fullChain, foundAnchor);
                    }
                }

                if (foundAnchor == null) {
                    throw new CertPathBuilderException(
                        "Chain does not terminate at a trust anchor");
                }
            }

            /* Remove trust anchor from path (CertPath should not include it) */
            List<X509Certificate> pathWithoutAnchor =
                fullChain.subList(0, fullChain.size() - 1);

            /* Check maxPathLength constraint */
            if (maxPathLength >= 0) {
                int numIntermediates = pathWithoutAnchor.size() - 1;
                if (numIntermediates > maxPathLength) {
                    log("path length " + numIntermediates +
                        " exceeds max " + maxPathLength);

                    throw new CertPathBuilderException(
                        "Certificate path exceeds maximum length: " +
                        maxPathLength + " (found " + numIntermediates +
                        " intermediate CA certificate(s))");
                }
            }

            X509Certificate finalAnchorCert = foundAnchor.getTrustedCert();
            log("path built successfully, trust anchor: " +
                (finalAnchorCert != null ?
                    finalAnchorCert.getSubjectX500Principal().getName() :
                    "unknown"));

            return new NativeChainResult(
                new ArrayList<>(pathWithoutAnchor), foundAnchor);

        } catch (WolfCryptException e) {
            throw new CertPathBuilderException(
                "Native certificate chain building failed: " +
                e.getMessage(), e);

        } catch (RuntimeException e) {
            throw new CertPathBuilderException(
                "Unexpected error during certificate chain building: " +
                e.getMessage(), e);

        } finally {
            if (storeCtx != null) {
                storeCtx.close();
            }
        }
    }

    /**
     * Attempts to build a certification path using the specified algorithm
     * parameter set.
     *
     * @param params the algorithm parameters to be used for building
     *
     * @return the result of the build algorithm
     *
     * @throws CertPathBuilderException if the builder is unable to construct
     *         a certification path that satisfies the specified parameters
     * @throws InvalidAlgorithmParameterException if the given parameters are
     *         inappropriate for this CertPathBuilder
     */
    @Override
    public CertPathBuilderResult engineBuild(CertPathParameters params)
        throws CertPathBuilderException, InvalidAlgorithmParameterException {

        PKIXBuilderParameters pkixParams = null;
        X509Certificate targetCert = null;
        List<X509Certificate> path = null;
        TrustAnchor trustAnchor = null;
        CertPath certPath = null;

        log("entered engineBuild(), FIPS enabled: " + Fips.enabled);

        /* Validate parameters */
        sanitizeCertPathParameters(params);
        pkixParams = (PKIXBuilderParameters) params;

        /* Check that we have trust anchors */
        Set<TrustAnchor> anchors = pkixParams.getTrustAnchors();
        if (anchors == null || anchors.isEmpty()) {
            throw new InvalidAlgorithmParameterException(
                "No TrustAnchors in PKIXBuilderParameters");
        }

        /* Check for name constraints on trust anchors (not supported) */
        for (TrustAnchor anchor : anchors) {
            if (anchor.getNameConstraints() != null) {
                throw new InvalidAlgorithmParameterException(
                    "TrustAnchors with name constraints are not supported");
            }
        }

        /* If in FIPS mode, verify wolfJCE is the Signature provider to
         * help maintain FIPS compliance */
        if (Fips.enabled && !"wolfJCE".equals(pkixParams.getSigProvider())) {
            if (pkixParams.getSigProvider() == null) {
                /* Preferred Signature provider not set, set to wolfJCE */
                pkixParams.setSigProvider("wolfJCE");
            }
            else {
                throw new CertPathBuilderException(
                    "CertPathParameters Signature Provider must be wolfJCE " +
                    "when using wolfCrypt FIPS: " +
                    pkixParams.getSigProvider());
            }
        }

        /* Find target certificate */
        targetCert = findTargetCertificate(pkixParams);

        /* Check if target cert is a trust anchor itself */
        for (TrustAnchor anchor : anchors) {
            X509Certificate anchorCert = anchor.getTrustedCert();
            if (anchorCert != null && anchorCert.equals(targetCert)) {
                /* Target is the trust anchor, return empty path */
                log("target certificate is a trust anchor, " +
                    "returning empty path");

                try {
                    CertificateFactory cf =
                        CertificateFactory.getInstance("X.509");
                    certPath = cf.generateCertPath(new ArrayList<>());

                    return new PKIXCertPathBuilderResult(certPath, anchor,
                        null, targetCert.getPublicKey());

                } catch (CertificateException e) {
                    throw new CertPathBuilderException(
                        "Failed to create empty CertPath", e);
                }
            }
        }

        /* Build and verify path using wolfSSL X509_STORE */
        NativeChainResult result = buildAndVerifyPathNative(
            targetCert, pkixParams);
        path = result.path;
        trustAnchor = result.trustAnchor;

        try {
            /* Convert path to CertPath object */
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certPath = cf.generateCertPath(path);

        } catch (CertificateException e) {
            throw new CertPathBuilderException(
                "Failed to create CertPath from built chain", e);
        }

        log("successfully built path with " + path.size() + " certificate(s)");

        /* PolicyNode not returned, certificate policies are not supported */
        return new PKIXCertPathBuilderResult(certPath, trustAnchor,
            null, targetCert.getPublicKey());
    }

    /**
     * Returns a CertPathChecker that this implementation uses to check
     * the revocation status of certificates.
     *
     * This implementation returns a WolfCryptPKIXRevocationChecker that
     * supports both OCSP and CRL checking.
     *
     * @return a CertPathChecker object that this implementation uses to
     *         check the revocation status of certificates.
     */
    @Override
    public CertPathChecker engineGetRevocationChecker() {

        WolfCryptPKIXRevocationChecker checker =
            new WolfCryptPKIXRevocationChecker();

        return checker;
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

