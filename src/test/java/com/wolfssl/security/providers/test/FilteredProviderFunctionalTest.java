/* FilteredProviderFunctionalTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.security.providers.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import java.security.Provider;
import java.security.Security;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.wolfssl.security.providers.FilteredSun;
import com.wolfssl.security.providers.FilteredSunEC;
import com.wolfssl.security.providers.FilteredSunRsaSign;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Functional test for the filtered Sun security providers.
 *
 * Proves the providers' service copying preserves real functionality
 * end-to-end:
 *     - FilteredSun parses an X.509 certificate (CertificateFactory).
 *     - FilteredSunEC initializes AlgorithmParameters EC with secp256r1. For
 *       FilteredSunEC the copied Provider.Service overrides newInstance() to
 *       delegate to the original SunEC service, so a working instance proves
 *       the delegation path executes.
 *
 * Also asserts "no crypto leaked". Iterating each provider's getServices()
 * must not surface any service whose type is in the blocked crypto set.
 *
 * Also covers the wolfssl.filtered.useOriginalNames Security property
 * (register under the original Sun names) and the
 * wolfssl.filtered.[provider].additionalServices properties (grant individual
 * services, ex: MessageDigest.MD5 for java.util.UUID.nameUUIDFromBytes()).
 *
 * Requires Java 9+. See examples/filtered-providers/docs/add-opens.md for the
 * required (JDK-version-dependent) JVM module flags.
 */
public class FilteredProviderFunctionalTest {

    /** Crypto service TYPES that must never be exposed by these providers. */
    private static final Set<String> BLOCKED_TYPES = new HashSet<>(
        Arrays.asList(
            "Cipher", "Signature", "MessageDigest", "Mac",
            "KeyPairGenerator", "KeyGenerator", "SecureRandom",
            "KeyAgreement"));

    private static String caEccCertDer;

    /** Security property controlling filtered provider registration names. */
    private static final String NAME_PROP =
        "wolfssl.filtered.useOriginalNames";

    /** Security property granting additional FilteredSun services. */
    private static final String ADD_PROP =
        "wolfssl.filtered.sun.additionalServices";

    /** Security property granting additional FilteredSunEC services. */
    private static final String EC_ADD_PROP =
        "wolfssl.filtered.sunec.additionalServices";

    /** Security property granting additional FilteredSunRsaSign services. */
    private static final String RSA_ADD_PROP =
        "wolfssl.filtered.sunrsasign.additionalServices";

    /** Properties pinned to benign values while registering providers. */
    private static final String[] PIN_PROPS = {
        NAME_PROP, ADD_PROP, EC_ADD_PROP, RSA_ADD_PROP };

    /** Benign pin values for PIN_PROPS. */
    private static final String[] PIN_VALS = { "false", "", "", "" };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersionAndInstall() {
        Assume.assumeTrue(
            "FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider functional test");

        /* Pin properties to benign values during registration so names stay
         * FilteredSun* and no extra services are granted, even if the test
         * JVM's java.security sets them. Restore afterward. */
        String[] prev = new String[PIN_PROPS.length];
        for (int i = 0; i < PIN_PROPS.length; i++) {
            prev[i] = Security.getProperty(PIN_PROPS[i]);
            Security.setProperty(PIN_PROPS[i], PIN_VALS[i]);
        }

        try {
            Security.addProvider(new FilteredSun());
            Security.addProvider(new FilteredSunEC());
            Security.addProvider(new FilteredSunRsaSign());
        } finally {
            for (int i = 0; i < PIN_PROPS.length; i++) {
                Security.setProperty(PIN_PROPS[i],
                    (prev[i] != null) ? prev[i] : PIN_VALS[i]);
            }
        }

        /* Relative path from repo root; forked tests have cwd = basedir. */
        String certPre = "";
        if (isAndroid()) {
            certPre = "/data/local/tmp/";
        }
        caEccCertDer = certPre.concat("examples/certs/ca-ecc-cert.der");
    }

    private static int javaMajorVersion() {
        String v = System.getProperty("java.specification.version");
        if (v == null) {
            return 0;
        }
        if (v.startsWith("1.")) {
            v = v.substring(2);
        }
        int dot = v.indexOf('.');
        if (dot >= 0) {
            v = v.substring(0, dot);
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean isAndroid() {
        String name = System.getProperty("java.runtime.name");
        return (name != null && name.contains("Android"));
    }

    @Test
    public void testFilteredSunParsesX509Cert() throws Exception {
        CertificateFactory cf =
            CertificateFactory.getInstance("X.509", "FilteredSun");

        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(caEccCertDer)) {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }

        assertNotNull("Failed to parse X.509 cert via FilteredSun", cert);
        assertNotNull("Parsed cert has null subject",
            cert.getSubjectX500Principal());
        assertEquals("FilteredSun", cf.getProvider().getName());
    }

    @Test
    public void testFilteredSunEcDelegatesNewInstance() throws Exception {
        AlgorithmParameters ap =
            AlgorithmParameters.getInstance("EC", "FilteredSunEC");

        /* init() exercises the delegating newInstance() path into SunEC. */
        ap.init(new ECGenParameterSpec("secp256r1"));

        assertNotNull("AlgorithmParameters EC encoding null after init",
            ap.getEncoded());
        assertEquals("FilteredSunEC", ap.getProvider().getName());
    }

    @Test
    public void testNoCryptoLeaked() {
        assertNoBlockedServices("FilteredSun");
        assertNoBlockedServices("FilteredSunEC");
        assertNoBlockedServices("FilteredSunRsaSign");
    }

    /**
     * Iterate the named provider's services and fail if any service type is in
     * the blocked crypto set. Version-robust: does not assume a fixed count.
     */
    private void assertNoBlockedServices(String providerName) {
        Provider p = Security.getProvider(providerName);
        assertNotNull(providerName + " not installed", p);

        for (Provider.Service svc : p.getServices()) {
            String type = svc.getType();
            assertFalse(providerName + " leaked blocked crypto service: "
                    + type + "." + svc.getAlgorithm(),
                BLOCKED_TYPES.contains(type));
        }
    }

    /** Restore NAME_PROP to prev, or "false" (equivalent to unset). */
    private static void restoreSecurityProperty(String prev) {
        Security.setProperty(NAME_PROP, (prev != null) ? prev : "false");
    }

    /** 1-based registration position of the named provider, or -1. */
    private static int providerPosition(String name) {

        Provider[] providers = Security.getProviders();

        for (int i = 0; i < providers.length; i++) {
            if (providers[i].getName().equals(name)) {
                return i + 1;
            }
        }

        return -1;
    }

    @Test
    public void testDefaultNamesUnchanged() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "false");

            assertEquals("FilteredSun",
                new FilteredSun().getName());
            assertEquals("FilteredSunEC",
                new FilteredSunEC().getName());
            assertEquals("FilteredSunRsaSign",
                new FilteredSunRsaSign().getName());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testSecurityPropertyEnablesOriginalNames() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "true");

            assertEquals("SUN", new FilteredSun().getName());
            assertEquals("SunEC", new FilteredSunEC().getName());
            assertEquals("SunRsaSign", new FilteredSunRsaSign().getName());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testSystemPropertyIsIgnored() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            /* A system property of the same name must have no effect and must
             * trigger the ignored-property warning */
            Security.setProperty(NAME_PROP, "false");
            System.setProperty(NAME_PROP, "true");

            final Provider[] holder = new Provider[1];
            String err = captureStderr(() -> {
                holder[0] = new FilteredSun();
            });

            assertEquals("FilteredSun", holder[0].getName());
            assertTrue("no ignored-system-property warning printed",
                err.contains("system property") && err.contains(NAME_PROP));

        } finally {
            System.clearProperty(NAME_PROP);
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testInfoStringUnchangedWithOverride() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "true");

            /* getInfo() must keep identifying the provider as filtered so
             * audits can distinguish it from the stock SUN */
            Provider p = new FilteredSun();
            assertEquals("SUN", p.getName());
            assertEquals("Filtered SUN for non-crypto ops", p.getInfo());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testHardcodedSunLookupResolvesWithOverride()
        throws Exception {

        String prev = Security.getProperty(NAME_PROP);
        Provider realSun = Security.getProvider("SUN");
        int realSunPos = providerPosition("SUN");
        Provider filtered = null;
        boolean filteredAdded = false;

        try {
            Security.setProperty(NAME_PROP, "true");

            filtered = new FilteredSun();
            assertEquals("SUN", filtered.getName());

            /* Simulate the hardened JRE: swap the real SUN out and register
             * the filtered provider in its place */
            if (realSun != null) {
                Security.removeProvider("SUN");
            }
            assertTrue("could not register filtered provider as SUN",
                Security.addProvider(filtered) != -1);
            filteredAdded = true;

            /* Hardcoded name lookup must resolve to the filtered instance */
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509", "SUN");
            assertNotNull("CertificateFactory X.509 not resolved from " +
                "provider registered as SUN", cf);
            assertSame("lookup did not resolve to the filtered provider",
                filtered, cf.getProvider());

        } finally {
            if (filteredAdded) {
                Security.removeProvider(filtered.getName());
            }
            if (realSun != null && Security.getProvider("SUN") == null) {
                if (realSunPos > 0) {
                    Security.insertProviderAt(realSun, realSunPos);
                } else {
                    Security.addProvider(realSun);
                }
            }
            restoreSecurityProperty(prev);
        }
    }

    /** Restore ADD_PROP to prev, or "" (equivalent to unset). */
    private static void restoreAdditionalServices(String prev) {
        Security.setProperty(ADD_PROP, (prev != null) ? prev : "");
    }

    /** Return lowercase hex encoding of the given bytes. */
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** Return the set of "Type.Algorithm" keys exposed by a provider. */
    private static Set<String> serviceKeys(Provider p) {
        Set<String> keys = new HashSet<>();
        for (Provider.Service svc : p.getServices()) {
            keys.add(svc.getType() + "." + svc.getAlgorithm());
        }
        return keys;
    }

    /** Run r with System.err captured, return output, restore stream. */
    private static String captureStderr(Runnable r) {
        PrintStream prevErr = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream capture = new PrintStream(buf, true);
        try {
            System.setErr(capture);
            r.run();
        } finally {
            System.setErr(prevErr);
            capture.close();
        }
        return buf.toString();
    }

    @Test
    public void testAdditionalServicesDefaultBlocked() {
        String prev = Security.getProperty(ADD_PROP);

        try {
            Security.setProperty(ADD_PROP, "");

            Provider p = new FilteredSun();
            assertNull("MessageDigest.MD5 exposed without property grant",
                p.getService("MessageDigest", "MD5"));

        } finally {
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testAdditionalServicesGrantsMd5() throws Exception {
        String prev = Security.getProperty(ADD_PROP);

        try {
            Security.setProperty(ADD_PROP, "MessageDigest.MD5");

            Provider p = new FilteredSun();
            assertNotNull("MessageDigest.MD5 not granted by property",
                p.getService("MessageDigest", "MD5"));

            /* Only the listed algorithm is granted, not the whole type */
            assertNull("MessageDigest.SHA-256 leaked by MD5 grant",
                p.getService("MessageDigest", "SHA-256"));

            /* Granted service must be usable end-to-end. RFC 1321 test
             * vector: MD5("abc") */
            MessageDigest md = MessageDigest.getInstance("MD5", p);
            byte[] digest = md.digest("abc".getBytes("UTF-8"));
            assertEquals("granted MD5 service computed wrong digest",
                "900150983cd24fb0d6963f7d28e17f72", toHex(digest));

        } finally {
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testAdditionalServicesCaseInsensitive() {
        String prev = Security.getProperty(ADD_PROP);

        try {
            Security.setProperty(ADD_PROP, "messagedigest.md5");

            Provider p = new FilteredSun();
            assertNotNull("case-insensitive entry not matched",
                p.getService("MessageDigest", "MD5"));

        } finally {
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testAdditionalServicesMalformedIgnored() {
        String prev = Security.getProperty(ADD_PROP);

        try {
            /* Baseline service set with no grants */
            Security.setProperty(ADD_PROP, "");
            Set<String> baseline = serviceKeys(new FilteredSun());

            /* Malformed entries must not throw and must leave the service
             * set identical to the no-grant baseline */
            Security.setProperty(ADD_PROP,
                "MessageDigest, .MD5, MessageDigest., , ,,");

            /* Warnings are expected here: capture them to keep the suite
             * log quiet, assert them so they cannot go missing */
            AtomicReference<Set<String>> observed = new AtomicReference<>();
            String warnings = captureStderr(
                () -> observed.set(serviceKeys(new FilteredSun())));

            assertEquals("malformed entries changed the service set",
                baseline, observed.get());

            for (String bad : new String[] {
                    "'MessageDigest'", "'.MD5'", "'MessageDigest.'" }) {
                assertTrue("no warning for malformed entry " + bad +
                    ", stderr was: " + warnings, warnings.contains(bad));
            }

        } finally {
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testUuidNameFromBytesUsesGrantedMd5() throws Exception {

        String prevAdd = Security.getProperty(ADD_PROP);
        String prevName = Security.getProperty(NAME_PROP);

        /* Swap out every provider offering MessageDigest.MD5 (SUN on a
         * stock JDK, possibly more elsewhere) plus the default FilteredSun
         * from setup, keyed by 1-based registration position */
        TreeMap<Integer, Provider> removed = new TreeMap<>();

        Provider[] md5Provs = Security.getProviders("MessageDigest.MD5");
        if (md5Provs != null) {
            for (Provider p : md5Provs) {
                int pos = providerPosition(p.getName());
                assertTrue("registered provider has no position", pos > 0);
                removed.put(pos, p);
            }
        }
        Provider prevFiltered = Security.getProvider("FilteredSun");
        if (prevFiltered != null) {
            int pos = providerPosition("FilteredSun");
            assertTrue("FilteredSun has no position", pos > 0);
            removed.put(pos, prevFiltered);
        }

        Provider granting = null;
        boolean grantingAdded = false;

        try {
            Security.setProperty(NAME_PROP, "false");
            Security.setProperty(ADD_PROP, "MessageDigest.MD5");

            granting = new FilteredSun();

            /* Simulate the hardened JRE: no registered provider offers MD5
             * until the granting filtered provider is registered */
            for (Provider p : removed.values()) {
                Security.removeProvider(p.getName());
            }
            assertTrue("could not register granting filtered provider",
                Security.addProvider(granting) != -1);
            grantingAdded = true;

            /* UUID.nameUUIDFromBytes()'s no-provider MD5 lookup must
             * resolve to the granting filtered provider */
            MessageDigest md = MessageDigest.getInstance("MD5");
            assertSame("MD5 did not resolve to the filtered provider",
                granting, md.getProvider());

            /* Must produce the deterministic version 3 UUID for "test" */
            UUID uuid = UUID.nameUUIDFromBytes("test".getBytes("UTF-8"));
            assertEquals("UUID is not version 3 (MD5)", 3, uuid.version());
            assertEquals("098f6bcd-4621-3373-8ade-4e832627b4f6",
                uuid.toString());

        } finally {
            if (grantingAdded) {
                Security.removeProvider(granting.getName());
            }
            /* Reinsert removed providers at original positions, ascending */
            for (Map.Entry<Integer, Provider> e : removed.entrySet()) {
                if (Security.getProvider(e.getValue().getName()) == null) {
                    Security.insertProviderAt(e.getValue(), e.getKey());
                }
            }
            restoreAdditionalServices(prevAdd);
            restoreSecurityProperty(prevName);
        }
    }

    @Test
    public void testAdditionalServicesGrantsSunEc() throws Exception {
        String prev = Security.getProperty(EC_ADD_PROP);

        try {
            Security.setProperty(EC_ADD_PROP, "KeyFactory.EC");

            Provider p = new FilteredSunEC();
            assertNotNull("KeyFactory.EC not granted by property",
                p.getService("KeyFactory", "EC"));

            /* Instantiation exercises the delegating newInstance() path */
            assertNotNull("granted KeyFactory.EC failed to instantiate",
                KeyFactory.getInstance("EC", p));

        } finally {
            Security.setProperty(EC_ADD_PROP, (prev != null) ? prev : "");
        }
    }

    @Test
    public void testAdditionalServicesGrantsSunRsaSign() throws Exception {
        String prev = Security.getProperty(RSA_ADD_PROP);

        try {
            Security.setProperty(RSA_ADD_PROP, "Signature.SHA256withRSA");

            Provider p = new FilteredSunRsaSign();
            assertNotNull("Signature.SHA256withRSA not granted by property",
                p.getService("Signature", "SHA256withRSA"));

            /* Instantiation exercises the delegating newInstance() path */
            assertNotNull("granted Signature failed to instantiate",
                Signature.getInstance("SHA256withRSA", p));

        } finally {
            Security.setProperty(RSA_ADD_PROP, (prev != null) ? prev : "");
        }
    }

    @Test
    public void testAdditionalServicesWithOriginalNames() {
        String prevName = Security.getProperty(NAME_PROP);
        String prevAdd = Security.getProperty(ADD_PROP);

        try {
            /* With both properties set, the provider registers under the
             * original name and carries the granted service */
            Security.setProperty(NAME_PROP, "true");
            Security.setProperty(ADD_PROP, "MessageDigest.MD5");

            Provider p = new FilteredSun();
            assertEquals("SUN", p.getName());
            assertNotNull("MessageDigest.MD5 not granted with name override",
                p.getService("MessageDigest", "MD5"));

        } finally {
            restoreAdditionalServices(prevAdd);
            restoreSecurityProperty(prevName);
        }
    }

    @Test
    public void testAdditionalServicesUnmatchedEntryWarns() {
        String prev = Security.getProperty(ADD_PROP);

        try {
            /* Baseline service set with no grants */
            Security.setProperty(ADD_PROP, "");
            Set<String> baseline = serviceKeys(new FilteredSun());

            /* A wrong-provider entry (KeyFactory.EC lives in SunEC) and
             * an OID alias entry must both warn and grant nothing */
            Security.setProperty(ADD_PROP,
                "KeyFactory.EC, MessageDigest.1.2.840.113549.2.5");

            final Provider[] holder = new Provider[1];
            String err = captureStderr(() -> {
                holder[0] = new FilteredSun();
            });

            assertTrue("no warning for unmatched entry KeyFactory.EC",
                err.contains("'KeyFactory.EC'"));
            assertTrue("no warning for OID alias entry",
                err.contains("'MessageDigest.1.2.840.113549.2.5'"));
            assertTrue("warning does not name the property",
                err.contains(ADD_PROP));
            assertEquals("unmatched entries changed the service set",
                baseline, serviceKeys(holder[0]));

        } finally {
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testAdditionalServicesMalformedEntryWarns() {
        String prev = Security.getProperty(ADD_PROP);
        String prevSys = System.getProperty(ADD_PROP);

        /* Clear any environment-set system property so its ignored-property
         * warning cannot pollute the captured stderr */
        System.clearProperty(ADD_PROP);

        try {
            /* A malformed entry must warn without blocking a valid grant
             * in the same list */
            Security.setProperty(ADD_PROP,
                "MessageDigest, MessageDigest.MD5");

            final Provider[] holder = new Provider[1];
            String err = captureStderr(() -> {
                holder[0] = new FilteredSun();
            });

            assertTrue("no malformed-entry warning printed",
                err.contains("malformed") &&
                err.contains("'MessageDigest'"));
            assertNotNull("valid entry not granted alongside malformed one",
                holder[0].getService("MessageDigest", "MD5"));

            /* Empty entries from stray commas must stay silent */
            Security.setProperty(ADD_PROP, " , ,,");
            String err2 = captureStderr(() -> {
                new FilteredSun();
            });
            assertFalse("empty entries should not warn",
                err2.contains(ADD_PROP));

        } finally {
            if (prevSys != null) {
                System.setProperty(ADD_PROP, prevSys);
            }
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testUnrecognizedUseOriginalNamesValueWarns() {
        String prev = Security.getProperty(NAME_PROP);
        String prevSys = System.getProperty(NAME_PROP);

        /* Clear any environment-set system property so its ignored-property
         * warning cannot pollute the captured stderr */
        System.clearProperty(NAME_PROP);

        try {
            /* Unrecognized value must warn and fall back to the filtered
             * name (ex: inline-comment mistake "true # comment") */
            Security.setProperty(NAME_PROP, "yes");

            final Provider[] holder = new Provider[1];
            String err = captureStderr(() -> {
                holder[0] = new FilteredSun();
            });

            assertTrue("no unrecognized-value warning printed",
                err.contains("'yes'") && err.contains(NAME_PROP));
            assertEquals("unrecognized value did not fall back to " +
                "filtered name", "FilteredSun", holder[0].getName());

            /* "false" must not warn */
            Security.setProperty(NAME_PROP, "false");
            String err2 = captureStderr(() -> {
                new FilteredSun();
            });
            assertFalse("value 'false' must not warn",
                err2.contains(NAME_PROP));

        } finally {
            if (prevSys != null) {
                System.setProperty(NAME_PROP, prevSys);
            }
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testAdditionalServicesSystemPropertyIsIgnored() {
        String prev = Security.getProperty(ADD_PROP);

        try {
            /* A system property must not grant services and must trigger
             * the ignored-property warning */
            Security.setProperty(ADD_PROP, "");
            System.setProperty(ADD_PROP, "MessageDigest.MD5");

            final Provider[] holder = new Provider[1];
            String err = captureStderr(() -> {
                holder[0] = new FilteredSun();
            });

            assertNull("system property must not grant services",
                holder[0].getService("MessageDigest", "MD5"));
            assertTrue("no ignored-system-property warning printed",
                err.contains("system property") && err.contains(ADD_PROP));

        } finally {
            System.clearProperty(ADD_PROP);
            restoreAdditionalServices(prev);
        }
    }

    @Test
    public void testAdditionalServicesUnmatchedEntryWarnsEcRsa() {
        String prevEc = Security.getProperty(EC_ADD_PROP);
        String prevRsa = Security.getProperty(RSA_ADD_PROP);

        try {
            /* MessageDigest.MD5 exists in neither SunEC nor SunRsaSign;
             * each warning must name its own property */
            Security.setProperty(EC_ADD_PROP, "MessageDigest.MD5");
            Security.setProperty(RSA_ADD_PROP, "MessageDigest.MD5");

            String err = captureStderr(() -> {
                new FilteredSunEC();
                new FilteredSunRsaSign();
            });

            assertTrue("warning does not name the sunec property",
                err.contains(EC_ADD_PROP));
            assertTrue("warning does not name the sunrsasign property",
                err.contains(RSA_ADD_PROP));

        } finally {
            Security.setProperty(EC_ADD_PROP,
                (prevEc != null) ? prevEc : "");
            Security.setProperty(RSA_ADD_PROP,
                (prevRsa != null) ? prevRsa : "");
        }
    }
}

