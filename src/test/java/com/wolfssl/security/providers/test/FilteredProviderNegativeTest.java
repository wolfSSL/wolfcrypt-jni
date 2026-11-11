/* FilteredProviderNegativeTest.java
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamConstants;
import java.io.Serializable;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import com.wolfssl.security.providers.FilteredSun;
import com.wolfssl.security.providers.FilteredSunEC;
import com.wolfssl.security.providers.FilteredSunRsaSign;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Negative test for the filtered Sun security providers.
 *
 * The filtered providers register only a small allow-list of non-crypto
 * services. Requesting a blocked crypto algorithm directly from one of the
 * filtered providers (two-arg getInstance with the provider name) must fail
 * with NoSuchAlgorithmException, because that algorithm is not registered with
 * that specific provider.
 *
 * Blocked crypto service TYPES:
 *     Cipher, Signature, MessageDigest, Mac, KeyPairGenerator,
 *     KeyGenerator, SecureRandom, KeyAgreement
 *
 * Requires Java 9+ (see FilteredProviderSmokeTest for required JVM flags).
 */
public class FilteredProviderNegativeTest {

    /** Properties pinned to benign values while registering providers. */
    private static final String[] PIN_PROPS = {
        "wolfssl.filtered.useOriginalNames",
        "wolfssl.filtered.sun.additionalServices",
        "wolfssl.filtered.sunec.additionalServices",
        "wolfssl.filtered.sunrsasign.additionalServices" };

    /** Benign pin values for PIN_PROPS. */
    private static final String[] PIN_VALS = { "false", "", "", "" };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersionAndInstall() {
        Assume.assumeTrue(
            "FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider negative test");

        /* Pin properties to benign values during registration so names stay
         * FilteredSun* and no extra services are granted, even if the test
         * JVM's java.security sets them. Restore afterward. */
        String[] prev = pinProperties();
        try {
            Security.addProvider(new FilteredSun());
            Security.addProvider(new FilteredSunEC());
            Security.addProvider(new FilteredSunRsaSign());
        } finally {
            restoreProperties(prev);
        }
    }

    /**
     * Set PIN_PROPS to PIN_VALS, returning the previous values.
     */
    private static String[] pinProperties() {
        String[] prev = new String[PIN_PROPS.length];
        for (int i = 0; i < PIN_PROPS.length; i++) {
            prev[i] = Security.getProperty(PIN_PROPS[i]);
            Security.setProperty(PIN_PROPS[i], PIN_VALS[i]);
        }
        return prev;
    }

    /**
     * Restore PIN_PROPS values returned by pinProperties().
     */
    private static void restoreProperties(String[] prev) {
        for (int i = 0; i < PIN_PROPS.length; i++) {
            Security.setProperty(PIN_PROPS[i],
                (prev[i] != null) ? prev[i] : PIN_VALS[i]);
        }
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

    @FunctionalInterface
    private interface ThrowingCall {
        void run() throws Exception;
    }

    /**
     * Run the supplied getInstance() call and assert it throws
     * NoSuchAlgorithmException.
     */
    private void assertThrowsNsa(String msg, ThrowingCall call)
        throws NoSuchProviderException {
        try {
            call.run();
            fail(msg + " (expected NoSuchAlgorithmException, none thrown)");
        } catch (NoSuchAlgorithmException expected) {
            /* expected: algorithm not registered with this provider */
        } catch (NoSuchProviderException e) {
            throw e;
        } catch (Exception e) {
            fail(msg + " (expected NoSuchAlgorithmException, got "
                + e.getClass().getName() + ": " + e.getMessage() + ")");
        }
    }

    /**
     * Attempt to get a representative algorithm of each blocked TYPE from
     * the named provider and assert NoSuchAlgorithmException is thrown.
     */
    private void assertBlocked(String providerName)
        throws NoSuchProviderException {

        assertThrowsNsa("Cipher AES not blocked from " + providerName,
            () -> javax.crypto.Cipher.getInstance("AES", providerName));
        assertThrowsNsa("Signature SHA256withRSA not blocked from "
                + providerName,
            () -> java.security.Signature.getInstance(
                "SHA256withRSA", providerName));
        assertThrowsNsa("MessageDigest SHA-256 not blocked from "
                + providerName,
            () -> java.security.MessageDigest.getInstance(
                "SHA-256", providerName));
        assertThrowsNsa("Mac HmacSHA256 not blocked from " + providerName,
            () -> javax.crypto.Mac.getInstance("HmacSHA256", providerName));
        assertThrowsNsa("KeyPairGenerator RSA not blocked from "
                + providerName,
            () -> java.security.KeyPairGenerator.getInstance(
                "RSA", providerName));
        assertThrowsNsa("KeyGenerator AES not blocked from " + providerName,
            () -> javax.crypto.KeyGenerator.getInstance("AES", providerName));
        assertThrowsNsa("SecureRandom SHA1PRNG not blocked from "
                + providerName,
            () -> java.security.SecureRandom.getInstance(
                "SHA1PRNG", providerName));
        assertThrowsNsa("KeyAgreement ECDH not blocked from " + providerName,
            () -> javax.crypto.KeyAgreement.getInstance(
                "ECDH", providerName));
    }

    @Test
    public void testFilteredSunBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSun");
    }

    @Test
    public void testFilteredSunEcBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSunEC");
    }

    @Test
    public void testFilteredSunRsaSignBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSunRsaSign");
    }

    /**
     * Assert the call throws SecurityException.
     */
    private void assertRejected(String msg, ThrowingCall call) {
        try {
            call.run();
            fail(msg + " (expected SecurityException, none thrown)");
        } catch (SecurityException expected) {
            /* expected: provider services are read-only */
        } catch (Exception e) {
            fail(msg + " (expected SecurityException, got "
                + e.getClass().getName() + ": " + e.getMessage() + ")");
        }
    }

    /**
     * Assert a collection view change is rejected. Provider views are
     * read-only and throw UnsupportedOperationException.
     */
    private void assertViewRejected(String msg, ThrowingCall call) {
        try {
            call.run();
            fail(msg + " (expected UnsupportedOperationException)");
        } catch (UnsupportedOperationException | SecurityException e) {
            /* expected */
        } catch (Exception e) {
            fail(msg + " (expected UnsupportedOperationException, got "
                + e.getClass().getName() + ": " + e.getMessage() + ")");
        }
    }

    /**
     * New, unregistered filtered provider, built with PIN_PROPS pinned so it
     * has no extra services. Tests that try to change services use it, so a
     * lock regression cannot damage the registered providers.
     */
    private static Provider newUnregistered(Supplier<Provider> ctor) {
        String[] prev = pinProperties();
        try {
            return ctor.get();
        } finally {
            restoreProperties(prev);
        }
    }

    /**
     * Assert the filtered provider rejects runtime service changes, so a
     * service the filter removed (Sun MD5) cannot be added back.
     */
    private void assertReadOnly(Supplier<Provider> ctor)
        throws NoSuchProviderException {

        final Provider p = newUnregistered(ctor);
        final String name = p.getName();
        final int servicesBefore = p.getServices().size();
        final String key = "MessageDigest.MD5";
        final String cls = "sun.security.provider.MD5";
        final String props = key + "=" + cls + "\n";
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE properties SYSTEM " +
            "\"http://java.sun.com/dtd/properties.dtd\">\n" +
            "<properties><entry key=\"" + key + "\">" + cls +
            "</entry></properties>\n";
        final Provider.Service svc = p.getServices().iterator().next();
        final String regKey = svc.getType() + "." + svc.getAlgorithm();
        final Object regVal = p.get(regKey);
        assertNotNull(name + " has no entry for " + regKey, regVal);

        /* Add a service */
        assertRejected("put on " + name, () -> p.put(key, cls));
        assertRejected("putAll on " + name,
            () -> p.putAll(Collections.singletonMap(key, cls)));
        assertRejected("putIfAbsent on " + name,
            () -> p.putIfAbsent(key, cls));
        assertRejected("setProperty on " + name,
            () -> p.setProperty(key, cls));
        assertRejected("compute on " + name, () -> p.compute(key,
            (k, v) -> cls));
        assertRejected("computeIfAbsent on " + name,
            () -> p.computeIfAbsent(key, k -> cls));
        assertRejected("merge on " + name,
            () -> p.merge(key, cls, (a, b) -> b));
        assertRejected("load(Reader) on " + name,
            () -> p.load(new StringReader(props)));
        assertRejected("load(InputStream) on " + name,
            () -> p.load(new ByteArrayInputStream(
                props.getBytes(StandardCharsets.UTF_8))));
        assertRejected("loadFromXML on " + name,
            () -> p.loadFromXML(new ByteArrayInputStream(
                xml.getBytes(StandardCharsets.UTF_8))));

        /* Change or remove a registered service */
        assertRejected("replace on " + name, () -> p.replace(regKey, cls));
        assertRejected("replace(key, old, new) on " + name,
            () -> p.replace(regKey, regVal, cls));
        assertRejected("computeIfPresent on " + name,
            () -> p.computeIfPresent(regKey, (k, v) -> cls));
        assertRejected("replaceAll on " + name,
            () -> p.replaceAll((k, v) -> v));
        assertRejected("remove on " + name, () -> p.remove(regKey));
        assertRejected("remove(key, value) on " + name,
            () -> p.remove(regKey, regVal));
        assertRejected("clear on " + name, () -> p.clear());

        assertViewRejected("keySet().remove on " + name,
            () -> p.keySet().remove(regKey));
        assertViewRejected("values().remove on " + name,
            () -> p.values().remove(regVal));
        assertViewRejected("entrySet() iterator remove on " + name, () -> {
            Iterator<Map.Entry<Object, Object>> it = p.entrySet().iterator();
            it.next();
            it.remove();
        });
        assertViewRejected("entrySet() Entry.setValue on " + name,
            () -> p.entrySet().iterator().next().setValue(cls));

        /* A clone of a read-only provider is also read-only */
        final Provider c = (Provider)p.clone();
        assertRejected("put on clone of " + name, () -> c.put(key, cls));
        assertNull(c.getService("MessageDigest", "MD5"));

        assertNull(p.getService("MessageDigest", "MD5"));
        assertThrowsNsa("MessageDigest MD5 added at runtime to " + name,
            () -> java.security.MessageDigest.getInstance("MD5", p));
        assertEquals(regVal, p.get(regKey));
        assertEquals(servicesBefore, p.getServices().size());
    }

    @Test
    public void testFilteredProvidersAreReadOnly()
        throws NoSuchProviderException {
        assertReadOnly(FilteredSun::new);
        assertReadOnly(FilteredSunEC::new);
        assertReadOnly(FilteredSunRsaSign::new);
    }

    /**
     * FilteredSun subclass that calls the protected putService() and
     * removeService() methods.
     */
    private static class ServiceChangingFilteredSun extends FilteredSun {
        private static final long serialVersionUID = 1L;

        void callPutService(Provider.Service s) {
            putService(s);
        }

        void callRemoveService(Provider.Service s) {
            removeService(s);
        }
    }

    @Test
    public void testPutServiceAndRemoveServiceRejected() {

        final ServiceChangingFilteredSun p = (ServiceChangingFilteredSun)
            newUnregistered(ServiceChangingFilteredSun::new);
        final int servicesBefore = p.getServices().size();
        final Provider.Service added = new Provider.Service(p,
            "MessageDigest", "MD5", "sun.security.provider.MD5", null, null);
        final Provider.Service existing = p.getServices().iterator().next();

        assertRejected("putService", () -> p.callPutService(added));
        assertRejected("removeService",
            () -> p.callRemoveService(existing));

        assertNull(p.getService("MessageDigest", "MD5"));
        assertNotNull(p.getService(existing.getType(),
            existing.getAlgorithm()));
        assertEquals(servicesBefore, p.getServices().size());
    }

    /**
     * Serialize the provider, replacing every occurrence of value (if not null)
     * with a Sun class name as in a tampered stream, then deserialize it.
     * PIN_PROPS are pinned while deserializing, in case readResolve() builds
     * a new provider.
     */
    private static Provider tamperedCopy(Provider p, final Object value)
        throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                {
                    enableReplaceObject(true);
                }
                @Override
                protected Object replaceObject(Object obj) {
                    return (value != null && value.equals(obj)) ?
                        "sun.security.provider.MD5" : obj;
                }
            }) {
            oos.writeObject(p);
        }

        String[] prev = pinProperties();
        try (ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(bos.toByteArray()))) {
            return (Provider)ois.readObject();
        } finally {
            restoreProperties(prev);
        }
    }

    /**
     * Key of the first service entry of the provider, for example
     * "CertificateFactory.X.509".
     */
    private static String firstServiceKey(Provider p) {
        Provider.Service svc = p.getServices().iterator().next();
        String key = svc.getType() + "." + svc.getAlgorithm();
        assertNotNull(p.getName() + " has no entry for " + key, p.get(key));
        return key;
    }

    @Test
    public void testDeserializedFilteredProvidersAreRegisteredInstances()
        throws Exception {

        for (String name : new String[] {
                "FilteredSun", "FilteredSunEC", "FilteredSunRsaSign" }) {

            final Provider p = Security.getProvider(name);
            assertNotNull(name + " not registered", p);
            final String key = firstServiceKey(p);
            final Object value = p.get(key);

            /* readResolve() must return the registered provider and ignore
             * the serialized entries */
            final Provider copy = tamperedCopy(p, value);

            assertSame(name, p, copy);
            assertEquals(value, copy.get(key));
            assertRejected("put on deserialized " + name, () -> copy.put(
                "MessageDigest.MD5", "sun.security.provider.MD5"));
            assertNull(copy.getService("MessageDigest", "MD5"));
        }
    }

    @Test
    public void testDeserializedFilteredProvidersAreNewWhenNotRegistered()
        throws Exception {

        List<Supplier<Provider>> ctors = Arrays.<Supplier<Provider>>asList(
            FilteredSun::new, FilteredSunEC::new, FilteredSunRsaSign::new);
        for (Supplier<Provider> ctor : ctors) {

            final Provider p = newUnregistered(ctor);
            final String name = p.getName();
            final String key = firstServiceKey(p);
            final Object value = p.get(key);

            /* Remove the registered provider of this name for the test, so
             * readResolve() must build a new one */
            Provider registered = Security.getProvider(name);
            assertNotNull(name + " not registered", registered);
            int pos = Arrays.asList(Security.getProviders())
                .indexOf(registered) + 1;
            Security.removeProvider(name);
            try {
                final Provider copy = tamperedCopy(p, value);

                assertEquals(p.getClass(), copy.getClass());
                assertNotSame(name, p, copy);
                assertNotSame(name, registered, copy);
                assertEquals(value, copy.get(key));
                assertRejected("put on deserialized " + name,
                    () -> copy.put("MessageDigest.MD5",
                        "sun.security.provider.MD5"));
                assertNull(copy.getService("MessageDigest", "MD5"));
            } finally {
                Security.insertProviderAt(registered, pos);
            }
        }
    }

    @Test
    public void testDeserializedSubclassWithoutConstructorFails()
        throws Exception {

        /* readResolve() is inherited by subclasses in other packages. This
         * subclass is not registered and has no accessible no-arg
         * constructor, so deserializing it must fail rather than return
         * services from the stream. */
        Provider p = newUnregistered(ServiceChangingFilteredSun::new);
        try {
            tamperedCopy(p, null);
            fail("Deserializing " + p.getClass().getName() +
                " should throw InvalidObjectException");
        } catch (InvalidObjectException e) {
            /* expected */
        }
    }

    /**
     * Serializable object that refers back to the provider being serialized,
     * and saves that reference when it is deserialized, before the provider's
     * readResolve() runs.
     */
    private static class BackReference implements Serializable {
        private static final long serialVersionUID = 1L;
        private static Provider captured;
        private final Provider ref;

        BackReference(Provider ref) {
            this.ref = ref;
        }

        private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            captured = ref;
        }
    }

    @Test
    public void testDeserializedBackReferenceHasNoServices()
        throws Exception {

        for (String name : new String[] {
                "FilteredSun", "FilteredSunEC", "FilteredSunRsaSign" }) {

            final Provider p = Security.getProvider(name);
            assertNotNull(name + " not registered", p);
            final String key = firstServiceKey(p);
            final Object value = p.get(key);

            /* Replace one service class name with an object that refers
             * back to the provider. The deserialized object it captures
             * must not serve any entries from the stream. */
            BackReference.captured = null;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                    {
                        enableReplaceObject(true);
                    }
                    @Override
                    protected Object replaceObject(Object obj) {
                        return value.equals(obj) ?
                            new BackReference(p) : obj;
                    }
                }) {
                oos.writeObject(p);
            }
            try (ObjectInputStream ois = new ObjectInputStream(
                    new ByteArrayInputStream(bos.toByteArray()))) {
                assertSame(name, p, ois.readObject());
            }

            final Provider captured = BackReference.captured;
            assertNotNull(name, captured);
            assertNotSame(name, p, captured);
            assertTrue(name, captured.getServices().isEmpty());
            assertNull(name, captured.get(key));
            assertRejected("put on captured " + name, () -> captured.put(
                "MessageDigest.MD5", "sun.security.provider.MD5"));
            assertRejected("putAll on captured " + name,
                () -> captured.putAll(Collections.singletonMap(
                    "MessageDigest.MD5", "sun.security.provider.MD5")));
        }
    }

    /** Provider, Properties, Hashtable and Object methods that do not
     * change services. Every other public or protected one must be
     * overridden by the filtered providers' base class. */
    private static final Set<String> READ_ONLY_METHODS =
        new HashSet<String>(Arrays.asList(
            "clone", "configure", "contains", "containsKey", "containsValue",
            "elements", "entrySet", "equals", "finalize", "forEach", "get",
            "getClass", "getInfo", "getName", "getOrDefault", "getProperty",
            "getService", "getServices", "getVersion", "getVersionStr",
            "hashCode", "isConfigured", "isEmpty", "keySet", "keys", "list",
            "notify", "notifyAll", "propertyNames", "rehash", "save", "size",
            "store", "storeToXML", "stringPropertyNames", "toString",
            "values", "wait"));

    @Test
    public void testAllMutatorsOverridden() {

        /* Fails if this JDK's Provider (or a superclass) has a public or
         * protected method that the read-only base class of the filtered
         * providers does not override and that is not known to be read-only,
         * for example a mutator added in a new Java release */
        Class<?> base = FilteredSun.class.getSuperclass();
        assertNotEquals(Provider.class, base);
        List<String> missing = new ArrayList<String>();
        for (Class<?> c = Provider.class; c != null; c = c.getSuperclass()) {
            for (Method m : c.getDeclaredMethods()) {
                int mod = m.getModifiers();
                if (Modifier.isStatic(mod) || m.isSynthetic() ||
                    m.isBridge() || READ_ONLY_METHODS.contains(m.getName())) {
                    continue;
                }
                if (!Modifier.isPublic(mod) && !Modifier.isProtected(mod)) {
                    continue;
                }
                try {
                    base.getDeclaredMethod(m.getName(), m.getParameterTypes());
                } catch (NoSuchMethodException e) {
                    missing.add(c.getSimpleName() + "." + m.getName() +
                        Arrays.toString(m.getParameterTypes()));
                }
            }
        }
        assertTrue("Methods that may change services are not overridden by " +
            base.getName() + ": " + missing, missing.isEmpty());
        assertEquals(base, FilteredSunEC.class.getSuperclass());
        assertEquals(base, FilteredSunRsaSign.class.getSuperclass());
    }

    /* Serializable object that calls put() on the provider being
     * deserialized, from its own readObject() */
    private static class PutOnRead implements Serializable {
        private static final long serialVersionUID = 1L;
        private static Provider captured;
        private static boolean rejected;
        private final Provider ref;

        PutOnRead(Provider ref) {
            this.ref = ref;
        }

        private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            captured = ref;
            try {
                ref.put("MessageDigest.MD5",
                    "sun.security.provider.MD5");
            } catch (SecurityException e) {
                rejected = true;
            }
        }
    }

    /* Serialize the provider with an extra Object field, holding a
     * PutOnRead, added to the descriptor of the named class. It is read,
     * and PutOnRead.readObject() runs, while that class's readObject()
     * reads its fields. Return the deserialized result. */
    private static Object deserializeWithPutOnRead(Provider p,
        final String className) throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                @Override
                protected void writeClassDescriptor(ObjectStreamClass desc)
                    throws IOException {
                    if (!desc.getName().equals(className)) {
                        super.writeClassDescriptor(desc);
                        return;
                    }
                    writeUTF(desc.getName());
                    writeLong(desc.getSerialVersionUID());
                    writeByte(ObjectStreamConstants.SC_SERIALIZABLE);
                    writeShort(1);
                    writeByte('L');
                    writeUTF("extra");
                    writeObject("Ljava/lang/Object;");
                }
            }) {
            oos.writeObject(p);
            /* Value of the extra field */
            oos.writeObject(new PutOnRead(p));
        }

        PutOnRead.captured = null;
        PutOnRead.rejected = false;
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()))) {
            return ois.readObject();
        }
    }

    @Test
    public void testDeserializationCallbackCannotAddServices()
        throws Exception {

        for (String name : new String[] {
                "FilteredSun", "FilteredSunEC", "FilteredSunRsaSign" }) {

            final Provider p = Security.getProvider(name);
            assertNotNull(name + " not registered", p);

            assertSame(name, p, deserializeWithPutOnRead(p,
                FilteredSun.class.getSuperclass().getName()));
            assertNotNull(name, PutOnRead.captured);
            assertTrue(name + ": put() from a deserialization callback " +
                "was not rejected", PutOnRead.rejected);
            assertNull(name, PutOnRead.captured.get("MessageDigest.MD5"));
        }
    }
}
